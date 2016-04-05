'''
Created on Apr 2, 2014

@author: sethjn
'''
from twisted.internet import reactor, defer

from Server import MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT

import playground
#import playground.extras.sandbox.SandboxCodeunitAdapter
from playground.crypto import X509Certificate, Pkcs7Padding
from playground.network.common import MIBAddressMixin, OneshotTimer
from playground.network.message import MessageData
from playground.network.message import definitions
from ServiceMessages import OpenSession, SessionOpen, SessionOpenFailure, EncryptedMobileCodeResult
from ServiceMessages import PurchaseDecryptionKey, RunMobileCodeFailure, AcquireDecryptionKeyFailure
from ServiceMessages import RerequestDecryptionKey, GeneralFailure, ResultDecryptionKey, SessionRunMobileCode
from ServiceMessages import RunMobileCodeAck

import random, time, math, os, dbm, pickle, sys, binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from playground.network.client.ClientMessageHandlers import RunMobileCodeHandler, MobileCodeCallbackHandler

from apps.bank.BankCore import LedgerLine
from apps.bank.OnlineBank import PlaygroundOnlineBankClient, BANK_FIXED_PLAYGROUND_ADDR, BANK_FIXED_PLAYGROUND_PORT
from apps.bank.OnlineBank import BankClientProtocol, BankClientSimpleCommand

from playground.network.message import definitions

from playground.playgroundlog import packetTrace, logging, protocolLog
from apps.mobilecodeservice.ServiceMessages import CheckMobileCodeResult
from playground.network.common.Timer import OneshotTimer
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol
from twisted.python.failure import Failure
logger = logging.getLogger(__file__)

from playground.config import GlobalPlaygroundConfigData
configData = GlobalPlaygroundConfigData.getConfig(__name__)

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

LOCATION_OF_PLAYGROUND = os.path.dirname(playground.__file__)

class BasicClient(object):
    STATE_NOT_SET = "No State Set"
    STATE_OPENING = "Opening Connection"
    STATE_WAITING = "Waiting for code"
    STATE_RUNNING = "Code Running"
    STATE_PURCHASE = "Purchasing Key"
    STATE_FINISHED = "Completed"
    STATE_ERROR = "ERROR"
    class SessionPod(object):
        def __init__(self):
            self.clientNonce = None
            self.cookie = None
            self.state = BasicClient.STATE_NOT_SET
            self.execId = None
            self.mobileCodeId = None
            self.maxRate = None
            self.mobileCodeString = None
            self.d = None
            self.maxRuntime = 0
            self.billingRate = 0
            self.account = None
            self.codeHash = None
            self.encryptedResult = None
            
    def __init__(self, clientbase, server, connectionType="RAW"):
        self.sessions = {}
        self.execIdToSession = {}
        self.clientbase = clientbase
        self.server = server
        self.connectionType = connectionType
        
    def buildProtocol(self, addr):
        return BasicClientProtocol(self, addr)
    
    def status(self, execId):
        pod =  self.execIdToSession.get(execId, None)
        if not pod:
            return None
        return pod.state
    
    def cancel(self, execId):
        pod =  self.execIdToSession.get(execId, None)
        if not pod:
            return 
        # We can't just delete it. We may be waiting on something
        # this should make it quit on the next response
        pod.state = self.STATE_ERROR
        
    def runningJobs(self):
        count = 0
        for pod in self.execIdToSession.values():
            if pod.state not in [self.STATE_ERROR, self.STATE_FINISHED, self.STATE_NOT_SET]:
                count += 1
        return count
    
    def allExecIds(self):
        return self.execIdToSession.keys()
    
    def connect(self, mobileCodeId, maxRate):
        srcport, protocol = self.clientbase.connect(self, self.server,
                                                    MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT,
                                                    connectionType=self.connectionType)
        pod = self.SessionPod()
        pod.mobileCodeId = mobileCodeId
        pod.maxRate = maxRate
        pod.d = defer.Deferred()
        protocol.connect(pod, timeout=30)
        return pod.d
        
    def runMobileCode(self, cookie, execId, mobileCodeString, maxRuntime):
        if not self.sessions.has_key(cookie):
            return None
        pod = self.sessions[cookie]
        self.execIdToSession[execId] = pod
        srcport, protocol = self.clientbase.connect(self, self.server, 
                                                    MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT,
                                                    connectionType=self.connectionType)
        pod.execId = execId
        pod.mobileCodeString, pod.maxRuntime = mobileCodeString, maxRuntime
        pod.d = defer.Deferred()
        protocol.runMobileCode(pod, timeout=30)
        return pod.d
    
    def protocolSignalsError(self, state, msg):
        state = self.execIdToSession.get(state.execId, None)
        if not state:
            state = self.sessions.get(state.cookie, None)
        if state and state.d:
            state.d.errback(Exception(msg))
        if self.execIdToSession.has_key(state.execId):
            # we should be able to delete here, because we just got a response
            del self.execIdToSession[state.execId]
        if self.sessions.has_key(state.cookie):
            del self.sessions[state.cookie]

    """def protocolSignalsConnectionList(self, state, msg):
        state = self.execIdToSession.get(state.execId, None)
        if not state:
            state = self.sessions.get(state.cookie, None)
        if state and state.d:
            self.protocolSignalsError(state, "Unexpected loss of connection before deferred.")"""

    def __validDestAccount(self, account):
        return True
        
    def protocolSignalsSessionOpen(self, state):
        if not state.cookie:
            logger.error("No cookie after sesion open. should have been an error" % state.cookie)
            return
        self.sessions[state.cookie] = state
        if state.d:
            # the callback may, in fact, reset state.d. We don't want
            # to overwrite it.
            d = state.d
            state.d = None
            d.callback(state.cookie)
        else:
            logger.error("No deferred in state for cookie %s. Perhaps called twice?" % state.cookie)
        
    def protocolSignalsMobileCodeAccepted(self, state):
        OneshotTimer(lambda: self.__checkResult(state)).run(10)
        
    def __checkResult(self, state):
        if state.state != self.STATE_RUNNING:
            # end callback loop. We already have a result!
            return
        srcport, protocol = self.clientbase.connect(self, self.server, 
                                                    MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT,
                                                    connectionType=self.connectionType)
        protocol.getResult(state)
        #OneshotTimer(lambda: self.__checkResult(state)).run(10)
        
    def protocolSignalsEncryptedResult(self, state):
        # if the server wasn't ready, runtime, codeHash, and encryptedResult are None
        if not state.cookie:
            logger.error("No cookie in protocolsignalsentryptedresult. Should have been an error")
            return
        if state.encryptedResult == None:
            return
        self.sessions[state.cookie] = state
        if state.d:
            # let's not accidentally overwrite a new d
            d = state.d
            state.d = None
            d.callback((state.cookie, state.encryptedResult, state.billingRate, state.account))
        else:
            logger.error("No encrypted result deferred for cookie %s. Already fired?" % state.cookie)
        
    def sendProofOfPayment(self, cookie, receipt, receiptSignature):
        state = self.sessions.get(cookie, None)
        if not state:
            logger.error("Unknown session with cookie %s. No error to callback to" % cookie)
            return None
        del self.sessions[cookie]
        d = defer.Deferred()
        state.d = d
        srcport, protocol = self.clientbase.connect(self, self.server, 
                                                    MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT,
                                                    connectionType=self.connectionType)
        protocol.sendProofOfPayment(state, receipt, receiptSignature)
        return state.d
    
    def protocolSignalsKey(self, state, key, iv):
        # this callback may not be necessary
        # I'm leaving it this way because there's less code to rewite
        if not state.cookie:
            logger.error("No cookie for protocolsignalskey. Should have been an error")
            return
        if state.d:
            # let's not accidentally overwrite state.d if it's set in the callback
            d = state.d
            state.d = None
            d.callback((state.cookie, key, iv))
        else:
            logger.error("No deferred for protocolSignalsKey cookie %s. Already fired?" % state.cookie)
        
    def rerequestKey(self, cookie):
        srcport, protocol = self.clientbase.connect(self, self.server, 
                                                    MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT,
                                                    connectionType=self.connectionType)
        fakeState = BasicClient.SessionPod()
        fakeState.cookie = cookie
        fakeState.state = BasicClient.STATE_FINISHED
        fakeState.d = defer.Deferred()
        protocol.rerequestKey(fakeState)
        return fakeState.d
        

def ConnectedAPI(method):
    def checkConnectionThenCall(self, *args, **kargs):
        if self._connectionState == SimpleMessageHandlingProtocol.PRECONNECTION_STATE:
            self.runWhenConnected.append(lambda: method(self, *args, **kargs))
        elif self._connectionState == SimpleMessageHandlingProtocol.CONNECTION_CLOSED_STATE:
            raise Exception("Cannot call %s as the connection has closed" % method.__name__)
        elif self._connectionState == SimpleMessageHandlingProtocol.CONNECTED_STATE:
            method(self, *args, **kargs)
        else:
            raise Exception("Unknown connection state")
    return checkConnectionThenCall

class BasicClientProtocol(playground.network.common.SimpleMessageHandlingProtocol, playground.network.common.StackingProtocolMixin):
    
    def __init__(self, factory, addr):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__factory = factory
        self.__state = None
        self.__awaitingResponse = None
        self.runWhenConnected = []
        self.registerMessageHandler(SessionOpen, self.__handleSessionOpen)
        self.registerMessageHandler(SessionOpenFailure, self.__handleSessionOpenFailure)
        self.registerMessageHandler(EncryptedMobileCodeResult, self.__handleEncryptedResult)
        self.registerMessageHandler(ResultDecryptionKey, self.__handleDecryptionKeyResult)
        self.registerMessageHandler(AcquireDecryptionKeyFailure, self.__handleDecryptionKeyFailure)
        self.registerMessageHandler(RunMobileCodeFailure, self.__handleMobileCodeFailure)
        self.registerMessageHandler(GeneralFailure, self.__handleFailure)
        self.registerMessageHandler(RunMobileCodeAck, self.__handleMobileCodeAck)
        
    """def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_CURRENT_STATE, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_CURRENT_STATE):
            return [self.__mode]
        return []"""
        
    def __error(self, msg, fatal=True):
        self.__awaitingResponse = None
        self.reportError(msg)
        # this call later prevents problems if we've just had the connection established
        self.callLater(0,lambda: self.transport and self.transport.loseConnection())
        if fatal and self.__state:
            self.__state.state = BasicClient.STATE_ERROR
            if self.__state.d: 
                # it's unlikey, but in case it gets set, don't
                # overwrite
                d = self.__state.d
                self.__state.d = None
                d.errback(Exception(msg))
        
    def connectionMade(self):
        SimpleMessageHandlingProtocol.connectionMade(self)
        self.__connected = True
        for op in self.runWhenConnected:
            op()
        self.runWhenConnected = []
        
    def connectionLost(self, reason=None):
        SimpleMessageHandlingProtocol.connectionLost(self, reason)
        logger.info("%s Connection lost. Reason: %s" % (self._connectionId(), reason))
        factory = self.__factory
        self.__factory = None
        if self.__awaitingResponse != None:
            factory.protocolSignalsError(self.__state, "Unexpected loss of connection while waiting for %s. [%s]" % (self.__awaitingResponse, reason))

    """def connectionLost(self, reason=None):
        playground.network.common.SimpleMessageHandlingProtocol.connectionLost(self, reason)
        protocolLog(self, logger.info, "Connection lost: %s. Current state: %s" % (str(reason), self.__mode))
        #self.__error("Connection Lost: " + str(reason))
        if self.__mode != self.STATE_ERROR:
            self.__mode = self.STATE_FINISHED"""
    
    @ConnectedAPI      
    def connect(self, state, timeout=None):
        request = MessageData.GetMessageBuilder(OpenSession)
        self.__state = state
        self.__state.clientNonce = RANDOM_u64()
        request["ClientNonce"].setData(self.__state.clientNonce)
        request["MobileCodeId"].setData(state.mobileCodeId)
        request["Authenticated"].setData(False)
        self.__state.state = BasicClient.STATE_OPENING
        peerAddr = self.transport.getPeer()
        if timeout:
            OneshotTimer(lambda: self.__state.state == BasicClient.STATE_OPENING and 
                         self.__error("MCServer %s No Response in %d seconds" % (peerAddr, timeout)) or
                         None).run(timeout)
        protocolLog(self, logger.info, "%s sending CONNECT" % self._connectionId())
        self.__awaitingResponse = "SESSION_OPEN"
        self.transport.writeMessage(request)
        
    def __handleSessionOpen(self, prot, msg):
        if not self.__state:
            return self.__error("Not ready. No state")
        self.__awaitingResponse = None
        protocolLog(self, logger.info, "%s Got Session Open from %s" % (self._connectionId(), str(self.transport.getPeer())))
        packetTrace(logger, msg, "Session Open msg. State: %s " % self.__state.state)
        if self.__state.state != BasicClient.STATE_OPENING:
            return self.__error("Unexpected session open. State is: %s" % self.__state.state)
        msgObj = msg.data()
        if msgObj.BillingRate > self.__state.maxRate:
            return self.__error("Can't use this server. Too expensive (%d)" % msgObj.BillingRate)
        
        if self.__state.clientNonce != msgObj.ClientNonce:
            return self.__error("Invalid connection data (ClientNonce)")
        self.__state.billingRate = msgObj.BillingRate
        self.__state.account = msgObj.Account
        self.__state.cookie = msgObj.Cookie
        self.__factory.protocolSignalsSessionOpen(self.__state)
        self.transport.loseConnection()
    
    @ConnectedAPI    
    def runMobileCode(self, state, timeout=None):
        self.__state = state
        logger.info("%s Starting runMobileCode with state %s, cookie %s, ID %s" % (self._connectionId(), state.state, state.cookie, state.execId))
        if not state.state == BasicClient.STATE_OPENING:
            raise Exception("Cannot call 'runMobileCode' except from opening state. Got %s instead" % state.state)
        
        """success, data = self.__factory.getCodeForConnection(msgObj.ClientNonce,
                                                                             msgObj.ServerNonce,
                                                                             self.transport.getPeer(),
                                                                             msgObj.BillingTimeSliceSeconds,
                                                                             msgObj.BillingRatePerSlice)
        if not success:
            return self.__error("Could not get code for %s: %s" %(self.transport.getPeer(),data))"""
        """codeString, codeID, maxRuntime = data
        if not codeString or not codeID:
            self.transport.loseConnection()
            return
            #return self.__error("Decided not to proceed with cost")
        if configData.get("SafeCodeWrapper",None) != None:
            codeString = __import__(configData.get("SafeCodeWrapper")).makeCodeSafe(self.transport.getPeer(), codeString)"""
        """self.__connData["ServerNonce"] = msgObj.ServerNonce
        protocolLog(self, logger.info, "ServerNonce is %d" % (msgObj.ServerNonce,))"""
        
        request = MessageData.GetMessageBuilder(definitions.playground.base.RunMobileCode)
        request["ID"].setData(state.execId)
        request["pythonCode"].setData(state.mobileCodeString)
        request["mechanism"].setData("pickle")
        serializedMsg = request.serialize()
        state.codeHash = SHA.new(serializedMsg).digest()
        wrapMsg = MessageData.GetMessageBuilder(SessionRunMobileCode)
        wrapMsg["Cookie"].setData(state.cookie)
        wrapMsg["RunMobileCodePacket"].setData(serializedMsg)
        wrapMsg["MaxRuntime"].setData(state.maxRuntime)
        
        state.state = BasicClient.STATE_WAITING
        packetTrace(logger, wrapMsg, "Sending wrapped SessionRunMobileCode Cookie = %s" % state.cookie)
        
        peerAddr = self.transport.getPeer()
        if timeout:
            # Make sure that we get a response within timeout
            OneshotTimer(lambda: self.__state.state == BasicClient.STATE_WAITING and
                         self.__error("MCServer %s No response to mobile code in %d seconds" % 
                                      (peerAddr, timeout)) or
                         None).run(timeout)
        # Make sure the code completes within max runtime.
        """OneshotTimer(lambda: self.__state.state == BasicClient.STATE_RUNNING and 
                     self.__error("MCServer %s Code not complete within max-runtime (%d)" % 
                                  (self.transport.getPeer(), state.maxRuntime)) or
                     None).run(state.maxRuntime)"""
        logger.info("%s sending RunMobileCode" % self._connectionId())
        self.__awaitingResponse = "RunMobileCode Response"
        self.transport.writeMessage(wrapMsg)
        
    def __handleSessionOpenFailure(self, prot, msg):
        curState = self.__state and self.__state.state or "NONE"
        cookie = self.__state and self.__state.cookie or "NONE"
        packetTrace(logger, msg, "Session Open failed. State: %s Cookie = %s" % (curState, cookie))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleDecryptionKeyFailure(self, prot, msg):
        curState = self.__state and self.__state.state or "NONE"
        cookie = self.__state and self.__state.cookie or "NONE"
        packetTrace(logger, msg, "Decryption failed. State: %s Cookie = %s" % (curState, cookie))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleMobileCodeFailure(self, prot, msg):
        curState = self.__state and self.__state.state or "NONE"
        cookie = self.__state and self.__state.cookie or "NONE"
        packetTrace(logger, msg, "Mobile Code failed. State: %s Cookie = %s" % (curState, cookie))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleFailure(self, prot, msg):
        curState = self.__state and self.__state.state or "NONE"
        cookie = self.__state and self.__state.cookie or "NONE"
        packetTrace(logger, msg, "Session Open failed. State: %s Cookie = %s" % (curState, cookie))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleMobileCodeAck(self, prot, msg):
        if not self.__state:
            return self.__error("Not ready. No state")
        self.__awaitingResponse = None
        protocolLog(self, logger.info, "%s Got MobileCode Ack from %s" % (self._connectionId(), str(self.transport.getPeer())))
        packetTrace(logger, msg, "Mobile Code Ack. State: %s, Cookie: %s " % (self.__state.state, self.__state.cookie))
        if self.__state.state not in [BasicClient.STATE_WAITING, BasicClient.STATE_RUNNING]:
            return self.__error("Unexpected mobile code ack. State is: %s, Cookie is: %s" % (self.__state.state,
                                                                                             self.__state.cookie),)
        msgObj = msg.data()
        if self.__state.state == BasicClient.STATE_WAITING:
            
            if self.__state.cookie != msgObj.Cookie:
                # ignore mismatching cookies
                return self.__error("Cookies mismatch", fatal=False)
            if not msgObj.MobileCodeAccepted:
                message = hasattr(msgObj,"Message") and msgObj.Message or ""
                return self.__error("Code not accepted. " + message)
            logger.info("%s now believes that mobile code is running on peer" % self._connectionId())
            self.__state.state = BasicClient.STATE_RUNNING
            self.__factory.protocolSignalsMobileCodeAccepted(self.__state)
        else:
            # just an ack from trying to get the result. Code not yet ready
            protocolLog(self, logger.info, "%s Got a MobileCodeAck letting us know the code isn't ready" % self._connectionId())
            if hasattr(msgObj, "Message") and msgObj.Message:
                logger.info("ACK message: %s" % msgObj.Message)
            self.__factory.protocolSignalsMobileCodeAccepted(self.__state)
        self.transport.loseConnection()
    
    @ConnectedAPI       
    def getResult(self, state, timeout=None):
        if state.state != BasicClient.STATE_RUNNING:
            raise Exception("Cannot call 'getResult' unless in running state")
        request = MessageData.GetMessageBuilder(CheckMobileCodeResult)
        request["Cookie"].setData(state.cookie)
        self.__state = state
        logger.info("%s sending CheckMobileCodeResult" % self._connectionId())
        self.__awaitingResponse = "CheckMobileCodeResult Response"
        self.transport.writeMessage(request)
        
    def __handleEncryptedResult(self, prot, msg):
        if not self.__state:
            return self.__error("Not ready. No state")
        
        if self.__state.state != BasicClient.STATE_RUNNING:
            return self.__error("Unexpected encrypted result. State is: %s" % self.__state.state)
        self.__awaitingResponse = None
        msgObj = msg.data()
        if msgObj.EncryptedMobileCodeResultPacket == '':
            # Still running. Not completed yet
            self.transport.loseConnection()
            return
        packetTrace(logger, msg, "Encrypted Result. Cookie %s, State: %s " % (self.__state.cookie, self.__state.state))
        protocolLog(self, logger.info, "%s Got Encrypted Result of len %d from %s" % (self._connectionId(), len(msgObj.EncryptedMobileCodeResultPacket),
                                                                str(self.transport.getPeer()),))
        if self.__state.cookie != msgObj.Cookie:
            # ignore mismatching cookies
            return self.__error("Cookies mismatch", fatal=False)
        if self.__state.codeHash != msgObj.RunMobileCodeHash:
            # don't ignore an invalid hash. Sounds like mischief
            return self.__error("Invalid code hash")
        
        if not msgObj.Success:
            return self.__error("Remote code execution failed for %s. Terminating before purchase." % self.__state.cookie)
        self.__state.state = BasicClient.STATE_PURCHASE
        self.__state.encryptedResult = msgObj.EncryptedMobileCodeResultPacket
        self.__factory.protocolSignalsEncryptedResult(self.__state)
        if self.transport: self.transport.loseConnection()
        """
        success, errMsg = self.__factory.registerEncryptedResult(msgObj.ClientNonce, msgObj.ServerNonce,
                                                            msgObj.EncryptedMobileCodeResultPacket)
        if not success:
            return self.__error("Could not register encrypted result: " + errMsg)
        success, errMsg = self.__factory.setPurchaseParameters(msgObj.ClientNonce, msgObj.ServerNonce,
                                                            msgObj.Account, msgObj.RunTime, msgObj.Cost)
        if not success:
            return self.__error("Could not set purchase parameters: " + errMsg)
        
        self.__mode = self.STATE_PURCHASING
        protocolLog(self, logger.info, "Start payForDecryptionKey %s/%s" % (str(msgObj.ClientNonce), str(msgObj.ServerNonce)))
        success, errMsg = self.__factory.payForDecryptionKey(msgObj.ClientNonce, msgObj.ServerNonce,
                                                             self.__purchaseComplete)
        if not success:
            return self.__error("Could not pay for decryption key: " + errMsg)
        
    def __purchaseComplete(self, receipt, receiptSignature):
        protocolLog(self, logger.info, "purchasecomplete callback with receipt.")
        if not self.__mode == self.STATE_PURCHASING:
            return self.__error("Unexpected purchase result. State is %s" % self.__mode)
        if not receipt or not receiptSignature:
            return self.__error("Unable to complete purchase")
        request = MessageData.GetMessageBuilder(PurchaseDecryptionKey)
        self.__setCookie(request)
        request["Receipt"].setData(receipt)
        request["ReceiptSignature"].setData(receiptSignature)
        self.__mode = self.STATE_WAITING_FOR_DECRYPTION_KEY
        
        packetTrace(logger, request, "Sending purchase information. Cookie = %d/%d" % (self.__connData["ClientNonce"],
                                                                                      self.__connData["ServerNonce"]))
        self.transport.writeMessage(request)"""
    
    @ConnectedAPI       
    def sendProofOfPayment(self, state, receipt, receiptSignature):
        if state.state != BasicClient.STATE_PURCHASE:
            self.__error("Not in correct mode to send proof of payment. Got %s, cookie %s" % 
                            (state.state, state.cookie))
        protocolLog(self, logger.info, "%s Sending proof of payment for cookie %s" % (self._connectionId(), state.cookie))
        request = MessageData.GetMessageBuilder(PurchaseDecryptionKey)
        request["Cookie"].setData(state.cookie)
        request["Receipt"].setData(receipt)
        request["ReceiptSignature"].setData(receiptSignature)
        self.__state=state
        self.__awaitingResponse = "ProofOfPayment Response"
        self.transport.writeMessage(request)
        
    def __handleDecryptionKeyResult(self, prot, msg):
        if not self.__state:
            return self.__error("Not ready. No state")
        self.__awaitingResponse = "GetKey Response"
        protocolLog(self, logger.info, "%s Got Decryption Result from %s" % (self._connectionId(), str(self.transport.getPeer())))
        packetTrace(logger, msg, "Decryption Result State: %s " % self.__state.state)
        if self.__state.state != BasicClient.STATE_PURCHASE:
            return self.__error("Unexpected mobile code ack. State is: %s" % self.__state.state)
        msgObj = msg.data()
        if self.__state.cookie != msgObj.Cookie:
            # ignore mismatching cookies
            return self.__error("Cookies mismatch", fatal=False)
        protocolLog(self, logger.info, "Key=%s, iv=%s" % (binascii.hexlify(msgObj.key), binascii.hexlify(msgObj.iv)))
        self.__state.state = BasicClient.STATE_FINISHED
        self.__factory.protocolSignalsKey(self.__state, msgObj.key, msgObj.iv)
        self.transport.loseConnection()
        
        """success, msg = self.__factory.decryptResult(msgObj.ClientNonce, msgObj.ServerNonce, msgObj.key, msgObj.iv)
        if not success:
            return self.__error("Decrypt failed: " + msg)
        self.__mode = self.STATE_FINISHED
        protocolLog(self, logger.info, "Call lose connection on %s" % str(self.transport))
        self.transport.loseConnection()"""
    
    @ConnectedAPI       
    def rerequestKey(self, state):
        if state.state != BasicClient.STATE_FINISHED:
            raise Exception("Can only rerequest key in a finished state. Got " + state.state)
        self.__awaitingResponse = "Rerequest Key Response"
        request = MessageData.GetMessageBuilder(RerequestDecryptionKey)
        request["Cookie"].setData(state.cookie)
        logger.info("%s RerequestDecryptionKey" % self._connectionId())
        self.transport.writeMessage(request)
        
class RemoteCodeStats(object):
    SAMPLES_FOR_USEFUL_STATS = 10
    def __init__(self):
        self.__reset()
        
    def __reset(self):
        self.__totalPurchases = 0
        self.__totalExecutions = 0
        self.__totalTime = 0
        self.__totalCost = 0
        self.__totalSuccesses = 0
        #self.__totalAfterPurchaseFailures = 0
        self.__blacklisted = False
        
    def totalExecutions(self): return self.__totalExecutions
    def totalTime(self): return self.__totalTime
    def useful(self): 
        if self.__blacklisted: return False
        return (self.__totalExecutions > self.SAMPLES_FOR_USEFUL_STATS)
    def averageTimePerExecution(self):
        if self.__totalExecutions == 0: return 0 
        return float(self.__totalTime)/self.__totalExecutions
    def averagePerSecondCost(self):
        if self.__totalTime == 0: return 0 
        return float(self.__totalCost)/self.__totalTime
    def approximateCostPerExecution(self):
        if self.__totalExecutions == 0: return 0 
        return float(self.__totalCost)/self.__totalExecutions
        
    def failures(self):
        return (self.__totalPurchases - self.__totalSuccesses)#self.__totalAfterPurchaseFailures
    def blacklisted(self):
        return self.__blacklisted
    def recordPurchase(self):
        self.__totalPurchases += 1
    def update(self, runTime, cost, failed=False):
        self.__totalExecutions += 1
        self.__totalTime += runTime
        self.__totalCost += cost
        if not failed:
            self.__totalSuccesses += 1#AfterPurchaseFailures+=1
    def setBlacklist(self, status=True):
        self.__blacklisted = status
        if not self.__blacklisted:
            self.__reset()
        
class CodeExecutionData(object):
    PROJECTED_RUNTIME_BOUND = 3.0
    
    def __init__(self, addr, codeId, execId, cookie):
        self.addr = addr
        self.codeId = codeId
        self.execId = execId
        self.encryptedResult = None
        self.account = None
        self.cookie = cookie
        
    def permitPurchase(self, projectedExecutionTime=None):
        # check max run time
        if self.__runtime > self.__maxRuntime: 
            logger.info("Purchase not permitted. %d exceeds max runtime %d" % (self.__runtime, self.__maxRuntime))
            return False
        
        # verify charges
        slices = int(math.ceil(float(self.__runtime)/self.__sliceTime))
        allowedCost = slices * self.__sliceCost
        if self.__cost > allowedCost:
            logger.info("Purchase not permitted. %d cost exceeds allowed cost %d" % (self.__cost, allowedCost))
            return False
        
        if not projectedExecutionTime:
            return True
        
        if self.__runtime > self.__sliceTime and self.__runtime > (self.PROJECTED_RUNTIME_BOUND*projectedExecutionTime):
            logger.info("Purchase not permitted. Exceeds projected time threshold")
            return False
        
        return True
        
class BasicMobileCodeFactory(playground.network.client.ClientApplicationServer.ClientApplicationClient):
    NO_CONNECT_TIMEOUT = 10*60 # Retry a node after 10 minutes
    MAX_RUN_TIME = 5*60
    MAX_AFTER_PURCHASE_FAILURES = 2
    CLIENT_CHECK_INTERVAL = 30 # how often we update our clients
    
    MIB_STATS = "ExecutionStats"
    MIB_BLACK_LIST_FAMILIES = "BlackListFamilies"
    MIB_RECENT_HISTORY = "RecentHistory"
    
    def __init__(self, playground, myAccount, bankFactory, bankAddr, **options):
        self.__playground = playground
        self.__myAccount = myAccount
        self.__bankFactory = bankFactory
        self.__specialMode = None
        self.__addrStats = {}
        self.__codeData = {}
        self.__cookies = {}
        self.__maxRuntime = self.MAX_RUN_TIME
        self.__openClients = {}
        self.__blackList = set([])
        self.__recentHistory = []
        self.__bankAddr = bankAddr
        self.__connectionFailures = {}
        self.__mcServerConnectionType = options.get("mcConnType","RAW")
        self.__bankConnectionType = options.get("bankConnType", "RAW")
        #self.__parallelControl = parallelControl
        
    def getBlacklist(self):
        return list(self.__blackList)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_STATS, self.__handleMib)
            self.registerLocalMIB(self.MIB_BLACK_LIST_FAMILIES, self.__handleMib)
            self.registerLocalMIB(self.MIB_RECENT_HISTORY, self.__handleMib)
        
    def __historyEvent(self, msg):
        if len(self.__recentHistory) > 100:
            self.__recentHistory = self.__recentHistory[:50]
        self.__recentHistory.insert(0, "%s: %s" % (time.ctime(), msg))
        logger.info(msg)
    
    def configureMIBAddress(self, *args, **kargs):
        playground.network.client.ClientApplicationServer.ClientApplicationClient.configureMIBAddress(self, *args, **kargs)
        self.__loadMibs()
        
    """def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_STATS):
            responses = []
            for addr in self.__addrStats.keys():
                stats = self.__addrStats[addr]
                data = "Executions: %d\n" % stats.totalExecutions()
                data += "Total Time: %s\n" % str(stats.totalTime())
                data += "Avg Time Per Execution: %s\n" % str(stats.averageTimePerExecution())
                data += "Avg Per Second Cost: %s\n" % str(stats.averagePerSecondCost())
                data += "Approx Cost Per Execution: %s\n" % str(stats.approximateCostPerExecution())
                data += "Purchased Failures: %s\n" % str(stats.failures())
                data += "Blacklisted: %s\n" % str(stats.blacklisted())
                responses.append("Stats for " + str(addr) + ":\n"+data)
            return responses
        elif mib.endswith(self.MIB_BLACK_LIST_FAMILIES):
            responses = []
            families = self.__blackListFamily.keys()
            if not families:
                return ["<None>"]
            for f in families:
                data = "%s: %s" % (f, str(self.__blackListFamily[f]))
                if len(self.__blackListFamily[f]) > 4:
                    data += " (BLACKLISTED!)"
                responses.append(data)
            return responses
        elif mib.endswith(self.MIB_RECENT_HISTORY):
            return self.__recentHistory
        return []"""
        
    def genericErrorHandler(self, e):
        logger.error("Got an error: %s" % e)

    def peersReceived(self, peerList):
        if self.__parallelControl.finished():
            return
        logger.info("Received %d addresses for running mobile code" % len(peerList))
        
        #print "got addresses", peerList
        #self.mcount = len(peerList)
        #instruction = playground.network.common.DefaultPlaygroundMobileCodeUnit(getRemotePiCodeString(self.n/(1.0*self.mcount)))
        for peerString in peerList:
            logger.info("%s is in peerList" % peerString)
            peer = playground.network.common.PlaygroundAddress.FromString(peerString)
            if self.__openClients.has_key(peer):
                # skip clients to whom we're already connected
                continue
            if peer in self.__blackList:
                logger.info("%s is blacklisted. Skipping" % peer)
                continue
            if self.__connectionFailures.has_key(peer):
                logger.info("%s previously failed." % peer)
                if time.time() < (self.__connectionFailures[peer] + self.NO_CONNECT_TIMEOUT):
                    logger.info("Skipping %s. We'll wait a while yet." % peer)
                    continue
                else:
                    # We've waited a while. Let's try reconnecting to this peer
                    logger.info("Waited long enough. Retrying %s." % peer)
                    del self.__connectionFailures[peer]
            logger.info("Connecting to %s" % peer)
            self.__connectToMobileCodeServer(peer)
            #print "Sending to peer", peerString
            
            # hardcoded port for now
            #srcPort, prot = self.__playground.connect(self, peer, 800, connectionType="RAW")
            #prot = prot.getApplicationLayer()
            #prot.sendPythonCode(instruction, self)
            
            
        OneshotTimer(self.__checkClients).run(self.CLIENT_CHECK_INTERVAL)
        
    def __connectToMobileCodeServer(self, peer):
        if self.__openClients.has_key(peer):
            # later, check if there are too many connections. For now, do nothing
            # client = self.__openClients[peer]
            pass
        else:
            self.__openClients[peer] = BasicClient(self.__playground, peer, self.__mcServerConnectionType)
        codeId = self.__parallelControl.mobileCodeId()
        maxRate = self.__parallelControl.maxRate()
        
        d = self.__openClients[peer].connect(codeId, maxRate)
        
        d.addCallback(self.__buildClientConnectedCallback(peer))
        d.addErrback(self.__buildClientConnectionErrback(peer))
        
    def __buildClientConnectedCallback(self, peer):
        def callback(cookie):
            if self.__parallelControl.finished():
                return
            codeId = self.__parallelControl.mobileCodeId()
            
            maxRuntime = self.__parallelControl.maxRuntime()
            codeStr, execId = self.__parallelControl.getNextCodeUnit(str(peer))
            if codeStr == None:
                # no next code unit. Might not be done though
                # errors get reinserted into the queue. We have an open
                # connection though, let's try again in just a few seconds
                OneshotTimer(self.__buildClientConnectedCallback(peer)).run(30)
                return
            self.__codeData[execId] = CodeExecutionData(peer, codeId, execId, cookie)
            self.__cookies[cookie] = self.__codeData[execId]
            d = self.__openClients[peer].runMobileCode(cookie, execId, codeStr, maxRuntime)
            if not d:
                return self.__errorWithCode("Could not execute mobile code", execId, cookie, fatal=True)
            d.addCallback(self.registerEncryptedResult)
            d.addErrback(lambda failure: self.__errorWithCode(str(failure), execId, fatal=True))
        return callback
        
    def __buildClientConnectionErrback(self, peer):
        def errback(failure):
            logger.error("Could not connect to peer %s: %s. Adding to connection failures" % (peer, failure))
            if self.__openClients.has_key(peer):
                del self.__openClients[peer]
            self.__connectionFailures[peer] = time.time()
            return Failure
        return errback
        
    def __checkClients(self):
        if self.__parallelControl.finished():
            return
        checkClientKeys = self.__openClients.keys()
        getMorePeers = False
        for clientAddr in checkClientKeys:
            client = self.__openClients[clientAddr]
            if client.runningJobs() == 0:
                logger.info("Peer %s is finished. Removing from protocol state" % clientAddr)
                del self.__openClients[clientAddr]
                getMorePeers = True
        if getMorePeers:
            self.autoDiscover()
        else:
            OneshotTimer(self.__checkClients).run(self.CLIENT_CHECK_INTERVAL)
        
    def autoDiscover(self):
        if not self.__parallelControl.finished():
            self.__playground.getPeers(self.peersReceived)
        #else:
        #    # nothing to do here. We're done
        #    self.__finishedCallback()
        
    def runParallel(self, parallelControl, finishedCallback):
        #if isinstance(parallelControl, MIBAddressMixin):
        #    self.configureMIBAddress("BasicMobileCode", parallelControl, parallelControl.MIBRegistrar())
        self.__parallelControl = parallelControl
        self.__finishedCallback = finishedCallback
        self.autoDiscover()
    
    def checkBalance(self):
        srcPort, bankProtocol = self.__playground.connect(self.__bankFactory,
                                                              self.__bankAddr, 
                                                              BANK_FIXED_PLAYGROUND_PORT,
                                                              connectionType=self.__bankConnectionType)
        bankCmd = BankClientSimpleCommand()
        return bankCmd(bankProtocol, self.__myAccount, BankClientProtocol.getBalance)
        
    
    def buildProtocol(self, addr):
        raise Exception("I don't think I do this anymore")
    
    """def getCodeForConnection(self, ClientNonce, ServerNonce, addr, BillingTimeSliceSeconds, BillingRatePerSlice):
        addr = addr.toString()
        perSecondCost = float(BillingRatePerSlice)/BillingTimeSliceSeconds
        if perSecondCost > self.MAX_COST_PER_SECOND:
            rejectMessage = "Per-second-cost (%f) exceeds threshold (%f)" % (perSecondCost, self.MAX_COST_PER_SECOND)
            self.__historyEvent(rejectMessage)
            return False, rejectMessage
        cookie = str(ClientNonce) + str(ServerNonce)
        if self.__cookies.has_key(cookie):
            return False, "Duplicate cookie"
        willUse = True
        if not self.__addrStats.has_key(addr):
            #willUse = True
            self.__addrStats[addr] = RemoteCodeStats()
        elif self.__addrStats[addr].blacklisted():
            return False, "Blacklisted"
        elif self.__addrStats[addr].failures() > self.MAX_AFTER_PURCHASE_FAILURES:
            self.blacklistAddr(addr)
            self.__historyEvent("%s has had too many purchased failures and is now blacklisted" % str(addr))
            return False, "Too many failures (now blacklisted)"
        elif self.__addrStats[addr].useful():
            logger.info("Attempt to determine cost effectiveness of node")
            # we will use our most "cost effective" nodes 100% of the time
            # For each node that is x times more expensive will be used
            # x times less often
            sortList = []
            addrStats = self.__addrStats[addr]
            predictedCost = addrStats.predictCostForExecution(BillingTimeSliceSeconds, BillingRatePerSlice)
            logger.info("Slice time: %d, Slice cost: %d, predicted cost: %f" % (BillingTimeSliceSeconds,
                                                                                BillingRatePerSlice,
                                                                                predictedCost))
            for auctionNode in self.__addrStats.keys():
                auctionStats = self.__addrStats[auctionNode]
                if not auctionStats.useful():
                    continue
                if auctionNode == addr:
                    sortList.append((predictedCost, addr))
                else:
                    sortList.append((auctionStats.approximateCostPerExecution(), auctionNode))
            logger.info("Auction data: " + str(sortList))
            if len(sortList) == 0:
                willUse = True
            else:
                sortList.sort()
                cheapestCost = sortList[0][0]
                logger.info("Cheapest cost: %f" % cheapestCost)
                if predictedCost == cheapestCost:
                    logger.info("Node is cheapest... always use")
                    willUse = True
                else:
                    costMultiplier = float(predictedCost)/cheapestCost
                    odds = 1.0/costMultiplier
                    logger.info("Node costMultiplier: %f, odds: %f" %(costMultiplier, odds))
                    willUse = (random.random() <= odds)
        if not willUse:
            return False, "Node too expensive. Not using."
        codeStr, codeId = self.__parallelControl.getNextCodeUnit(addr)
        if not codeStr or not codeId:
            return False, "No code string from parallel computation (possibly finished)."
        self.__cookies[cookie] =  CodeExecutionData(addr, codeId, 
                                                    BillingTimeSliceSeconds, 
                                                    BillingRatePerSlice, 
                                                    self.__maxRuntime)
        self.__historyEvent("Got code string (len: %d) with ID %d for address %s" % (len(codeStr), codeId, str(addr)))
        return True, (codeStr, codeId, self.__maxRuntime)"""
    
    def __errorWithCode(self, errorMsg, execId=None, cookie=None, fatal=True):
        codeData = None
        if execId != None and self.__codeData.has_key(execId):
            codeData = self.__codeData[execId]
        if not codeData and cookie != None and self.__cookies.has_key(cookie):
            codeData = self.__cookies[cookie]
        
        if codeData and execId != None and codeData.execId != execId:
            logger.error("While reporting error, noted mismatch between requested id %s and stored id %s" % (execId, codeData.execId))
        if codeData and cookie != None and codeData.cookie != cookie:
            logger.error("While reporting error, noted mismatch between requested cookie %s and stored cookie %s" % (cookie, codeData.cookie))    
        
        if not codeData:
            identifier = "[No identifiying info, passed %s, %s]" % (execId, cookie)
        else:
            identifier = "[MCServer: %s, ExecId: %s, Cookie: %s]" % (codeData.addr, codeData.execId, codeData.cookie)
        logger.error("%s Error: %s" % (identifier, errorMsg))
        if fatal and codeData:
            if self.__openClients.has_key(codeData.addr):
                logger.error("Trying to cancel job %s" %  codeData.execId)
                try:
                    self.__openClients[codeData.addr].cancel(codeData.execId)
                    logger.error("Cancelled job %s" % codeData.execId)
                except Exception, e:
                    logger.error("Could not cancel job %s. Reason: %s" % (codeData.execId, e))
            if self.__codeData.has_key(codeData.execId):
                logger.error("Removing stored code data with id %s" % codeData.execId)
                del self.__codeData[codeData.execId]
            if self.__cookies.has_key(codeData.cookie):
                logger.error("Removing stored cookie data %s" % codeData.cookie)
                del self.__cookies[codeData.cookie]
            logger.error("Trying to alert parallel program that code failed for id %s" % codeData.execId)
            try:
                self.__parallelControl.codeErrback(codeData.execId, errorMsg)
                logger.error("Reported")
            except Exception, e:
                logger.error("Could not alert parallel program that code failed for id %s. Reason: %s" % 
                             (codeData.execId, e))

    def registerEncryptedResult(self, result):
        cookie, EncryptedMobileCodeResultPacket, billingRate, account = result
        if not self.__cookies.has_key(cookie):
            logger.error("Unknown session with cookie %s" % cookie)
            return
        session = self.__cookies[cookie]
        if not self.__codeData.has_key(session.execId):
            self.__errorWithCode("Internal mismatch between cookie and execId", 
                                 session.execId, session.cookie, fatal=True)
            return
        if session.encryptedResult:
            logger.error("Already have a result for %s cookie %s" % (session.addr, session.cookie))
            return
        session.encryptedResult = EncryptedMobileCodeResultPacket
        self.__startPurchase(session.addr, account, billingRate, cookie, 
                             lambda receipt, sig: self.afterPurchase(session, receipt, sig))
        
    def afterPurchase(self, codeData, receipt, receiptSignature):
        logger.info("Purchase complete. Sending proof of payment for execid: %s, cookie: %s" % 
                    (codeData.execId, codeData.cookie))
        client = self.__openClients.get(codeData.addr, None)
        if not client:
            self.__errorWithCode("Could not find client data for addr %s" % codeData.addr, codeData.execId, fatal=True) 
            return
        if not receipt or not receiptSignature:
            self.__errorWithCode("Bank failure. Could not transfer money.", codeData.execId, fatal=True)
        else:
            d = client.sendProofOfPayment(codeData.cookie, receipt, receiptSignature)
            if not d:
                self.__errorWithCode("Failure to send Proof of Payment", 
                                     codeData.execId, codeData.cookie, fatal=True)
            d.addCallback(self.decryptResult)
            d.addErrback(lambda failure: self.__errorWithCode(str(failure), codeData.execId, fatal=True))
    
    """def setPurchaseParameters(self, ClientNonce, ServerNonce, Account, Runtime, Cost):
        cookie = str(ClientNonce) + str(ServerNonce)
        if not self.__cookies.has_key(cookie):
            return False, "No such cookie"
        data = self.__cookies[cookie]
        if data.payableAccount():
            return False, "Already have purchase parameters for this cookie"
        if not data.validateReportedRuntime(Runtime):
            #self.__addrStats[data.addr()].setBlacklist()
            self.blacklistAddr(data.addr())
            return False, "Dishonest runtime reported"
        data.setPurchaseParameters(Account, Runtime, Cost)
        return True, ""
        """
    
    """def payForDecryptionKey(self, ClientNonce, ServerNonce, callback):
        cookie = str(ClientNonce) + str(ServerNonce)
        if not self.__cookies.has_key(cookie):
            return False, "No such cookie"
        data = self.__cookies[cookie]
        projectedRunTime = None
        stats = self.__addrStats[data.addr()]
        if stats.useful():
            projectedRunTime = stats.averageTimePerExecution()
        else:
            avgSum = 0.0
            total = 0
            for statsObj in self.__addrStats.values():
                if statsObj.useful():
                    avgSum += statsObj.averageTimePerExecution()
                    total += 1
            if total > 0:
                projectedRunTime = avgSum/total
        if not data.permitPurchase(projectedRunTime):
            return False, "Purchase too expensive (outside of bounds)"
        self.__startPurchase(data.addr(), data.payableAccount(), data.costToPurchaseKey(), cookie, callback)
        return True, ""
        """
    
    def __startPurchase(self, addr, account, amount, memo, callback):
        srcPort, bankProtocolStack = self.__playground.connect(self.__bankFactory,
                                                              self.__bankAddr, 
                                                              BANK_FIXED_PLAYGROUND_PORT,
                                                              connectionType=self.__bankConnectionType)
        bankProtocol = bankProtocolStack
        logger.info("Logging into bank for %s transfer for work done by %s" % (str(memo), str(addr)))
        d = bankProtocol.waitForConnection()
        d.addCallback(lambda result: self.__startLogin(bankProtocol, addr, account, amount, memo, callback))
        d.addErrback(lambda failure: self.__loginFailed(bankProtocol, addr, callback, failure))
        
    def __startLogin(self, bankProtocol, addr, account, amount, memo, callback):
        d = bankProtocol.loginToServer()
        d.addCallback(lambda msgObj: self.__loginComplete(bankProtocol, addr, account, amount, memo, callback))
        d.addErrback(lambda failure: self.__loginFailed(bankProtocol, addr, callback, failure))
        
    def __loginComplete(self, bankProtocol, addr, account, amount, memo, finalCallback):
        self.__historyEvent("Switching to my account %s" % self.__myAccount)
        d = bankProtocol.switchAccount(self.__myAccount)
        d.addCallback(lambda result: self.__switchComplete(bankProtocol, addr, account, amount, memo, finalCallback))
        d.addErrback(lambda failure: self.__accountFailure(bankProtocol, addr, finalCallback, failure))
        
    def __switchComplete(self, bankProtocol, addr, account, amount, memo, finalCallback):
        self.__historyEvent("Connected to my account %s. Starting transfer from my account to %s (addr :%s, amount: %d, memo: %s" % 
                            (self.__myAccount, account, addr, amount, memo))
        d = bankProtocol.transfer(account, amount, memo)
        d.addCallback(lambda msgObj: self.__transferSuccessful(bankProtocol, addr, msgObj, finalCallback))
        d.addErrback(lambda failure: self.__transferFailed(bankProtocol, finalCallback, failure))
        
    def __loginFailed(self, bankProtocol, addr, finalCallback, failure):
        bankProtocol.close()
        logger.error("Login to bank failed: " + str(failure))
        finalCallback(None, None)
        # don't return failure unless you want this to halt execution in some way
        #return failure
    
    def __switchFailed(self, bankProtocol, addr, finalCallback, failure):
        bankProtocol.close()
        logger.error("Switch to account %s failed: %s" % (self.__myAccount, failure))
        finalCallback(None, None)
        # don't return failure unless you want this to halt execution in some way
        #return failure
        
    def __transferSuccessful(self, bankProtocol, addr, msgObj, finalCallback):
        bankProtocol.close()
        #stats = self.__addrStats[addr]
        #stats.recordPurchase()
        logger.info("Transfer for code execution from %s successful. Handing off receipt" % (addr, ))
        receipt, receiptSignature = msgObj.Receipt, msgObj.ReceiptSignature
        finalCallback(receipt, receiptSignature)
        
    def __transferFailed(self, bankProtocol, finalCallback, failure):
        bankProtocol.close()
        logger.error("Bank transfer failed: %s" % failure)
        finalCallback(None, None)
        # Don't return the failure unless you want this to halt execution in some way
        #return failure
        
    def decryptResult(self, result):
        cookie, key, iv = result
        if not self.__cookies.has_key(cookie):
            logger.error("Decrypt Result: No such cookie %s" % cookie)
            return# False, "No such cookie"
        data = self.__cookies[cookie]
        #addrStats = self.__addrStats[data.addr()]
        encryptedData = data.encryptedResult
        if not encryptedData:
            logger.error("Decrypt Result: No encrypted data for cookie %s" % cookie)
            return #False, "No encrypted data to decrypt"
        if len(key) != 16:
            self.__blackList.add(data.addr)
            self.__errorWithCode("Decrypt Result: Setting %s blacklisted for invalid key (len %d) for cookie %s" % 
                        (data.addr, len(key), cookie),
                        cookie=cookie,
                        fatal=True)
            #addrStats.setBlacklist()
            #self.blacklistAddr(data.addr())
            return #False, "Invalid Key Length"
        if len(iv) != 16:
            self.__blackList.add(data.addr)
            self.__errorWithCode("Decrypt Result: Setting %s blacklisted for invalid iv (len %d) for cookie %s" % 
                        (data.addr, len(iv), cookie),
                        cookie=cookie,
                        fatal=True)
            #addrStats.setBlacklist()
            #self.blacklistAddr(data.addr
            return #False, "Invalid IV Length"
        decrypter = AES.new(key, mode=AES.MODE_CBC, IV=iv)
        plaintext = decrypter.decrypt(encryptedData)
        unpaddedData = Pkcs7Padding(AES.block_size).unpadData(plaintext)
        try:
            mobileCodeResultPacket = MessageData.Deserialize(unpaddedData)[0]
        except Exception, e:
            #addrStats.update(data.actualRuntime(), data.costToPurchaseKey(),failed=True)
            self.__blackList.add(data.addr)
            self.__errorWithCode("Blacklisting %s. Decrypt Result: Encrypted data for cookie %s could not decrypt. Reason %s" % 
                         (data.addr, cookie, e),
                         cookie=cookie,
                         fatal=True)
            return #False, "Could not restore data: " + str(e)
        mobileCodeResultObj = mobileCodeResultPacket.data()
        picklePart = (mobileCodeResultObj.success and mobileCodeResultObj.resultPickled or mobileCodeResultObj.exceptionPickled)
        reactor.callInThread(self.runControlCallback, data, cookie, mobileCodeResultObj, picklePart)

    def runControlCallback(self, data, cookie, mobileCodeResultObj, picklePart):
        success, errMsg = self.__parallelControl.pickleBack(data.execId, mobileCodeResultObj.success, picklePart)
        reactor.callFromThread(self.returnFromControlCallback, data, cookie, picklePart, success, errMsg)

    def returnFromControlCallback(self, data, cookie, picklePart, success, errMsg):
        if not success:
            self.__blackList.add(data.addr)
            logger.error("Will blacklist %s for bad computation." % data.addr)
            logger.error(picklePart)
            self.__errorWithCode("Blacklisting %s. Reason: %s" % (data.addr, errMsg), data.execId, cookie, fatal=True)
        elif self.__parallelControl.finished():
            self.__finishedCallback()
        else:
            self.__connectToMobileCodeServer(data.addr)
        """success = True
        if mobileCodeResultObj.success:
            try:
                resultObj = pickle.loads(mobileCodeResultObj.resultPickled)
            except Exception, e:
                addrStats.update(data.actualRuntime(), data.costToPurchaseKey(),failed=True)
                success, errMsg = False, "Could not restore successful result: " + str(e)
            if success:
                success, errMsg = self.__parallelControl.codeCallback(data.codeId(), resultObj)
        else:
            try:
                exceptionObj = pickle.loads(mobileCodeResultObj.exceptionPickled)
            except Exception, e:
                addrStats.update(data.actualRuntime(), data.costToPurchaseKey(),failed=True)
                success, errMsg = False, "Could not restore exception: " + str(e)
            if success:
                success, errMsg = self.__parallelControl.codeErrback(data.codeId(), exceptionObj)"""
        """self.__historyEvent("Updating runtime stats for %s. Runime: %d, cost: %d, success: %s" % (data.addr(),
                                                                                   data.actualRuntime(), 
                                                                                   data.costToPurchaseKey(), 
                                                                                   str(success)))
        addrStats.update(data.actualRuntime(), data.costToPurchaseKey(), failed=(not success))
        if success:
            return True, ""
        else:
            return False, "Code result or exception not accepted for addr %s: %s" % (str(data.addr()), errMsg)"""


