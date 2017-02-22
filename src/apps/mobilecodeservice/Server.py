'''
Created on Apr 2, 2014

@author: sethjn
'''
import playground
from playground.config import LoadOptions
from playground.crypto import X509Certificate
from playground.network.common import Packet
from playground.network.message import definitions
from playground.network.message import MessageData
from playground.sandbox.pypy.SandboxCodeRunner import SandboxCodeRunner
#from playground.network.message import definitions
from ServiceMessages import OpenSession, SessionOpen, SessionOpenFailure, EncryptedMobileCodeResult
from ServiceMessages import PurchaseDecryptionKey, RunMobileCodeFailure, AcquireDecryptionKeyFailure
from ServiceMessages import RerequestDecryptionKey, GeneralFailure, ResultDecryptionKey, SessionRunMobileCode
from ServiceMessages import RunMobileCodeAck, CheckMobileCodeResult

import random, time, math, os, shelve, pickle, sys, binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from playground.playgroundlog import packetTrace, logging, LoggingContext
from binhex import binhex
from twisted.internet.protocol import Protocol, Factory
from playground.network.common.statemachine.StateMachine import StateMachine
from apps.mobilecodeservice.ServiceMessages import RerequestDecryptionKey,\
    SessionRunMobileCode, CheckMobileCodeResult, PurchaseDecryptionKey
from playground.network.common.Protocol import MessageStorage
from playground.error.ErrorHandler import GetErrorReporter
from playground.network.common.Timer import callLater
from apps.mobilecodeservice.MobileCodeHandler import SimpleMobileCodeHandler
from playground.network.message.ProtoBuilder import MessageDefinition

errReporter = GetErrorReporter(__name__)
logger = logging.getLogger(__name__)

from apps.bank.BankCore import LedgerLine

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

LOCATION_OF_PLAYGROUND = os.path.dirname(playground.__file__)

MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT = 800

class CodeExecutionContext(object):
    def __init__(self):
        self.startTime = None
        self.cookie = None
        self.runMobileCodeHash = None
        self.finishCallback = None
        
class WrapMobileCodeResultProtocol(object):
    def __init__(self, transport):
        self.transport = transport

class WrapMobileCodeResultTransport(object):
    def __init__(self, peer, host, aesKey, aesIV, ctx):
        self.__key = aesKey
        self.__iv = aesIV
        self.__ctx = ctx
        self.__peer = peer
        self.__host = host
        self.__written = False
        self.__deserialized = None
        
    def write(self, data):
        if self.__written:
            raise Exception("Internal Error. This should never happen")
        self.__written = True
        if not self.__deserialized:
            self.__deserialized, desBytes = MessageData.Deserialize(data)
        endTime = time.time()
        runTimeInSeconds = int(endTime-self.__ctx.startTime)
        runTimeInSeconds += 1
        logger.info("Finished execution of code in %f seconds" % runTimeInSeconds)
        response = MessageData.GetMessageBuilder(EncryptedMobileCodeResult)
        response["Cookie"].setData(self.__ctx.cookie)
        response["RunTime"].setData(runTimeInSeconds)
        response["RunMobileCodeHash"].setData(self.__ctx.runMobileCodeHash)
        if self.__deserialized.topLevelData()[0] != definitions.playground.base.MobileCodeResult.PLAYGROUND_IDENTIFIER:
            response["Success"].setData(False)
            response["EncryptedResult"].setData("")
        else:
            encrypter = AES.new(self.__key, mode=AES.MODE_CBC, IV=self.__iv)
            padder = playground.crypto.Pkcs7Padding(AES.block_size)
            encrypted = encrypter.encrypt(padder.padData(data))
            response["Success"].setData(self.__deserialized["success"].data())
            response["EncryptedMobileCodeResultPacket"].setData(encrypted)
        # in some ways, it would be easier to save "response" rather than 
        # response serialized. But we're saving this stuff to disk in case
        # of interruption or disconnect. So serialized it is.
        self.__ctx.finishCallback(self.__ctx, response.serialize())
        
        packetTrace(logger, response, "Encrypted mobile code result ready for transmission")
        
    def writeMessage(self, m):
        self.__deserialized = m
        self.write(m.serialize())
        
    def writeSequence(self, buffers):
        raise Exception("Only expected a single response to a single run mobile code packet")
    
    def writeMessages(self, messages):
        raise Exception("Only expected a single response to a single run mobile code packet")
    
    def getHost(self): return self.__host
    def getPeer(self): return self.__peer
    def loseConnection(self): pass
    def abortConnection(self): pass

class ServerProtocol(Protocol):
    
    STATE_UNINIT = "Uninitialized"
    STATE_RESTORE_STATE = "Restore state in connectionless protocol"
    STATE_OPEN = "Open"
    STATE_FINISHED = "Finished"
    STATE_PURCHASE = "Purchase decryption key started"
    STATE_REREQUEST = "Rerequest decryption key"
    STATE_RUNNING = "Running code"
    STATE_ERROR = "Error"
    
    SIGNAL_CODE_EXECUTION_COMPLETE = "Finished Code Execution"
    
    SIGNAL_RESTORE_OPEN = "Return to Open State"
    SIGNAL_RESTORE_RUNNING = "Return to Running State"
    SIGNAL_RESTORE_PURCHASE = "Return to Purchase State"
    SIGNAL_RESTORE_FINISHED = "Return to Finished State"
    SIGNAL_NO_CHARGE = "Billing rate is zero. No charge for computation."
    
    CODE_TIMEOUT = 1*60*60 # one hour maximum run
    
    #SANDBOX_CONTROLLER = os.path.join(LOCATION_OF_PLAYGROUND, "extras", "sandbox", "IOEnabledSandbox.py")

    
    def __init__(self, accountName):
        
        # The ServerProtocol state machine can work in a connection oriented
        # or connectionless fashion. The restore signals return it to the 
        # saved state
        
        self.__fsm = StateMachine()
        
        self.__fsm.addState(self.STATE_UNINIT,
                            (SessionRunMobileCode, self.STATE_RESTORE_STATE),
                            (CheckMobileCodeResult, self.STATE_RESTORE_STATE),
                            (PurchaseDecryptionKey, self.STATE_RESTORE_STATE),
                            (RerequestDecryptionKey, self.STATE_RESTORE_STATE),
                            
                            (OpenSession, self.STATE_OPEN))
        
        self.__fsm.addState(self.STATE_RESTORE_STATE,
                            (self.SIGNAL_RESTORE_OPEN, self.STATE_OPEN),
                            (self.SIGNAL_RESTORE_RUNNING, self.STATE_RUNNING),
                            (self.SIGNAL_RESTORE_PURCHASE, self.STATE_PURCHASE),
                            (self.SIGNAL_RESTORE_FINISHED, self.STATE_FINISHED),
                            onEnter=self.__handleRestoreState)
        
        self.__fsm.addState(self.STATE_OPEN, 
                            (SessionRunMobileCode, self.STATE_RUNNING),
                            onEnter=self.__handleOpenSession)
        
        self.__fsm_addState(self.STATE_RUNNING, 
                            # TRANSITIONS
                            (self.SIGNAL_CODE_EXECUTION_COMPLETE, self.STATE_PURCHASE),
                            (CheckMobileCodeResult, self.STATE_RUNNING),
                            # Callback
                            onEnter=self.__handleRunMobileCode)
        
        self.__fsm.addState(self.STATE_PURCHASE,
                            (self.SIGNAL_NO_CHARGE, self.STATE_FINISHED), 
                            (PurchaseDecryptionKey, self.STATE_FINISHED),
                            (CheckMobileCodeResult, self.STATE_PURCHASE),
                            onEnter=self.__mobileCodeComplete)
        
        self.__fsm.addState(self.STATE_FINISHED, 
                            (CheckMobileCodeResult, self.STATE_FINISHED),
                            (RerequestDecryptionKey, self.STATE_FINISHED),
                            onEnter=self.__handleFinished)
        self.__fsm.addState(self.STATE_ERROR, onEnter=self.__handleError)
        self.__fsm.start(self.STATE_UNINIT, self.STATE_ERROR)
    
        self.__stateContext = None
        self.__accountName = accountName
        self.__codeString = None
        self.__curState = None
        self.__storage = MessageStorage()
    
    def dataReceived(self, data):
        self.__storage.update(data)
        for msg in self.__storage.iterateMessages():
            self.__fsm.signal(msg.__class__, msg)    

        
    def close(self):
        if self.transport: self.transport.loseConnection()
        self.transport = None
        
    def writeMessageAndClose(self, msg):
        self.transport.write(msg.__serialize__())
        callLater(0, self.close)

    def __handleError(self, signal, data):
        errReporter.error("Entered error state on signal %s with data %s" % (signal, data))
        callLater(0, self.close)
        
    def __sendError(self, errorType, msg, **kargs):
        failure = errorType(ErrorMessage=msg, **kargs)
        self.writeMessageAndClose(failure)
        
    def __handleRestoreState(self, signal, data):
        # all messages that come to this state should have a Cookie
        try:
            restoreKey = data.Cookie
        except:
            return self.close()# TODO fix
        self.__stateContext = self.factory.getSessionState(restoreKey)
        if not self.__stateContext:
            return self.close() # TODO Fix
        
        logger.info("Restoring State for cookie %s. Next signal %s" % (data.Cookie, self.__stateContext.nextSignal))
        self.__fsm.signal(self.__stateContext.restoreStateSignal, data)
        
    def __handleOpenSession(self, signal, data):
        if signal == self.SIGNAL_RESTORE_OPEN:
            self.__fsm.signal(data.__class__, data)
        
        elif signal == SessionOpen:
            openSessionMsg = data
    
            if openSessionMsg.Authenticated:
                return self.__sendError(SessionOpenFailure,
                                        "Authenticated operation not yet supported",
                                        ClientNonce=openSessionMsg.ClientNonce)
    
            self.__stateContext = self.factory.createSessionContext(openSessionMsg.ClientNonce, 
                                                                  openSessionMsg.MobileCodeId)
            self.__stateContext.restoreStateSignal = self.SIGNAL_RESTORE_OPEN
            if not self.__stateContext:
                return self.__sendError(SessionOpenFailure, 
                                        "Unwilling to respond to this request",
                                        ClientNonce=openSessionMsg.ClientNonce)
            response = SessionOpen(ClientNonce  =openSessionMsg.clientNonce,
                                   Cookie       =self.__stateContext.cookie,
                                   ServiceLevel =self.__stateContext.level,
                                   BillingRate  =self.__stateContext.billingRate,
                                   Account      =self.__accountName,
                                   ServiceExtras=self.__stateContext.extras)
            self.writeMessageAndClose(response)
            
        else:
            return self.close() # TODO Fix
            
        
    def __handleRunMobileCode(self, signal, data):
        self.__stateContext.restoreStateSignal = self.SIGNAL_RESTORE_RUNNING
        if signal == self.SIGNAL_RESTORE_RUNNING:
            self.__fsm.signal(data.__class__, data)
        
        elif signal == SessionRunMobileCode:
            runMobileCodeMsg = data
            if runMobileCodeMsg.MaxRuntime > self.CODE_TIMEOUT:
                response = RunMobileCodeAck(Cookie            =self.__stateContext.Cookie,
                                            MobileCodeAccepted=False,
                                            Message           ="Max run time parameter is too long.")
                return self.writeMessageAndClose(response)
            
            success, msg = self.factory.execute(runMobileCodeMsg.ID,
                                                runMobileCodeMsg.Mechanism,
                                                runMobileCodeMsg.PythonCode,
                                                (runMobileCodeMsg.SaveKey != MessageDefinition.UNSET and runMobileCodeMsg.SaveKey or None),
                                                self.__stateContext.cookie)
            
            response = RunMobileCodeAck(Cookie             = self.__stateContext.cookie,
                                        MobileCodeAccepted = success,
                                        Message            = msg)
            
            self.writeMessageAndClose(response)
        elif signal == CheckMobileCodeResult:
            if self.__stateContext.encryptedResult != None:
                self.__fsm.signal(self.SIGNAL_CODE_EXECUTION_COMPLETE, None)
                return
            response = RunMobileCodeAck(Cookie=self.__curState.cookie,
                                        MobileCodeAccepted=True,
                                        Message="Still running")

            return self.writeMsgAndClose(response)
                        
        """rawRunMobileCodeMsg = msgObj.RunMobileCodePacket
        startTime = time.time()
        ctx = CodeExecutionContext()
        ctx.startTime = startTime
        ctx.cookie = self.__curState.cookie
        ctx.runMobileCodeHash = SHA.new(rawRunMobileCodeMsg).digest()
        ctx.finishCallback = lambda ctx, response: self.__factory.mobileCodeComplete(ctx.cookie, response)
        aesKey = os.urandom(16)
        aesIv = os.urandom(16)
        succeed, errmsg = self.__factory.createMobileCodeRecord(self.__curState.cookie, 
                                                                aesKey, aesIv, msgObj.MaxRuntime)
        if not succeed:
            return self.__error("Could not run this code. Reason: " + errmsg, fatal=True)
        transport = WrapMobileCodeResultTransport(self.transport.getPeer(), self.transport.getHost(),
                                                  aesKey, aesIv, ctx)
        wrappedProtocol = WrapMobileCodeResultProtocol(transport)
        logger.info("Starting execution of mobile code. MaxRunTime: %d" % msgObj.MaxRuntime)
        #realCodeHandler = playground.extras.sandbox.SandboxCodeunitAdapter(self.SANDBOX_CONTROLLER,
                                                                       #timeout=min(msgObj.MaxRuntime,self.CODE_TIMEOUT))
        #codeHandler = lambda codeUnit: self.__codeHandlerWrapper(realCodeHandler, codeUnit)
        runMobileCodeHandler = RunMobileCodeHandler(self, sandbox=SandboxCodeRunner())
        runMobileCodeHandler(wrappedProtocol, MessageData.Deserialize(rawRunMobileCodeMsg)[0])
        self.__curState.state = self.STATE_RUNNING
        response = MessageData.GetMessageBuilder(RunMobileCodeAck)
        response["Cookie"].setData(self.__curState.cookie)
        response["MobileCodeAccepted"].setData(True)
        self.writeMsgAndClose(response)"""
        
    def __generateEncryptedResultMessage(self):
        response = EncryptedMobileCodeResult(Cookie=self.__stateContext.cookie,
                                             RunTime=self.__stateContext.runtime,
                                             RunMobileCodeHash=self.__stateContext.runMobileCodeHash,
                                             EncryptedMobileCodeResultPacket=self.__stateContext.encryptedResult)
        if self.__stateContext.encryptedResult != "":
            response.Success = True
        else: response.Success = False
        return response
    
    def __generateDecryptionKeyMessage(self):
        decryptionKey, decryptionIv = self.__factory.getDecryptionData(data.Cookie)
        response = ResultDecryptionKey(Cookie=self.__stateContext.cookie,
                                       key=decryptionKey,
                                       iv=decryptionIv)
        return response
    
    def __mobileCodeComplete(self, signal, data):
        self.__stateContext.restoreStateSignal = self.SIGNAL_RESTORE_PURCHASE
        if signal == self.SIGNAL_RESTORE_RUNNING:
            self.__fsm.signal(data.__class__, data)
        elif signal == self.SIGNAL_CODE_EXECUTION_COMPLETE or signal == CheckMobileCodeResult:
            if self.__stateContext.billingRate == 0:
                self.__fsm.signal(self.SIGNAL_NO_CHARGE, data)
                return
            response = self.__generateEncryptedResultMessage()
            return self.writeMessageAndClose(response)
        
    def __handleFinished(self, signal, data):
        self.__stateContext.restoreStateSignal = self.SIGNAL_RESTORE_FINISHED
        if signal == self.SIGNAL_RESTORE_RUNNING:
            self.__fsm.signal(data.__class__, data)
        elif signal == PurchaseDecryptionKey or signal == self.SIGNAL_NO_CHARGE:
            if signal == PurchaseDecryptionKey:
                pass
            response = self.__generateDecryptionKeyMessage()
            self.writeMessageAndClose(response)
        elif signal == CheckMobileCodeResult:
            if self.__stateContext.paid >= self.__stateContext.billingRate:
                response = self.__generateDecryptionKeyMessage()
            else:
                response = self.__generateEncryptedResultMessage()
            self.writeMessageAndClose(response)
        
        
    def __handleCheckMobileCodeResult(self, prot, msg):
        msgObj = msg.data()
        self.__curState = self.__factory.getSessionState(msgObj.Cookie)
        if not self.__curState:
            return self.__error("No such session found for cookie %s." % msgObj.Cookie, 
                                fatal=True)
        elif self.__curState.state == self.STATE_RUNNING:
            response = MessageData.GetMessageBuilder(RunMobileCodeAck)
            response["Cookie"].setData(self.__curState.cookie)
            response["MobileCodeAccepted"].setData(True)
            response["Message"].setData("Still running")
            return self.writeMsgAndClose(response)
        elif self.__curState.state == self.STATE_PURCHASE:
            # curState.encryptedResult is an already serialized packet.
            # so we can't use writeMsg. Have to write, then close
            # Can't do this here: self.writeMsgAndClose(self.__curState.encryptedResult)
            self.transport.write(self.__curState.encryptedResult)
            return self.transport.loseConnection()
        if self.__curState.state not in [self.STATE_RUNNING, self.STATE_PURCHASE]:
            return self.__error("Invalid command. Cannot check result in state (%s) cookie %s" % 
                                (self.__curState.state, self.__curState.cookie),
                                fatal=False)
        
    def __handlePurchase(self, prot, msg):
        msgObj = msg.data()
        self.__curState = self.__factory.getSessionState(msgObj.Cookie)
        if self.__curState.state != self.STATE_PURCHASE:
            return self.__error("Invalid command. Not in correct state for purchase (%s)" % self.__curState.state,
                                fatal=False)
        
        if not self.__factory.validatePurchase(msgObj.Cookie,
                                               msgObj.Receipt, msgObj.ReceiptSignature):
            return self.__error("Invalid purchase receipt", fatal=True)
        decryptionKey, decryptionIv = self.__factory.getDecryptionData(msgObj.Cookie)
        if not decryptionKey or not decryptionIv:
            return self.__error("Unexpected failure in getDecryptionData!", fatal=True)
        response = MessageData.GetMessageBuilder(ResultDecryptionKey)
        response["Cookie"].setData(msgObj.Cookie)
        response["key"].setData(decryptionKey)
        response["iv"].setData(decryptionIv)
        self.__state = self.STATE_FINISHED
        packetTrace(logger, response, "%s sending key %s, iv %s" % (msgObj.Cookie,
                                                                    binascii.hexlify(decryptionKey),
                                                                    binascii.hexlify(decryptionIv)))
        self.writeMsgAndClose(response)
        
    def __handleRerequest(self, prot, msg):
        msgObj = msg.data()
        self.__curState = self.__factory.getSessionState(msgObj.Cookie)
        if not self.__curState.state == self.STATE_FINISHED:
            return self.__error("Cannot re-request a key until the session is finished", fatal=False)
        self.__state = self.STATE_REREQUEST
        msgObj = msg.data()
        decryptionKey, decryptionIv = self.__factory.getDecryptionData(msgObj.Cookie)
        if not decryptionKey or not decryptionIv:
            return self.__error("No decryption key found", fatal=False)
        response = MessageData.GetMessageBuilder(ResultDecryptionKey)
        response["Cookie"].setData(msgObj.Cookie)
        response["key"].setData(decryptionKey)
        response["iv"].setData(decryptionIv)
        packetTrace(logger, response, "%s re-sending key %s, iv %s" % (msgObj.Cookie,
                                                                    binascii.hexlify(decryptionKey),
                                                                    binascii.hexlify(decryptionIv)))
        self.writeMsgAndClose(response)

class ServerStateContext(object):
    def __init__(self, key):
        self.cookie = key
        self.restoreStateSignal = None
        self.mobileCodeId = ""
        self.level = "BASIC"
        self.billingRate = 0
        self.extras = []
        self.paid = 0
        self.nextTimeout = time.time() + Server.DEFAULT_TIMEOUT_TO_START
        self.aesKey = None
        self.aesIv = None
        self.runMobilecodeHash = ""
        self.encryptedResult = None
        self.runtime = 0

class Server(Factory):
    MIB_BILLING_ACCOUNT = "BillingAccount"
    MIB_CODE_IN_PROCESS = "CodeInProcess"
    
    DEFAULT_TIMEOUT_TO_START = 5*60 # 5 minutes after opening a session to start code
    #DEFAULT_TIMEOUT_TO_RUN = 
    DEFAULT_TIMEOUT_TO_PURCHASE = 30*60 # 30 minutes after code completes to purchase
    DEFAULT_TIMEOUT_FOR_RECEIPT = 2*60*60 # 2 hours after completion to get results
    
    StatePod = ServerStateContext
    
    def __init__(self, accountName, bankCert, persistentDb):
        self.__accountName = accountName
        self.__bankCert = bankCert
        """self.__receiptDbFile = receiptDb
        self.__keyDbFile = keyDb
        self.__receiptDb = shelve.open(receiptDb, "c")
        self.__keyDb = shelve.open(keyDb,"c")"""
        self.__inprocessCode = set([])
        self.__connData = {}
        db = shelve.open(persistentDb,"c")
        for k in db.keys():
            self.__connData[k] = db[k]
        db.close()
        #self.__connDataPersistent = shelve.open(persistentDb, "c")
        self.__persistentDbFile = persistentDb
        self.__clearStaleKeys()
        rsaKey = RSA.importKey(bankCert.getPublicKeyBlob())
        self.__validater = PKCS1_v1_5.new(rsaKey)
        self.__mobileCodeIds = {}
        self.__codeHandlers = {"__default__":SimpleMobileCodeHandler()}
        
    def registerMobileCodeService(self, mobileCodeId, rate):
        if rate < 0:
            raise Exception("Rate must be positive")
        self.__mobileCodeIds[mobileCodeId] = ("BASIC", rate, [])
        
    def registerMobileCodeHandler(self, mechanism, handler):
        self.__codeHandlers[mechanism] = handler
        
    def execute(self, mobileCodeId, mobileCodeMechanism, code, saveKey, cookie):
        
        
    def createSessionContext(self, clientNonce, mobileCodeId):
        parameters = self.__mobileCodeIds.get(mobileCodeId, None)
        if not parameters:
            return None
        serverNonce = RANDOM_u64()
        maxtries = 10
        sessionKey = str(clientNonce)+str(serverNonce)
        while self.__connData.has_key(sessionKey):
            serverNonce = RANDOM_u64()
            sessionKey = str(clientNonce)+str(serverNonce)
            maxtries -= 1
            if maxtries == 0:
                return None
        pod = self.StatePod(sessionKey)
        pod.level, pod.billingRate, pod.extras = parameters
        self.__connData[sessionKey] = pod
        
        return pod
    
    def getSessionState(self, key):
        pod = self.__connData.get(key, None)
        return pod
    
    def closeSession(self, key):
        if self.__connData.has_key(key):
            del self.__connData[key]
        
    def __clearStaleKeys(self):
        staleList = set([])
        for key, pod in self.__connData.items():
            if pod.state in [ServerProtocol.STATE_UNINIT]:
                logger.info("Clearing state that is uninit. Cookie=%s" % pod.cookie)
                staleList.add(key)
            elif time.time() > pod.nextTimeout:
                logger.info("Clearing state that timed out (%s). Cookie=%s" % 
                            (str(pod.nextTimeout), pod.cookie))
                staleList.add(key)
        for k in staleList:
            logger.info("Closing session %s" % pod.cookie)
            self.closeSession(k)
        #self.__save()
        
    def __save(self):
        # incredibly inefficient. Haven't figured out a better solution yet.
        # could use the "writeback" or could come up with my own approach.
        self.__clearStaleKeys()
        db = shelve.open(self.__persistentDbFile, "w")
        db.clear()
        for k in self.__connData.keys():
            db[k] = self.__connData[k]
        db.close()
        
    def buildProtocol(self, addr):
        return ServerProtocol(self, addr, self.__accountName)
    
    def createMobileCodeRecord(self, searchKey, aesKey, aesIv, maxRuntime):
        statePod = self.__connData.get(searchKey,None)
        if not statePod:
            return False, "No such key"
        self.__inprocessCode.add(searchKey)
        statePod.aesKey = aesKey
        statePod.aesIv = aesIv
        statePod.nextTimeout = time.time() + maxRuntime
        self.__save()
        return True, ""
    
    def mobileCodeComplete(self, searchKey, encryptedResult):
        statePod = self.__connData.get(searchKey,None)
        if not statePod:
            return False, "No such key"
        if searchKey in self.__inprocessCode:
            self.__inprocessCode.remove(searchKey)
        statePod.nextTimeout = time.time() + self.DEFAULT_TIMEOUT_TO_PURCHASE
        statePod.state = ServerProtocol.STATE_PURCHASE
        statePod.encryptedResult = encryptedResult
        self.__save()
        return True, ""
    
    def validatePurchase(self, searchKey, receipt, receiptSignature):
        statePod = self.getSessionState(searchKey)
        if not statePod:
            return False, "Session has expired or never existed"
        if not self.__validater.verify(SHA.new(receipt), receiptSignature):
            return False, "Signature failed"
        ll = pickle.loads(receipt)
        if ll.memo(self.__accountName) != searchKey:
            return False, "Memo is not equal to clientNonce+serverNonce"
        statePod.paid += ll.getTransactionAmount(self.__accountName)
        if statePod.paid < statePod.billingRate:
            return False, "Insufficient purchase"
        statePod.nextTimeout = time.time() + self.DEFAULT_TIMEOUT_FOR_RECEIPT
        self.__save()
        return True, ""
    
    def getDecryptionData(self, searchKey):
        statePod = self.getSessionState(searchKey)
        if not statePod:
            return False, "Session has expired or never existed"
        key, iv = statePod.aesKey, statePod.aesIv
        logger.info("Consistency check: %s Produced key (%s) and iv (%s)" % (searchKey,
                                                                             binascii.hexlify(key), 
                                                                             binascii.hexlify(iv)))
        if len(key) != 16:
            raise Exception("Internal consistency error. Expected key of 16 but got %d" % len(key))
        if len(iv) != 16:
            raise Exception("Internal consistency error. Expected IV of 16, but got %d" % len(iv))
        return key, iv

USAGE = """
mobilecodeserver.Server <playground addr> <chaperone IP> <config file>
"""

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(USAGE)
    addr, ipAddr, configFilename = sys.argv[1:4]
    if not os.path.exists(configFilename):
        sys.exit("No such config file %s" % configFilename)
    configOptions = LoadOptions(configFilename)
    bankOptions = configOptions.getSection("mobilecodeserver.bankdata")
    cert = bankOptions["bank_cert_path"]
    accountName = bankOptions["account_name"]
    ipPort = 9090
    playgroundAddress = playground.network.common.PlaygroundAddress.FromString(addr)
    
    logctx = LoggingContext()
    logctx.nodeId = "mobile_code_server_"+addr
    #logctx.doPacketTracing = True
    playground.playgroundlog.startLogging(logctx)
    
    if not os.path.exists(cert):
        sys.exit("Could not locate cert file " + cert)
    with open(cert) as f:
        cert = X509Certificate.loadPEM(f.read())
    persistenceFile = "mc_server_data."+playgroundAddress.toString()
    server = Server(accountName, cert, persistenceFile)
    # hard coded... move to config file
    
    serviceOptions = configOptions.getSection("mobilecodeserver.servicedata")
    for serviceKey in serviceOptions.keys(topLevelOnly=True):
        serviceName = serviceOptions[serviceKey]["name"]
        serviceCharge = serviceOptions[serviceKey]["charge"]
        serviceCharge = int(serviceCharge)
        print "Registering %s %d" % (serviceName, serviceCharge)
        server.registerMobileCodeService(serviceName, serviceCharge)
    #server.registerMobileCodeService("Parallel TSP", 50)
    
    networkOptions = configOptions.getSection("mobilecodeserver.networkdata")
    connectionType = networkOptions.get("connectionType", "RAW")
    client = playground.network.client.ClientBase(playgroundAddress)
    client.listen(server, MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT, 
                  connectionType=connectionType)
    client.connectToChaperone(ipAddr, ipPort)