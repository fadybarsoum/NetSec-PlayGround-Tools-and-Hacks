'''
Created on Apr 2, 2014

@author: sethjn
'''
from twisted.internet import reactor

import playground
#import playground.extras.sandbox.SandboxCodeunitAdapter
from playground.crypto import X509Certificate, Pkcs7Padding
from playground.network.common import Packet, MIBAddressMixin, OneshotTimer
from playground.network.message import MessageData
from playground.network.message import definitions
from ServiceMessages import OpenSession, SessionOpen, SessionOpenFailure, EncryptedMobileCodeResult
from ServiceMessages import PurchaseDecryptionKey, RunMobileCodeFailure, AcquireDecryptionKeyFailure, Heartbeat
from ServiceMessages import RerequestDecryptionKey, GeneralFailure, ResultDecryptionKey, SessionRunMobileCode

import random, time, math, os, dbm, pickle, sys, binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from playground.network.client.ClientMessageHandlers import RunMobileCodeHandler, MobileCodeCallbackHandler

from apps.bank.BankCore import LedgerLine
from apps.bank.OnlineBank import PlaygroundOnlineBankClient, BANK_FIXED_PLAYGROUND_ADDR, BANK_FIXED_PLAYGROUND_PORT

from playground.network.message import definitions

from playground.playgroundlog import packetTrace, logging, protocolLog
logger = logging.getLogger(__file__)

from playground.config import GlobalPlaygroundConfigData
configData = GlobalPlaygroundConfigData.getConfig(__name__)

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

LOCATION_OF_PLAYGROUND = os.path.dirname(playground.__file__)

class BasicClientProtocol(playground.network.common.SimpleMessageHandlingProtocol, playground.network.common.StackingProtocolMixin):
    STATE_UNINIT = "Uninitialized"
    STATE_OPENING = "Opening Session"
    STATE_WAITING_FOR_CODE = "Waiting for code execution"
    STATE_PURCHASING = "Purchasing"
    STATE_WAITING_FOR_DECRYPTION_KEY = "Waiting for decryption key"
    STATE_FINISHED = "FINISHED"
    STATE_ERROR = "Error"
    
    HB_UNSET = "Heartbeat Not Set"
    HB_WAITING = "Heartbeat Waiting"
    
    MIB_CURRENT_STATE = "CurrentState"
    
    def __init__(self, factory, addr, specialMode=None):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__factory = factory
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0}
        self.__specialMode = specialMode
        self.__mode = self.STATE_UNINIT
        self.__heartbeatMode = self.HB_UNSET
        self.registerMessageHandler(SessionOpen, self.__handleSessionOpen)
        self.registerMessageHandler(SessionOpenFailure, self.__handleSessionOpenFailure)
        self.registerMessageHandler(EncryptedMobileCodeResult, self.__handleEncryptedResult)
        self.registerMessageHandler(ResultDecryptionKey, self.__handleDecryptionKeyResult)
        self.registerMessageHandler(AcquireDecryptionKeyFailure, self.__handleDecryptionKeyFailure)
        self.registerMessageHandler(RunMobileCodeFailure, self.__handleMobileCodeFailure)
        self.registerMessageHandler(GeneralFailure, self.__handleFailure)
        self.registerMessageHandler(Heartbeat, self.__handleHeartbeat)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_CURRENT_STATE, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_CURRENT_STATE):
            return [self.__mode]
        return []
        
    def state(self): return self.__mode
        
    def __error(self, msg):
        if self.__mode != self.STATE_ERROR:
            self.__mode = self.STATE_ERROR
            self.reportError(msg)
            # this call later prevents problems if we've just had the connection established
            self.callLater(0,lambda: self.transport and self.transport.loseConnection())
        
    def __setCookie(self, msg):
        msg["ClientNonce"].setData(self.__connData["ClientNonce"])
        msg["ServerNonce"].setData(self.__connData["ServerNonce"])
        
    def sendHeartbeat(self, timeout=30):
        if not self.transport:
            return False
        if self.__heartbeatMode == self.HB_UNSET:
            msg = MessageData.GetMessageBuilder(Heartbeat)
            msg["Response"].setData(False)
            self.callLater(timeout, self.__checkHeartbeat)
            self.__heartbeatMode = self.HB_WAITING
            self.transport.writeMessage(msg)
            return True
        elif self.__heartbeatMode == self.HB_WAITING:
            return False
        
    def __handleHeartbeat(self, prot, msg):
        protocolLog(self, logger.info, "Heartbeat received.")
        self.__heartbeatMode = self.HB_UNSET
        
    def __checkHeartbeat(self):
        if self.__heartbeatMode == self.HB_WAITING:
            return self.__error("Heartbeat Timeout.")
        
    def connectionMade(self):
        protocolLog(self, logger.info, "Mobile Code Connection made to %s" % (str(self.transport.getPeer()),))
        playground.network.common.SimpleMessageHandlingProtocol.connectionMade(self)
        self.__loadMibs()
        if not self.__specialMode:
            self.__mode = self.STATE_OPENING
            request = MessageData.GetMessageBuilder(OpenSession)
            self.__connData["ClientNonce"] = RANDOM_u64()
            request["ClientNonce"].setData(self.__connData["ClientNonce"])
            request["Authenticated"].setData(False)
            
            protocolLog(self, logger.info, "Sending Open Session with %s" % (str(self.__connData["ClientNonce"]),))
            packetTrace(logger, request, "Starting session with %s (CN: %d)" % (str(self.transport.getPeer()),
                                                                                self.__connData["ClientNonce"]))
            self.transport.writeMessage(request)
            return
        mode, clientNonce, serverNonce = self.__specialMode
        self.__connData["ClientNonce"] = clientNonce
        self.__connData["ServerNonce"] = serverNonce
        if mode == "PURCHASE":
            self.__mode = self.STATE_PURCHASING
            success, errMsg = self.__factory.payForDecryptionKey(clientNonce, serverNonce,
                                                                 self.__purchaseComplete)
            if not success:
                return self.__error("Could not pay for decryption key: " + errMsg)
            return
        elif mode == "REREQUEST":
            self.__mode = self.STATE_WAITING_FOR_DECRYPTION_KEY
            request = MessageData.GetMessageBuilder(RerequestDecryptionKey)
            self.__loadCookie(request)
            
            packetTrace(logger, request, "Special mode: rerequest. Cookie = %d/%d" % (self.__connData["ClientNonce"],
                                                                                      self.__connData["ServerNonce"]))
            self.transport.writeMessage(request)
            return
        else:
            return self.__error("Unknown special mode %s" % mode)
        
    def connectionLost(self, reason=None):
        playground.network.common.SimpleMessageHandlingProtocol.connectionLost(self, reason)
        protocolLog(self, logger.info, "Connection lost: %s. Current state: %s" % (str(reason), self.__mode))
        #self.__error("Connection Lost: " + str(reason))
        if self.__mode != self.STATE_ERROR:
            self.__mode = self.STATE_FINISHED
        
    def __handleSessionOpen(self, prot, msg):
        protocolLog(self, logger.info, "Got Session Open from %s" % (str(self.transport.getPeer()),))
        packetTrace(logger, msg, "Session Open msg. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        if not self.__mode == self.STATE_OPENING:
            return self.__error("Unexpected session open. State is: %s" % self.__mode)
        msgObj = msg.data()
        if not self.__connData["ClientNonce"] == msgObj.ClientNonce:
            return self.__error("Invalid connection data (ClientNonce)")
        success, data = self.__factory.getCodeForConnection(msgObj.ClientNonce,
                                                                             msgObj.ServerNonce,
                                                                             self.transport.getPeer(),
                                                                             msgObj.BillingTimeSliceSeconds,
                                                                             msgObj.BillingRatePerSlice)
        if not success:
            return self.__error("Could not get code for %s: %s" %(self.transport.getPeer(),data))
        codeString, codeID, maxRuntime = data
        if not codeString or not codeID:
            self.transport.loseConnection()
            return
            #return self.__error("Decided not to proceed with cost")
        if configData.get("SafeCodeWrapper",None) != None:
            codeString = __import__(configData.get("SafeCodeWrapper")).makeCodeSafe(self.transport.getPeer(), codeString)
        self.__connData["ServerNonce"] = msgObj.ServerNonce
        protocolLog(self, logger.info, "ServerNonce is %d" % (msgObj.ServerNonce,))
        
        request = MessageData.GetMessageBuilder(definitions.playground.base.RunMobileCode)
        request["ID"].setData(codeID)
        request["pythonCode"].setData(codeString)
        request["mechanism"].setData("pickle")
        serializedMsg = Packet.SerializeMessage(request)
        self.__runningCodeHash = SHA.new(serializedMsg).digest()
        wrapMsg = MessageData.GetMessageBuilder(SessionRunMobileCode)
        self.__setCookie(wrapMsg)
        wrapMsg["RunMobileCodePacket"].setData(serializedMsg)
        wrapMsg["MaxRuntime"].setData(maxRuntime)
        
        self.__mode = self.STATE_WAITING_FOR_CODE
        
        packetTrace(logger, wrapMsg, "Sending wrapped SessionRunMobileCode Cookie = %d/%d" % (self.__connData["ClientNonce"],
                                                                                      self.__connData["ServerNonce"]))
        self.transport.writeMessage(wrapMsg)
        
    def __handleSessionOpenFailure(self, prot, msg):
        packetTrace(logger, msg, "Session Open failed. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleDecryptionKeyFailure(self, prot, msg):
        packetTrace(logger, msg, "Decryption key failed. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleMobileCodeFailure(self, prot, msg):
        packetTrace(logger, msg, "Mobile Code Failed. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
    
    def __handleFailure(self, prot, msg):
        packetTrace(logger, msg, "General failure. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        msgObj = msg.data()
        return self.__error(msgObj.ErrorMessage)
        
    def __handleEncryptedResult(self, prot, msg):
        msgObj = msg.data()
        protocolLog(self, logger.info, "Got Encrypted Result of len %d from %s" % (len(msgObj.EncryptedMobileCodeResultPacket),
                                                                str(self.transport.getPeer()),))
        packetTrace(logger, msg, "Encrypted result. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        if not self.__mode == self.STATE_WAITING_FOR_CODE:
            return self.__error("Unexpected code result. State is: %s" % self.__mode)
        
        if not self.__connData["ClientNonce"] == msgObj.ClientNonce:
            return self.__error("Invalid connection data (ClientNonce)")
        if not self.__connData["ServerNonce"] == msgObj.ServerNonce:
            return self.__error("Invalid connection data (ServerNonce)")
        if self.__runningCodeHash != msgObj.RunMobileCodeHash:
            return self.__error("Invalid code hash")
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
        self.transport.writeMessage(request)
        
    def __handleDecryptionKeyResult(self, prot, msg):
        packetTrace(logger, msg, "Decryption key. State: %s Cookie = %d/%d" % (self.__mode,
                                                                                 self.__connData["ClientNonce"],
                                                                                 self.__connData["ServerNonce"]))
        if self.__mode != self.STATE_WAITING_FOR_DECRYPTION_KEY:
            return self.__error("Unexpected decryption key result. State is %s" % self.__mode)
        msgObj = msg.data()
        if not self.__connData["ClientNonce"] == msgObj.ClientNonce:
            return self.__error("Invalid connection data (ClientNonce)")
        if not self.__connData["ServerNonce"] == msgObj.ServerNonce:
            return self.__error("Invalid connection data (ServerNonce)")
        protocolLog(self, logger.info, "Key=%s, iv=%s" % (binascii.hexlify(msgObj.key), binascii.hexlify(msgObj.iv)))
        protocolLog(self, logger.info, "(2) Key=%s, iv=%s" % (binascii.hexlify(msg["key"].data()), binascii.hexlify(msg["iv"].data())))
        success, msg = self.__factory.decryptResult(msgObj.ClientNonce, msgObj.ServerNonce, msgObj.key, msgObj.iv)
        if not success:
            return self.__error("Decrypt failed: " + msg)
        self.__mode = self.STATE_FINISHED
        protocolLog(self, logger.info, "Call lose connection on %s" % str(self.transport))
        self.transport.loseConnection()
        
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
    def predictCostForExecution(self, sliceSize, sliceCost):
        slices = int(math.ceil(self.averageTimePerExecution()/sliceSize))
        return slices * sliceCost
        
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
    
    def __init__(self, addr, codeId, sliceTime, sliceCost, maxRuntime):
        self.__addr = addr
        self.__codeID = codeId
        self.__sliceTime = sliceTime
        self.__sliceCost = sliceCost
        self.__maxRuntime = maxRuntime
        self.__encryptedResult = None
        self.__account = None
        self.__runtime = None
        self.__cost = None
        self.__start = time.time()
        
    def codeId(self):
        return self.__codeID
    
    def addr(self):
        return self.__addr
    
    def setEncryptedResult(self, res):
        self.__encryptedResult = res
        
    def encryptedResult(self):
        return self.__encryptedResult
    
    def validateReportedRuntime(self, runtime):
        endTime = time.time()
        myTime = endTime - self.__start
        # The times can be very close and the other side always adds 1 second
        # because it won't allow a "zero" time. Adjust accordingly so we don't
        # accidentally reject a good time.
        myTime = math.ceil(myTime)+1
        return  runtime <= myTime
        
    def setPurchaseParameters(self, account, runtime, cost):
        self.__account = account
        self.__runtime = runtime
        self.__cost = cost
        
    def payableAccount(self):
        return self.__account
    
    def costToPurchaseKey(self):
        return self.__cost
    
    def actualRuntime(self):
        return self.__runtime
        
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
    MAX_RUN_TIME = 5*60
    MAX_AFTER_PURCHASE_FAILURES = 2
    MAX_COST_PER_SECOND = .02
    
    MIB_STATS = "ExecutionStats"
    MIB_BLACK_LIST_FAMILIES = "BlackListFamilies"
    MIB_RECENT_HISTORY = "RecentHistory"
    
    def __init__(self, playground, bankFactory):
        self.__playground = playground
        self.__bankFactory = bankFactory
        self.__specialMode = None
        self.__addrStats = {}
        self.__cookies = {}
        self.__maxRuntime = self.MAX_RUN_TIME
        self.__openProts = {}
        self.__blackListFamily = {}
        self.__recentHistory = []
        #self.__parallelControl = parallelControl
        
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
        
    def __handleMib(self, mib, args):
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
        return []
        
    def callLater(self, delay, callBack):
        reactor.callLater(delay, callBack)

    def peersReceived(self, peerList):
        logger.info("Received addresses for running mobile code")
        #print "got addresses", peerList
        #self.mcount = len(peerList)
        #instruction = playground.network.common.DefaultPlaygroundMobileCodeUnit(getRemotePiCodeString(self.n/(1.0*self.mcount)))
        for peerString in peerList:
            if self.__openProts.has_key(peerString):
                logger.info("Sending heartbeat to " + peerString)
                self.__openProts[peerString].sendHeartbeat()
                continue
            peerFamily = ".".join(peerString.split(".")[:2])
            if len(self.__blackListFamily.get(peerFamily, [])) > 4:
                self.__historyEvent("Rejecting %s because family %s is blacklisted" % (peerString, peerFamily))
                continue
            logger.info("Connecting to " + peerString)
            #print "Sending to peer", peerString
            peer = playground.network.common.PlaygroundAddress.FromString(peerString)
            # hardcoded port for now
            srcPort, prot = self.__playground.connect(self, peer, 800, connectionType="RAW")
            prot = prot.getApplicationLayer()
            #prot.sendPythonCode(instruction, self)
            self.__openProts[peerString] = prot
        self.callLater(5, self.__checkProts)
        
    def __checkProts(self):
        checkProtKeys = self.__openProts.keys()
        getMorePeers = False
        for protocolAddr in checkProtKeys:
            protocol = self.__openProts[protocolAddr]
            if protocol.transport == None or protocol.state() in [BasicClientProtocol.STATE_ERROR, BasicClientProtocol.STATE_FINISHED]:
                logger.info("Peer %s is finished. Removing from protocol state" % protocolAddr)
                del self.__openProts[protocolAddr]
                getMorePeers = True
        if getMorePeers:
            self.autoDiscover()
        else:
            self.callLater(5, self.__checkProts)
        
    def autoDiscover(self):
        if not self.__parallelControl.finished():
            self.__playground.getPeers(self.peersReceived)
        else:
            # nothing to do here. We're done
            self.__finishedCallback()
        
    def runParallel(self, parallelControl, finishedCallback):
        #if isinstance(parallelControl, MIBAddressMixin):
        #    self.configureMIBAddress("BasicMobileCode", parallelControl, parallelControl.MIBRegistrar())
        self.__parallelControl = parallelControl
        self.__finishedCallback = finishedCallback
        self.autoDiscover()
            
    
    def buildProtocol(self, addr):
        prot = BasicClientProtocol(self, addr, self.__specialMode)
        return prot
    
    def getAddrFamily(self, addr):
        addrParts = str(addr).split(".")
        family = ".".join(addrParts[:2])
        return family
    
    def blacklistAddr(self, addr):
        self.__addrStats[addr].setBlacklist()
        family = self.getAddrFamily(addr)
        if not self.__blackListFamily.has_key(family):
            self.__blackListFamily[family] = set([])
        self.__blackListFamily[family].add(str(addr))
        t = OneshotTimer(lambda: self.removeAddrFromBlacklist(addr))
        t.run(60*60*2) # Remove from blacklist in 2 hours
        
    def removeAddrFromBlacklist(self, addr):
        self.__addrStats[addr].setBlacklist(False)
        family = self.getAddrFamily(addr)
        self.__blackListFamily[family].remove(str(addr))
    
    def getCodeForConnection(self, ClientNonce, ServerNonce, addr, BillingTimeSliceSeconds, BillingRatePerSlice):
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
        return True, (codeStr, codeId, self.__maxRuntime)
    

    def registerEncryptedResult(self, ClientNonce, ServerNonce, EncryptedMobileCodeResultPacket):
        cookie = str(ClientNonce) + str(ServerNonce)
        if not self.__cookies.has_key(cookie):
            return False, "No such cookie"
        data = self.__cookies[cookie]
        if data.encryptedResult():
            return False, "Already have a result"
        data.setEncryptedResult(EncryptedMobileCodeResultPacket)
        return True, ""
    
    def setPurchaseParameters(self, ClientNonce, ServerNonce, Account, Runtime, Cost):
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
    
    def payForDecryptionKey(self, ClientNonce, ServerNonce, callback):
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
    
    def __startPurchase(self, addr, account, amount, memo, callback):
        srcPort, bankProtocolStack = self.__playground.connect(self.__bankFactory,
                                                              BANK_FIXED_PLAYGROUND_ADDR, 
                                                              BANK_FIXED_PLAYGROUND_PORT,
                                                              connectionType="RAW")
        bankProtocol = bankProtocolStack.getApplicationLayer()
        logger.info("Logging into bank for %s transfer for work done by %s" % (str(memo), str(addr)))
        d = bankProtocol.waitForConnection()
        d.addCallback(lambda result: self.__startLogin(bankProtocol, addr, account, amount, memo, callback))
        d.addErrback(lambda failure: self.__loginFailed(bankProtocol, addr, callback, failure))
        
    def __startLogin(self, bankProtocol, addr, account, amount, memo, callback):
        d = bankProtocol.loginToServer()
        d.addCallback(lambda result: self.__loginComplete(bankProtocol, addr, account, amount, memo, callback))
        d.addErrback(lambda failure: self.__loginFailed(bankProtocol, addr, callback, failure))
        
    def __loginComplete(self, bankProtocol, addr, account, amount, memo, finalCallback):
        self.__historyEvent("Logged in. Starting transfer from my account to %s (addr :%s, amount: %d, memo: %s" % (account, addr, amount, memo))
        d = bankProtocol.transfer(account, amount, memo)
        d.addCallback(lambda result: self.__transferSuccessful(bankProtocol, addr, result, finalCallback))
        d.addErrback(lambda failure: self.__transferFailed(bankProtocol, finalCallback, failure))
        
    def __loginFailed(self, bankProtocol, addr, finalCallback, failure):
        bankProtocol.close()
        logger.error("Login to bank failed: " + str(failure))
        finalCallback(None, None)
        return failure
        
    def __transferSuccessful(self, bankProtocol, addr, result, finalCallback):
        bankProtocol.close()
        stats = self.__addrStats[addr]
        stats.recordPurchase()
        logger.info("Transfer for code execution from %s successful. Handing off receipt (failures: %d)" % (addr, stats.failures()))
        receipt, receiptSignature = result
        finalCallback(receipt, receiptSignature)
        
    def __transferFailed(self, bankProtocol, finalCallback, failure):
        bankProtocol.close()
        logger.error("Bank transfer failed: " + str(failure))
        finalCallback(None, None)
        return failure
        
    def decryptResult(self, ClientNonce, ServerNonce, key, iv):
        cookie = str(ClientNonce) + str(ServerNonce)
        if not self.__cookies.has_key(cookie):
            return False, "No such cookie"
        data = self.__cookies[cookie]
        addrStats = self.__addrStats[data.addr()]
        encryptedData = data.encryptedResult()
        if not encryptedData:
            return False, "No encrypted data to decrypt"
        if len(key) != 16:
            logger.info("Setting %s blacklisted for invalid key (len %d)" % (data.addr(), len(key)))
            #addrStats.setBlacklist()
            self.blacklistAddr(data.addr())
            return False, "Invalid Key Length"
        if len(iv) != 16:
            logger.info("Setting %s blacklisted for invalid iv (len %d)" % (data.addr(), len(iv)))
            #addrStats.setBlacklist()
            self.blacklistAddr(data.addr())
            return False, "Invalid IV Length"
        decrypter = AES.new(key, mode=AES.MODE_CBC, IV=iv)
        plaintext = decrypter.decrypt(encryptedData)
        unpaddedData = Pkcs7Padding(AES.block_size).unpadData(plaintext)
        try:
            mobileCodeResultPacket = Packet.DeserializeMessage(unpaddedData)[0]
        except Exception, e:
            addrStats.update(data.actualRuntime(), data.costToPurchaseKey(),failed=True)
            return False, "Could not restore data: " + str(e)
        mobileCodeResultObj = mobileCodeResultPacket.data()
        picklePart = (mobileCodeResultObj.success and mobileCodeResultObj.resultPickled or mobileCodeResultObj.exceptionPickled)
        success, errMsg = self.__parallelControl.pickleBack(data.codeId(), mobileCodeResultObj.success, picklePart)
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
        self.__historyEvent("Updating runtime stats for %s. Runime: %d, cost: %d, success: %s" % (data.addr(),
                                                                                   data.actualRuntime(), 
                                                                                   data.costToPurchaseKey(), 
                                                                                   str(success)))
        addrStats.update(data.actualRuntime(), data.costToPurchaseKey(), failed=(not success))
        if success:
            return True, ""
        else:
            return False, "Code result or exception not accepted for addr %s: %s" % (str(data.addr()), errMsg)


