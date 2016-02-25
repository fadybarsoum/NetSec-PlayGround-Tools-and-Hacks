'''
Created on Apr 2, 2014

@author: sethjn
'''
import playground
from playground.crypto import X509Certificate
from playground.network.common import Packet, MIBAddressMixin
from playground.network.message import definitions
from playground.network.message import MessageData
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

from playground.network.client.ClientMessageHandlers import RunMobileCodeHandler, MobileCodeCallbackHandler

from playground.playgroundlog import packetTrace, logging, LoggingContext
from binhex import binhex
logger = logging.getLogger(__file__)

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

class ServerProtocol(playground.network.common.SimpleMessageHandlingProtocol):
    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_FINISHED = "Finished"
    STATE_PURCHASE = "Purchase decryption key"
    STATE_REREQUEST = "Rerequest decryption key"
    STATE_RUNNING = "Running code"
    STATE_ERROR = "Error"

    CODE_TIMEOUT = 1*60*60 # one hour maximum run
    
    #SANDBOX_CONTROLLER = os.path.join(LOCATION_OF_PLAYGROUND, "extras", "sandbox", "IOEnabledSandbox.py")
    
    MIB_PEER_ADDRESS = "PeerAddress"
    MIB_STATE = "State"
    MIB_COOKIE = "Cookie"
    MIB_CODE_STRING = "CodeString"
    
    def __init__(self, factory, addr, accountName):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__factory = factory
        self.__accountName = accountName
        self.__codeString = None
        self.__curState = None
        
        self.registerMessageHandler(SessionRunMobileCode, self.__handleRunMobileCode)
        self.registerMessageHandler(OpenSession, self.__handleOpenSession)
        self.registerMessageHandler(PurchaseDecryptionKey, self.__handlePurchase)
        self.registerMessageHandler(RerequestDecryptionKey, self.__handleRerequest)
        self.registerMessageHandler(CheckMobileCodeResult, self.__handleCheckMobileCodeResult)
        
    """def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_PEER_ADDRESS, self.__handleMib)
            self.registerLocalMIB(self.MIB_STATE, self.__handleMib)
            self.registerLocalMIB(self.MIB_COOKIE, self.__handleMib)
            self.registerLocalMIB(self.MIB_CODE_STRING, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_PEER_ADDRESS):
            if self.transport:
                return [str(self.transport.getPeer())]
            return ["<Not Connected>"]
        elif mib.endswith(self.MIB_STATE):
            return [self.]
        elif mib.endswith(self.MIB_COOKIE):
            return ["%d-%d" % (self.__connData["ClientNonce"], self.__connData["ServerNonce"])]
        elif mib.endswith(self.MIB_CODE_STRING):
            if self.__codeString: return [self.__codeString]
            return ["<Not Set Yet>"]
        return ""
        """
        
    def writeMsgAndClose(self, msg):
        self.transport.writeMessage(msg)
        self.callLater(.1, self.transport.loseConnection)
        
    def connectionMade(self):
        playground.network.common.SimpleMessageHandlingProtocol.connectionMade(self)
        #self.__loadMibs()

    def __error(self, errMsg, **kargs):
        logger.error("MobileCodeServer had an error %s" % errMsg)
        if kargs.has_key("fatal"):
            fatal = kargs["fatal"]
            del kargs["fatal"]
        else:
            fatal = True
        if not self.__curState or self.__curState.state == self.STATE_ERROR:
            if self.transport:
                self.transport.loseConnection()
            return None
        
        if self.__curState.state == self.STATE_UNINIT:
            response = MessageData.GetMessageBuilder(SessionOpenFailure)
            response["ClientNonce"].setData(kargs.get("ClientNonce",0))
            self.__curState.state = self.STATE_ERROR
        else:
            if self.__curState.state == self.STATE_OPEN:
                response = MessageData.GetMessageBuilder(RunMobileCodeFailure)
            elif self.__curState.state == self.STATE_PURCHASE or self.__state == self.STATE_REREQUEST:
                response = MessageData.GetMessageBuilder(AcquireDecryptionKeyFailure)
            else:
                response = MessageData.GetMessageBuilder(GeneralFailure)
            response["Cookie"].setData(self.__curState.cookie)
        for karg in kargs.keys():
            response[karg].setData(kargs[karg])
        response["ErrorMessage"].setData(errMsg)
        if fatal: self.__state = self.STATE_ERROR
        
        packetTrace(logger, response, "Had an error %s" % errMsg)
        self.writeMsgAndClose(response)
        return None
        
    def __handleOpenSession(self, protocol, msg):
        msgObj = msg.data()
        if msgObj.Authenticated:
            return self.__error("Authenticated operation not yet supported", 
                                fatal=True, ClientNonce=msgObj.ClientNonce)
        self.__curState = self.__factory.getNewSessionState(msgObj.ClientNonce, msgObj.MobileCodeId)
        if not self.__curState:
            logger.info("Unwilling to serve this mobile code operation (%s). Refused to create state." % msgObj.MobileCodeId) 
            response = MessageData.GetMessageBuilder(SessionOpenFailure)
            response["ClientNonce"].setData(msgObj.ClientNonce)
            response["ErrorMessage"].setData("Unwilling to serve mobile code operation %s" % msgObj.MobileCodeId)
            self.writeMsgAndClose(response)
            return
        self.__curState.state = self.STATE_OPEN
        response = MessageData.GetMessageBuilder(SessionOpen)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["Cookie"].setData(self.__curState.cookie)
        response["ServiceLevel"].setData(self.__curState.level)
        response["BillingRate"].setData(self.__curState.billingRate)
        response["Account"].setData(self.__accountName)
        response["ServiceExtras"].setData(self.__curState.extras)
        
        packetTrace(logger, response, "Received opensession message from %s. State is now open" % str(self.transport.getPeer()))
        self.writeMsgAndClose(response)
        
    def __codeHandlerWrapper(self, realHandler, codeUnit):
        self.__codeString = codeUnit.getCodeString()
        return realHandler(codeUnit)
        
    def __handleRunMobileCode(self, prot, msg):
        msgObj = msg.data()
        self.__curState = self.__factory.getSessionState(msgObj.Cookie)
        if not self.__curState or not self.__curState.state == self.STATE_OPEN:
            curState = self.__curState and self.__curState.state or "<NO STATE>"
            return self.__error("Invalid command. Cannot run mobile code unless session open (%s)"%curState, 
                                fatal=True)
        
        logger.info("State found for cookie %s. State=%s" % (msgObj.Cookie, self.__curState.state))
        if msgObj.MaxRuntime > self.CODE_TIMEOUT:
            response = MessageData.GetMessageBuilder(RunMobileCodeAck)
            response["Cookie"].setData(self.__curState.cookie)
            response["MobileCodeAccepted"].setData(False)
            response["Message"].setData("Max Run Time parameter is too long.")
            self.writeMsgAndClose(response)
        
        rawRunMobileCodeMsg = msgObj.RunMobileCodePacket
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
        runMobileCodeHandler = RunMobileCodeHandler(self)#, codeHandler)
        runMobileCodeHandler(wrappedProtocol, MessageData.Deserialize(rawRunMobileCodeMsg)[0])
        self.__curState.state = self.STATE_RUNNING
        response = MessageData.GetMessageBuilder(RunMobileCodeAck)
        response["Cookie"].setData(self.__curState.cookie)
        response["MobileCodeAccepted"].setData(True)
        self.writeMsgAndClose(response)
        
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

class ServerStatePod(object):
    def __init__(self, key):
        self.cookie = key
        self.state = ServerProtocol.STATE_UNINIT
        self.mobileCodeId = ""
        self.level = "BASIC"
        self.billingRate = 0
        self.extras = []
        self.paid = 0
        self.nextTimeout = time.time() + Server.DEFAULT_TIMEOUT_TO_START
        self.aesKey = None
        self.aesIv = None
        self.encryptedResult = None

class Server(playground.network.client.ClientApplicationServer.ClientApplicationServer):
    MIB_BILLING_ACCOUNT = "BillingAccount"
    MIB_CODE_IN_PROCESS = "CodeInProcess"
    
    DEFAULT_TIMEOUT_TO_START = 5*60 # 5 minutes after opening a session to start code
    #DEFAULT_TIMEOUT_TO_RUN = 
    DEFAULT_TIMEOUT_TO_PURCHASE = 30*60 # 30 minutes after code completes to purchase
    DEFAULT_TIMEOUT_FOR_RECEIPT = 2*60*60 # 2 hours after completion to get results
    
    StatePod = ServerStatePod
    
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
        #self.__connDataPersistent = shelve.open(persistentDb, "c")
        self.__persistentDbFile = persistentDb
        self.__clearStaleKeys()
        rsaKey = RSA.importKey(bankCert.getPublicKeyBlob())
        self.__validater = PKCS1_v1_5.new(rsaKey)
        self.__mobileCodeIds = {}
        
    def registerMobileCodeService(self, mobileCodeId, rate):
        if rate < 0:
            raise Exception("Rate must be positive")
        self.__mobileCodeIds[mobileCodeId] = ("BASIC", rate, [])
        
    def getNewSessionState(self, clientNonce, mobileCodeId):
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
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_BILLING_ACCOUNT, self.__handleMib)
            self.registerLocalMIB(self.MIB_CODE_IN_PROCESS, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_BILLING_ACCOUNT):
            return [self.__accountName]
        elif mib.endswith(self.MIB_CODE_IN_PROCESS):
            return self.__inprocessCode
        return []
        
    def configureMIBAddress(self, *args, **kargs):
        MIBAddressMixin.configureMIBAddress(self, *args, **kargs)
        self.__loadMibs()
        
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
mobilecodeserver.Server <accountName> <bank cert> <playground addr> <playground IP server> <playground IP server port>
"""

if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit(USAGE)
    accountName, cert, addr, ipAddr, ipPort = sys.argv[1:6]
    playgroundAddress = playground.network.common.PlaygroundAddress.FromString(addr)
    
    logctx = LoggingContext()
    logctx.nodeId = "mobile_code_server_"+addr
    logctx.doPacketTracing = True
    playground.playgroundlog.startLogging(logctx)
    
    ipPort = int(ipPort)
    if not os.path.exists(cert):
        sys.exit("Could not locate cert file " + cert)
    with open(cert) as f:
        cert = X509Certificate.loadPEM(f.read())
    persistenceFile = "mc_server_data."+playgroundAddress.toString()
    server = Server(accountName, cert, persistenceFile)
    # hard coded... move to config file
    server.registerMobileCodeService("Parallel TSP", 50)
    client = playground.network.client.ClientBase(playgroundAddress)
    client.listen(server, MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT, connectionType="RAW")
    client.connectToChaperone(ipAddr, ipPort)