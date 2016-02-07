'''
Created on Apr 2, 2014

@author: sethjn
'''
import playground
from playground.crypto import X509Certificate
from playground.network.common import Packet, MIBAddressMixin
from playground.network.message import MessageData
#from playground.network.message import definitions
from ServiceMessages import OpenSession, SessionOpen, SessionOpenFailure, EncryptedMobileCodeResult
from ServiceMessages import PurchaseDecryptionKey, RunMobileCodeFailure, AcquireDecryptionKeyFailure, Heartbeat
from ServiceMessages import RerequestDecryptionKey, GeneralFailure, ResultDecryptionKey, SessionRunMobileCode

import random, time, math, os, shelve, pickle, sys, binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from playground.network.client.ClientMessageHandlers import RunMobileCodeHandler, MobileCodeCallbackHandler

from playground.playgroundlog import packetTrace, logging, LoggingContext
logger = logging.getLogger(__file__)

from apps.bank.BankCore import LedgerLine

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

LOCATION_OF_PLAYGROUND = os.path.dirname(playground.__file__)

MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT = 800

class CodeExecutionContext(object):
    def __init__(self):
        self.startTime = None
        self.clientNonce = None
        self.serverNonce = None
        self.runMobileCodeHash = None
        self.slice = None
        self.rate = None
        self.account = None
        self.finishCallback = None
        
class WrapMobileCodeResultProtocol(object):
    def __init__(self, transport):
        self.transport = transport

class WrapMobileCodeResultTransport(object):
    def __init__(self, transport, aesKey, aesIV, ctx):
        self.__key = aesKey
        self.__iv = aesIV
        self.__transport = transport
        self.__ctx = ctx
        
    def write(self, data):
        endTime = time.time()
        runTimeInSeconds = int(endTime-self.__ctx.startTime)
        runTimeInSeconds += 1
        logger.info("Finished execution of code in %f seconds" % runTimeInSeconds)
        encrypter = AES.new(self.__key, mode=AES.MODE_CBC, IV=self.__iv)
        padder = playground.crypto.Pkcs7Padding(AES.block_size)
        encrypted = encrypter.encrypt(padder.padData(data))
        response = MessageData.GetMessageBuilder(EncryptedMobileCodeResult)
        response["ClientNonce"].setData(self.__ctx.clientNonce)
        response["ServerNonce"].setData(self.__ctx.serverNonce)
        response["RunTime"].setData(runTimeInSeconds)
        response["RunMobileCodeHash"].setData(self.__ctx.runMobileCodeHash)
        billingSlices = int(math.ceil(float(runTimeInSeconds)/self.__ctx.slice))
        cost = billingSlices * self.__ctx.rate
        logger.info("%d seconds is %d billing slices. At %d bit points per slice, cost is %d" % (runTimeInSeconds,
                                                                                                 billingSlices,
                                                                                                 self.__ctx.rate,
                                                                                                 cost))
        response["Cost"].setData(cost)
        response["Account"].setData(self.__ctx.account)
        response["EncryptedMobileCodeResultPacket"].setData(encrypted)
        self.__ctx.finishCallback(self.__ctx, cost)
        
        packetTrace(logger, response, "Sending encrypted mobile code result")
        self.__transport.writeMessage(response)
        
    def writeMessage(self, m):
        self.write(m.serialize())
        
    def writeSequence(self, buffers):
        raise Exception("Only expected a single response to a single run mobile code packet")
    
    def writeMessages(self, messages):
        raise Exception("Only expected a single response to a single run mobile code packet")
    
    def getHost(self): return self.__transport.getHost()
    def getPeer(self): return self.__transport.getPeer()
    def loseConnection(self): self.__transport.loseConnection()
    def abortConnection(self): self.__transport.abortConnection()

class ServerProtocol(playground.network.common.SimpleMessageHandlingProtocol):
    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_FINISHED = "Finished"
    STATE_PURCHASE = "Purchase decryption key"
    STATE_REREQUEST = "Rerequest decryption key"
    STATE_RUNNING = "Running code"
    STATE_ERROR = "Error"
    
    BILLING_SLICE_SECONDS = 5*60 # 5 Minute Slices
    BILLING_RATE_PER_SLICE = 5 # 5 Bitpoints per 5 minute slice
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
        self.__state = self.STATE_UNINIT
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0}
        self.__codeString = None
        
        self.registerMessageHandler(SessionRunMobileCode, self.__handleRunMobileCode)
        self.registerMessageHandler(OpenSession, self.__handleOpenSession)
        self.registerMessageHandler(PurchaseDecryptionKey, self.__handlePurchase)
        self.registerMessageHandler(RerequestDecryptionKey, self.__handleRerequest)
        self.registerMessageHandler(Heartbeat, self.__handleHeartbeat)
        
    def __loadMibs(self):
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
            return [self.__state]
        elif mib.endswith(self.MIB_COOKIE):
            return ["%d-%d" % (self.__connData["ClientNonce"], self.__connData["ServerNonce"])]
        elif mib.endswith(self.MIB_CODE_STRING):
            if self.__codeString: return [self.__codeString]
            return ["<Not Set Yet>"]
        return ""
        
    def connectionMade(self):
        playground.network.common.SimpleMessageHandlingProtocol.connectionMade(self)
        self.__loadMibs()

    def __error(self, errMsg):
        if self.__state == self.STATE_ERROR:
            if self.transport:
                self.transport.loseConnection()
            return None
        if self.__state == self.STATE_UNINIT:
            response = MessageData.GetMessageBuilder(SessionOpenFailure)
            response["ClientNonce"] = self.__connData["ClientNonce"]
        else:
            if self.__state == self.STATE_OPEN:
                response = MessageData.GetMessageBuilder(RunMobileCodeFailure)
            elif self.__state == self.STATE_PURCHASE or self.__state == self.STATE_REREQUEST:
                response = MessageData.GetMessageBuilder(AcquireDecryptionKeyFailure)
            else:
                response = MessageData.GetMessageBuilder(GeneralFailure)
            response["ClientNonce"].setData(self.__connData["ClientNonce"])
            response["ServerNonce"].setData(self.__connData["ServerNonce"])
        response["ErrorMessage"].setData(errMsg)
        self.__state = self.STATE_ERROR
        
        packetTrace(logger, response, "Had an error %s" % errMsg)
        self.transport.writeMessage(response)
        self.callLater(1,self.transport.loseConnection)
        return None
    
    def __handleHeartbeat(self,prot, msg):
        logger.info("Heartbeat received, sending response")
        msg["Response"].setData(True)
        self.transport.writeMessage(msg)
    
    def __loadCookie(self, builder):
        builder["ClientNonce"].setData(self.__connData["ClientNonce"])
        builder["ServerNonce"].setData(self.__connData["ServerNonce"])
        
    def __handleOpenSession(self, protocol, msg):
        if not self.__state == self.STATE_UNINIT:
            return self.__error("Invalid open session. Session not ready to be opened (%s)" % self.__state)
        msgObj = msg.data()
        if msgObj.Authenticated:
            return self.__error("Authenticated operation not yet supported")
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        self.__connData["ServerNonce"] = RANDOM_u64()
        response = MessageData.GetMessageBuilder(SessionOpen)
        self.__loadCookie(response)
        response["ServiceLevel"].setData("BASIC")
        response["BillingTimeSliceSeconds"].setData(self.BILLING_SLICE_SECONDS)
        response["BillingRatePerSlice"].setData(self.BILLING_RATE_PER_SLICE)
        response["ServiceExtras"].init()
        self.__state = self.STATE_OPEN
        
        packetTrace(logger, response, "Received opensession message from %s. State is now open" % str(self.transport.getPeer()))
        self.transport.writeMessage(response)
        
    def __codeHandlerWrapper(self, realHandler, codeUnit):
        self.__codeString = codeUnit.getCodeString()
        return realHandler(codeUnit)
        
    def __handleRunMobileCode(self, prot, msg):
        if not self.__state == self.STATE_OPEN:
            return self.__error("Invalid command. Cannot run mobile code unless session open")
        msgObj = msg.data()
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return self.__error("Invalid connection data (clientNonce)")
        if msgObj.ServerNonce != self.__connData["ServerNonce"]:
            return self.__error("Invalid connection data (serverNonce)")
        rawRunMobileCodeMsg = msgObj.RunMobileCodePacket
        startTime = time.time()
        ctx = CodeExecutionContext()
        ctx.account= self.__accountName
        ctx.startTime = startTime
        ctx.clientNonce = self.__connData["ClientNonce"]
        ctx.serverNonce = self.__connData["ServerNonce"]
        ctx.runMobileCodeHash = SHA.new(rawRunMobileCodeMsg).digest()
        ctx.slice = self.BILLING_SLICE_SECONDS
        ctx.rate = self.BILLING_RATE_PER_SLICE
        ctx.finishCallback = self.__mobileCodeComplete
        aesKey = os.urandom(16)
        aesIv = os.urandom(16)
        succeed, errmsg = self.__factory.createMobileCodeRecord(ctx.clientNonce, ctx.serverNonce, aesKey, aesIv, msgObj.MaxRuntime)
        if not succeed:
            return self.__error("Could not run this code. Reason: " + errmsg)
        transport = WrapMobileCodeResultTransport(self.transport, aesKey, aesIv, ctx)
        wrappedProtocol = WrapMobileCodeResultProtocol(transport)
        self.__state = self.STATE_RUNNING
        logger.info("Starting execution of mobile code")
        #realCodeHandler = playground.extras.sandbox.SandboxCodeunitAdapter(self.SANDBOX_CONTROLLER,
                                                                       #timeout=min(msgObj.MaxRuntime,self.CODE_TIMEOUT))
        #codeHandler = lambda codeUnit: self.__codeHandlerWrapper(realCodeHandler, codeUnit)
        runMobileCodeHandler = RunMobileCodeHandler(self)#, codeHandler)
        runMobileCodeHandler(wrappedProtocol, Packet.DeserializeMessage(rawRunMobileCodeMsg)[0])
        
    def __mobileCodeComplete(self, ctx, cost):
        self.__factory.mobileCodeComplete(ctx.clientNonce, ctx.serverNonce, cost)
        self.__state = self.STATE_PURCHASE
        
    def __handlePurchase(self, prot, msg):
        if self.__state not in [self.STATE_PURCHASE, self.STATE_UNINIT]:
            return self.__error("Invalid command. Not in correct state for purchase (%s)" % self.__state)
        msgObj = msg.data()
        if self.__state == self.STATE_PURCHASE:
            if msgObj.ClientNonce != self.__connData["ClientNonce"]:
                return self.__error("Invalid connection data (clientNonce)")
            if msgObj.ServerNonce != self.__connData["ServerNonce"]:
                return self.__error("Invalid connection data (serverNonce)")
        else:
            self.__state = self.STATE_PURCHASE
            self.__connData["ClientNonce"] = msgObj.ClientNonce
            self.__connData["ServerNonce"] = msgObj.ServerNonce
        if not self.__factory.validatePurchase(msgObj.ClientNonce, msgObj.ServerNonce, 
                                               msgObj.Receipt, msgObj.ReceiptSignature):
            return self.__error("Invalid purchase receipt")
        decryptionKey, decryptionIv = self.__factory.getDecryptionData(msgObj.ClientNonce, msgObj.ServerNonce)
        if not decryptionKey or not decryptionIv:
            return self.__error("Unexpected failure in getDecryptionData!")
        response = MessageData.GetMessageBuilder(ResultDecryptionKey)
        self.__loadCookie(response)
        response["key"].setData(decryptionKey)
        response["iv"].setData(decryptionIv)
        self.__state = self.STATE_FINISHED
        packetTrace(logger, response, "%s sending key %s, iv %s" % (str(msgObj.ClientNonce)+str(msgObj.ServerNonce),
                                                                    binascii.hexlify(decryptionKey),
                                                                    binascii.hexlify(decryptionIv)))
        self.transport.writeMessage(response)
        self.callLater(1, self.transport.loseConnection)
        
    def __handleRerequest(self, prot, msg):
        if not self.__state == self.STATE_UNINIT:
            return self.__error("Cannot re-request a key except at the beginning of a session")
        self.__state = self.STATE_REREQUEST
        msgObj = msg.data()
        decryptionKey, decryptionIv = self.__factory.getDecryptionData(msgObj.ClientNonce, msgObj.ServerNonce)
        if not decryptionKey or not decryptionIv:
            return self.__error("No decryption key found")

class Server(playground.network.client.ClientApplicationServer.ClientApplicationServer):
    MIB_BILLING_ACCOUNT = "BillingAccount"
    MIB_CODE_IN_PROCESS = "CodeInProcess"
    
    def __init__(self, accountName, bankCert, receiptDb, keyDb):
        self.__accountName = accountName
        self.__bankCert = bankCert
        self.__receiptDbFile = receiptDb
        self.__keyDbFile = keyDb
        self.__receiptDb = shelve.open(receiptDb, "c")
        self.__keyDb = shelve.open(keyDb,"c")
        self.__clearStaleKeys()
        self.__inprocessCode = set([])
        rsaKey = RSA.importKey(bankCert.getPublicKeyBlob())
        self.__validater = PKCS1_v1_5.new(rsaKey)
        
    def __clearStaleKeys(self):
        staleList = []
        for searchKey in self.__receiptDb.keys():
            keyData  = self.__receiptDb[searchKey]
            currentKeyType, timestamp = keyData[0], keyData[1]
            if time.time() > timestamp:
                staleList.append(searchKey)
        for searchKey in staleList:
            del self.__receiptDb[searchKey]
            if self.__keyDb.has_key(searchKey):
                del self.__keyDb[searchKey]
        
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
        self.__clearStaleKeys()
        self.__receiptDb.close()
        self.__keyDb.close()
        self.__receiptDb = shelve.open(self.__receiptDbFile, "w")
        self.__keyDb = shelve.open(self.__keyDbFile, "w")
        
    def buildProtocol(self, addr):
        return ServerProtocol(self, addr, self.__accountName)
    
    def createMobileCodeRecord(self, clientNonce, serverNonce, aesKey, aesIv, maxRuntime):
        searchKey = str(clientNonce) + str(serverNonce)
        self.__inprocessCode.add(searchKey)
        if self.__keyDb.has_key(searchKey) or self.__receiptDb.has_key(searchKey):
            return False, "Duplicate cookie"
        self.__keyDb[searchKey] = (aesKey, aesIv)
        self.__receiptDb[searchKey] = ("UNKNOWN",time.time()+maxRuntime)
        self.__save()
        return True, ""
    
    def mobileCodeComplete(self, clientNonce, serverNonce, cost):
        searchKey = str(clientNonce) + str(serverNonce)
        if not self.__keyDb.has_key(searchKey) or not self.__receiptDb.has_key(searchKey):
            return False, "No such cookie"
        if searchKey in self.__inprocessCode:
            self.__inprocessCode.remove(searchKey)
        self.__receiptDb[searchKey] = ("COST",time.time()+300,cost)
        self.__save()
        return True, ""
    
    def validatePurchase(self, clientNonce, serverNonce, receipt, receiptSignature):
        searchKey = str(clientNonce) + str(serverNonce)
        if not self.__keyDb.has_key(searchKey) or not self.__receiptDb.has_key(searchKey):
            return False, "No such cookie"
        if not self.__receiptDb[searchKey][0] == "COST":
            return False, "Not expecting a purchase"
        if not self.__validater.verify(SHA.new(receipt), receiptSignature):
            return False, "Signature failed"
        ll = pickle.loads(receipt)
        if ll.memo(self.__accountName) != searchKey:
            return False, "Memo is not equal to clientNonce+serverNonce"
        costCode, timestamp, expectedCost = self.__receiptDb[searchKey]
        if ll.getTransactionAmount(self.__accountName) < expectedCost:
            remaining = expectedCost - ll.getTransactionAmount(self.__accountName)
            self.__receiptDb[searchKey] = ("COST",remaining)
            return False, "Insufficient purchase"
        self.__receiptDb[searchKey]=("RECEIPT",time.time()+300,receipt,receiptSignature)
        self.__save()
        return True, ""
    
    def getDecryptionData(self, clientNonce, serverNonce):
        searchKey = str(clientNonce) + str(serverNonce)
        if not self.__keyDb.has_key(searchKey) or not self.__receiptDb.has_key(searchKey):
            logger.error("Attempt to get decryption key, iv for %s, but search key not found" % searchKey)
            return None, None
        if not self.__receiptDb[searchKey][0] == "RECEIPT":
            rCode = self.__receiptDb[searchKey][0]
            logger.error("Attempt to get decryption key, iv for %s, but expected receipt code is" % (searchKey,
                                                                                                     rCode))
            return None, None
        key, iv = self.__keyDb[searchKey]
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
    receiptdbFile = "receiptdb"+playgroundAddress.toString()
    keysdbFile = "keysdb"+playgroundAddress.toString()
    server = Server(accountName, cert, receiptdbFile, keysdbFile)
    client = playground.network.client.ClientBase(playgroundAddress)
    client.listen(server, MOBILE_CODE_SERVICE_FIXED_PLAYGROUND_PORT, connectionType="RAW")
    client.connectToChaperone(ipAddr, ipPort)