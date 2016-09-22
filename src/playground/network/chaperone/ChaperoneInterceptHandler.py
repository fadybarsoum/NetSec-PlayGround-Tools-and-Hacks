'''
Created on Mar 28, 2016

@author: sethjn
'''

from playground.network.message.definitions.playground import intercept
from playground.network.message import MessageData
from playground.network.common import Packet
import time, os, hashlib

class InterceptionData(object):
    DEFAULT_ZEROS = 35
    DEFAULT_TIMEOUT = (24*3600) # 24 hours x seconds/hour
    def __init__(self):
        self.starttime = 0
        self.chaperoneProtocol = None
        self.interceptionHandler = None
        self.currentZeros = self.DEFAULT_ZEROS
        
g_InterceptionDb = {}

class MessageInterceptor(object):
    def __init__(self):
        self.ignore = set([])
    def __call__(self, serializedMessage, originalMessage):
        if originalMessage.playground_msgID in self.ignore:
            self.ignore.remove(originalMessage.playground_msgID)
            return serializedMessage        
        
        dstInterceptData = g_InterceptionDb.get(originalMessage.dstAddress, None)
        if dstInterceptData and dstInterceptData.chaperoneProtocol.transport:
            dstInterceptData.chaperoneProtocol.transport.write(serializedMessage)
            return ""
        srcInterceptData = g_InterceptionDb.get(originalMessage.srcAddress, None)
        if srcInterceptData and srcInterceptData.chaperoneProtocol.transport:
            srcInterceptData.chaperoneProtocol.transport.write(serializedMessage)
            return ""
        
        return serializedMessage
messageInterceptor = MessageInterceptor()

def encapsulatedMessageHandler(protocol, msg):
        try:
            c2cMsg, actualBytes = MessageData.Deserialize(msg.G2GMessage)
        except:
            # todo, this is an error. There wasn't a full message. Add logging?
            return
        
        if g_InterceptionDb.has_key(msg.Address) and g_InterceptionDb[msg.Address].chaperoneProtocol == protocol:
            key = c2cMsg.playground_msgID
            messageInterceptor.ignore.add(key)
        protocol.dataReceived(Packet.MsgToPacketBytes(c2cMsg))

class ChaperoneInterceptHandler(object):
    TEST_MESSAGE_SIZE = 10
    
    def __init__(self):
        self.outstandingRegistrations = {}
        self.currentRegistrations = set([])
        
    def registerMessages(self, chaperone):
        chaperone.registerMessageHandler(intercept.Register, self.handleRegistration)
        chaperone.registerMessageHandler(intercept.ChallengeResponse, self.handleChallengeResponse)
        chaperone.registerMessageHandler(intercept.Unregister, self.handleUnregister)
        
    def handleRegistration(self, chaperone, msg):
        interceptionAddress = msg.Address
                
        # don't allow them to try to register the address while ongoing
        if self.outstandingRegistrations.has_key(interceptionAddress):
            chaperone.transport.loseConnection()
            return
        
        curData = g_InterceptionDb.get(msg.Address, None)
        if curData:
            zerosRequired = curData.currentZeros
        else:
            zerosRequired = InterceptionData.DEFAULT_ZEROS
        testMessage = os.urandom(self.TEST_MESSAGE_SIZE)
        challengeMsg = intercept.Challenge()
        challengeMsg.Address = interceptionAddress
        challengeMsg.HashAlgorithm = "SHA256" # hardcoded for now
        challengeMsg.TestMessage=testMessage
        challengeMsg.ZerosRequired = zerosRequired
        self.outstandingRegistrations[interceptionAddress] = ("SHA256", testMessage, zerosRequired)
        packetBytes = Packet.MsgToPacketBytes(challengeMsg)
        chaperone.transport.write(packetBytes)
        #Message(challengeMsg)
        
    def handleChallengeResponse(self, chaperone, msg):
        
        # got an unexpected challenge response. Shut down connection.
        if not self.outstandingRegistrations.has_key(msgObj.Address):
            chaperone.transport.loseConnection()
            return
        
        algorithm, message, zerosRequired = self.outstandingRegistrations[msgObj.Address]
        realhash = hashlib.sha256(message+msgObj.Response).hexdigest()
        realhashAsNumber = int(realhash, 16)
        resultMsg = MessageData.GetMessageBuilder(intercept.RegistrationResult)
        resultMsg["Address"].setData(msg.Address)
        if (realhashAsNumber >> (256-zerosRequired)) != 0:
            resultMsg["Result"].setData(False)
            chaperone.transport.write(Packet.MsgToPacketBytes(resultMsg))
            chaperone.callLater(0.5, chaperone.transport.loseConnection)
        else:
            resultMsg["Result"].setData(True)
            del self.outstandingRegistrations[msg.Address]
            curData = g_InterceptionDb.get(msg.Address, None)
            if curData:
                curData.interceptionHandler.releaseAddress(msg.Address, "Bumped")
                del g_InterceptionDb[msg.Address]
            g_InterceptionDb[msg.Address] = InterceptionData()
            g_InterceptionDb[msg.Address].starttime = time.time()
            g_InterceptionDb[msg.Address].chaperoneProtocol = chaperone
            g_InterceptionDb[msg.Address].interceptionHandler = self
            g_InterceptionDb[msg.Address].zerosRequired = zerosRequired+1
            self.currentRegistrations.add(msg.Address)
            timeout = InterceptionData.DEFAULT_TIMEOUT/(2**(zerosRequired-InterceptionData.DEFAULT_ZEROS))
            chaperone.callLater(timeout, lambda: self.releaseAddress(msg.Address, "Timeout"))
            chaperone.transport.write(Packet.MsgToPacketBytes(resultMsg))
    
    def handleUnregister(self, chaperone, msg):
        if g_InterceptionDb.has_key(msg.Address):
            if g_InterceptionDb[msg.Address].interceptionHandler != self:
                # Trying to unregister someone else. Disconnect
                chaperone.transport.loseConnection()
                return
            g_InterceptionDb[msg.Address].interceptionHandler.releaseAddress(msg.Address, "Unregistered")
            
    def releaseAddress(self, address, msg):
        if address in self.currentRegistrations:
            self.currentRegistrations.remove(address)
            curData = g_InterceptionDb.get(address, None)
            if not curData: return 
            del g_InterceptionDb[address]
            if not curData.chaperoneProtocol: return
            if not curData.chaperoneProtocol.transport: return
            termMsg = MessageData.GetMessageBuilder(intercept.Terminated)
            termMsg["Address"].setData(address)
            termMsg["Reason"].setData(msg)
            curData.chaperoneProtocol.transport.write(Packet.MsgToPacketBytes(termMsg))
            
    def close(self):
        while self.currentRegistrations:
            address = self.currentRegistrations.pop()
            self.releaseAddress(address, "Connection Closed")