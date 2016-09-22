'''
Created on Mar 28, 2016

@author: sethjn
'''
from playground.network.common import Packet
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol
from playground.network.message.definitions.playground import intercept, base
from playground.network.message import MessageData
from twisted.internet import reactor

import threading, hashlib
from playground.network.client.ClientApplicationTransport import StackingTransportMixin
#from playground.network.common import PlaygroundAddress
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet import reactor

sha256Int = lambda s: int(hashlib.sha256(s).hexdigest(), 16)

class ComputeResponse(object):
    def __init__(self, challenge, completionRoutine):
        self.challenge = challenge
        self.response = None
        self.completionRoutine = completionRoutine
        self.errorMessage = None
        
    def run(self):
        algorithm, testMessage, zerosRequired = self.challenge
        if algorithm != "SHA256":
            self.errorMessage = "Could not compute for algorithm %s" % algorithm
            return self.completionRoutine()
        iv = 0
        while (sha256Int(testMessage+str(iv)) >> (256-zerosRequired)) != 0:
            iv += 1
        self.response = str(iv)
        return self.completionRoutine()

class ClientInterceptor(SimpleMessageHandlingProtocol, StackingTransportMixin):
    def __init__(self, factory, address, interceptAddr, dstHigherProtocol, srcHigherProtocol):
        SimpleMessageHandlingProtocol.__init__(self, factory, None)
        self.ipAddress = address
        self.__interceptAddress = interceptAddr
        self.__responseComp = None
        self.dstHigherProtocol = dstHigherProtocol
        self.srcHigherProtocol = srcHigherProtocol
        self.registerMessageHandler(intercept.Challenge, self.handleChallenge)
        self.registerMessageHandler(intercept.RegistrationResult, self.handleResult)
        self.registerMessageHandler(base.Gate2GateMessage, self.handleC2CPacket)
        
    def connectionMade(self):
        intMsg = MessageData.GetMessageBuilder(intercept.Register)
        intMsg["Address"].setData(self.__interceptAddress)
        self.transport.write(Packet.MsgToPacketBytes(intMsg))
        
    def __sendResponse(self):
        if not self.__responseComp:
            raise Exception("could not compute response")
        if self.__responseComp.errorMessage:
            raise Exception("Error during computation: %s" % self.__responseComp.errorMessage)
        if not self.__responseComp.response:
            raise Exception("No response or error message generated")
        respMsg = MessageData.GetMessageBuilder(intercept.ChallengeResponse)
        respMsg["Address"].setData(self.__interceptAddress)
        respMsg["Response"].setData(self.__responseComp.response)
        reactor.callFromThread(lambda: self.transport.write(Packet.MsgToPacketBytes(respMsg)))
        
    def handleChallenge(self, protocol, challengeMsg):
        if not self.__interceptAddress:
            raise Exception("Invalid state. No address")
        msgObj = challengeMsg.data()
        challenge = (msgObj.HashAlgorithm, msgObj.TestMessage, msgObj.ZerosRequired)
        self.__responseComp = ComputeResponse(challenge, self.__sendResponse)
        t = threading.Thread(target=self.__responseComp.run)
        t.daemon = True
        t.start()
        
    def handleResult(self, protocol, resultMsg):
        msgObj = resultMsg.data()
        if msgObj.Result:
            self.srcHigherProtocol.makeConnection(self)
            self.dstHigherProtocol.makeConnection(self)
        else:
            self.transport.loseConnection()
            raise Exception("Invalid result?")
        
    def handleC2CPacket(self, protocol, msg):
        msgObj = msg.data()
        print "Received intercepted c2c message", msgObj.dstAddress, msgObj.srcAddress, self.__interceptAddress
        if msgObj.dstAddress == self.__interceptAddress:
            print "pass to dstHigher"
            self.dstHigherProtocol.messageReceived(msg)
        elif msgObj.srcAddress == self.__interceptAddress:
            print "pass to srcHigher"
            self.srcHigherProtocol.messageReceived(msg)
        else:
            raise Exception("Unexpected packet from %s to %s" % (msgObj.srcAddress, msgObj.dstAddress))
        
    def write(self, data):
        encap = MessageData.GetMessageBuilder(intercept.EncapsulatedC2C)
        encap["Address"].setData(self.__interceptAddress)
        encap["C2CMessage"].setData(data)
        self.transport.write(Packet.MsgToPacketBytes(encap))
        
    def loseConnection(self):
        self.transport.loseConnection()
        self.connectionLost()
        
    def connectionLost(self, reason=None):
        self.dstHigherProtocol.connectionLost(reason)
        self.srcHigherProtocol.connectionLost(reason)
        
    def handleTermination(self, protocol, msg):
        msgObj = msg.data()
        self.dstHigherProtocol.connectionLost(msgObj.Reason)
        self.srcHigherProtocol.connectionLost(msgObj.Reason)
        self.transport.connectionLost()
        
class InterceptorFactory(Factory):
    Protocol = ClientInterceptor
    def __init__(self, interceptAddr, dstProtocol, srcProtocol):
        self.interceptAddr = interceptAddr
        self.dstProtocol = dstProtocol
        self.srcProtocol = srcProtocol
        
    def buildProtocol(self, addr):
        return self.Protocol(self, addr, self.interceptAddr, self.dstProtocol, self.srcProtocol)
    
    def connectToChaperone(self, chaperoneAddr, chaperonePort):
        point = TCP4ClientEndpoint(reactor, chaperoneAddr, chaperonePort)
        point.connect(self)
    