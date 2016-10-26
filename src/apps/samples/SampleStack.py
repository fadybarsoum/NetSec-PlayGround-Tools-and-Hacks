'''
Created on Sep 21, 2016

@author: sethjn
'''
from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from twisted.internet.error import ConnectionDone

class FixedStreamCipherMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.samples.SampleStack.FixedSreamCipherMessage"
    MESSAGE_VERSION = "1.0"
    
    BODY = [ ("data", STRING) ]
    
def XorStrings(s1, s2):
    xorStr = ""
    for i in range(len(s1)):
        xorStr += chr(ord(s1[i]) ^ ord(s2[i]))
    return xorStr

class FixedStreamCipherTransport(StackingTransport):
    def __init__(self, lowerTransport, fixedKey):
        StackingTransport.__init__(self, lowerTransport)
        self.FixedKey = fixedKey
        
    def write(self, data):
        xorData = ""
        keySize = len(self.FixedKey)
        while data:
            dataChunk, data = data[:keySize], data[keySize:]
            xorData += XorStrings(dataChunk, self.FixedKey)
        fscMessage = FixedStreamCipherMessage()
        fscMessage.data = xorData
        self.lowerTransport().write(fscMessage.__serialize__())

class FixedStreamCipherProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.messageStorage = MessageStorage()
        
    def connectionMade(self):
        higherTransport = FixedStreamCipherTransport(self.transport, self.factory.FixedKey)
        self.makeHigherConnection(higherTransport)
        
    def connectionLost(self, reason=ConnectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport=None
        self.setHigherProtocol(None)
        
    def dataReceived(self, data):
        self.messageStorage.update(data)
        for fscMessage in self.messageStorage.iterateMessages():
        
            xoredData = fscMessage.data
            keySize = len(self.factory.FixedKey)
            plainData = ""
            while xoredData:
                dataChunk, xoredData = xoredData[:keySize], xoredData[keySize:]
                plainData += XorStrings(dataChunk, self.factory.FixedKey)
            if self.higherProtocol():
                self.higherProtocol().dataReceived(plainData)
            else:
                print "ERROR, still had data but no higher layer"
        
class FixedStreamCipherFactory(StackingFactoryMixin, Factory):
    FixedKey = "PASSWORD"
    protocol = FixedStreamCipherProtocol
    
ConnectFactory = FixedStreamCipherFactory
ListenFactory = FixedStreamCipherFactory
            