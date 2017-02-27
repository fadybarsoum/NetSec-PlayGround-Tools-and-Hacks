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

class PassthruMsg(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "none.Passthru"
    MESSAGE_VERSION = "1.0"
    
    BODY = [ ("data", STRING) ]

class PassthruTransport(StackingTransport):
    def __init__(self, lowerTransport):
        StackingTransport.__init__(self, lowerTransport)
        
    def write(self, data):
        fscMessage = PassthruMsg()
        fscMessage.data = data
        self.lowerTransport().write(fscMessage.__serialize__())

class PassthruProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.messageStorage = MessageStorage()
        
    def connectionMade(self):
        higherTransport = PassthruTransport(self.transport)
        self.makeHigherConnection(higherTransport)
        
    def connectionLost(self, reason=ConnectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport=None
        self.setHigherProtocol(None)
        
    def dataReceived(self, data):
        self.messageStorage.update(data)
        for msg in self.messageStorage.iterateMessages():
         
            if self.higherProtocol():
                self.higherProtocol().dataReceived(msg.data)
            else:
                print "ERROR, still had data but no higher layer"
        
class PassthruFactory(StackingFactoryMixin, Factory):
    protocol = PassthruProtocol
    
ConnectFactory = PassthruFactory
ListenFactory = PassthruFactory
            