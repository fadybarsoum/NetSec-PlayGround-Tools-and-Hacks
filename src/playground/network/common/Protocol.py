'''
Created on Oct 23, 2013

@author: sethjn
'''


import logging
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.Errors import DeserializationError,\
    UnexpectedMessageError
from playground.error.ErrorHandler import GetErrorReporter
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.defer import Deferred
from playground.network.common.Timer import callLater

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

class MessageStorage(object):
    
    def __init__(self, messageType=None, myErrReporter=None):
        # Allow an error reporter to be passed in. The calling
        # code will probably want to use its own error trapping
        # and reporting
        self.__errReporter = myErrReporter and myErrReporter or errReporter
        self.__messageType = messageType and messageType or MessageDefinition
        self.clear()
        
    def __forceAdvanceBufferPointer(self, offset=1):
        # we need to not keep trying with the current buffer
                # advance packetStorage at least one byte.
        if self.__packetStorage and self.__packetStorage[0]:
            self.__packetStorage[0] = self.__packetStorage[0][offset:]
        
    def update(self, data):
        if data: self.__packetStorage.append(data)
        
    def clear(self):
        self.__packetStorage = []
        self.__streamIterator = None
        
    def popMessage(self):
        dirty = False
        while self.__packetStorage:
            if not self.__packetStorage[0]:
                self.__packetStorage.pop(0)
                continue
            if not self.__streamIterator:
                self.__streamIterator = self.__messageType.DeserializeStream(self.__packetStorage)
            try:
                message = self.__streamIterator.next()
                dirty = False
            except StopIteration:
                message = None
                self.__streamIterator = None
                self.__errReporter.error("Could not get messageBuilder. This is unexpected.")
                self.__forceAdvanceBufferPointer()
                continue
            except DeserializationError, e:
                if not dirty:
                    # we have an error. It may take use some time to find the right place
                    # in the stream. Don't report the error until we're done or found a good spot
                    dirty = True
                    self.__errReporter.error("New Deserialization error. Attempt to get back in stream.", exception=e)
                self.__streamIterator = None
                self.__forceAdvanceBufferPointer()
                continue
            except UnexpectedMessageError, e:
                self.__errReporter.error("Deserialized the wrong type of message")
                continue
            except Exception, e:
                self.__errReporter.error("Unexpected error in deserialization.")
                
            if not message:
                # there shouldn't be any left over bytes
                # logger.debug("Remaining buffers lengths: %s" % map(len, self.__packetStorage))
                return None
            
            # TODO: Figure out a logging strategy.
            self.__streamIterator = None
            return message
        
    def iterateMessages(self):
        while True:
            message = self.popMessage()
            if message: yield message
            else: break

class StackingFactoryMixin(object):
    __higherFactory = None
    
    @classmethod
    def StackType(cls, higherFactoryType):
        class StackedType(cls):
            @classmethod
            def Stack(self, higherFactory):
                return cls.Stack(higherFactoryType.Stack(higherFactory))
        return StackedType
    
    @classmethod
    def Stack(cls, higherFactory):
        factory = cls()
        factory.setHigherFactory(higherFactory)
        return factory
    
    def setHigherFactory(self, f):
        self.__higherFactory = f
        
    def higherFactory(self):
        return self.__higherFactory
    
    def buildProtocolStack(self, addr):
        myProt = self.buildProtocol(addr)
        if self.higherFactory():
            if isinstance(self.higherFactory(), StackingFactoryMixin):
                higherProt = self.higherFactory().buildProtocolStack(addr)
            else:
                higherProt = self.higherFactory().buildProtocol(addr)
            myProt.setHigherProtocol(higherProt)
        return myProt
       
class StackingProtocolMixin(object):
    __higherProtocol = None
    __higherConnectionDeferred = None
    
    def waitForHigherConnection(self):
        self.__higherConnectionDeferred = Deferred()
        if self.higherProtocol().transport:
            callLater(0,self.__higherConnectionDeferred.callback, self.higherProtocol())
        return self.__higherConnectionDeferred
    
    def makeHigherConnection(self, higherTransport):
        self.higherProtocol().makeConnection(higherTransport)
        if self.__higherConnectionDeferred:
            callLater(0,self.__higherConnectionDeferred.callback, self.higherProtocol())
    
    def setHigherProtocol(self, higherProtocol):
        self.__higherProtocol = higherProtocol
        
    def higherProtocol(self):
        return self.__higherProtocol
        
    def applicationLayer(self):
        higherLayer = self.higherProtocol()
        if not higherLayer: return self
        
        if isinstance(higherLayer, StackingProtocolMixin): 
            return higherLayer.applicationLayer()
        return higherLayer
    
class StackingTransport(object):
    implements(ITransport)
    
    def __init__(self, lowerTransport):
        self.__lowerTransport = lowerTransport
        
    def lowerTransport(self):
        return self.__lowerTransport
        
    def write(self, data):
        self.__lowerTransport.write(data)
        
    def writeSequence(self, seq):
        self.__lowerTransport.writeSequence(seq)
        
    def getHost(self):
        return self.__lowerTransport.getHost()
    
    def getPeer(self):
        return self.__lowerTransport.getPeer()
    
    def loseConnection(self):
        return self.__lowerTransport.loseConnection()
    
    def __repr__(self):
        return "%s Transport %s to %s over %s" % (self.__class__,
                                                  self.getHost(), self.getPeer(),
                                                  self.__lowerTransport)
    

