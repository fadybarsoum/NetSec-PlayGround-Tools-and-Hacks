'''
Created on Oct 23, 2013

@author: sethjn
'''

from twisted.internet.protocol import Protocol as TwistedProtocol
from twisted.internet.protocol import Factory as TwistedFactory

from playground.network.message import MessageData
from Packet import PacketStorage
from Timer import OneshotTimer
from playground.error import ErrorHandlingMixin
from MIBAddress import MIBAddressMixin

from playground.playgroundlog import packetTrace
import logging, time
logger = logging.getLogger(__name__)

class Protocol(TwistedProtocol, MIBAddressMixin, ErrorHandlingMixin):
    '''
    Base class of all Playground protocols. A thin wrapper around
    Twisted Protocols but providing for "message Received" as opposed
    to "dataReceived."
    '''


    def __init__(self, factory=None, addr=None):
        '''
        Constructor
        '''
        # There is no "TwistedProtocol.__init__"
        self._factory = factory
        self._addr = addr
        if isinstance(factory, TwistedFactory):
            self.__dataHandlingMode = "internet"
            self.__packetStorage = PacketStorage()
        else:
            self.__dataHandlingMode = "playground"
            self.__packetStorage = []
            self.__streamIterator = None
        # set defaults
        self.changeTimerClass()
        
    def reportError(self, error, explicitReporter=None, stackHack=0):
        peer = self.transport and str(self.transport.getPeer()) or "<NOT CONNECTED>"
        return ErrorHandlingMixin.reportError(self, "%s [PEER: %s]" % (error, peer),
                                              explicitReporter=explicitReporter,
                                              stackHack=stackHack+1)
        
    def connectionMade(self):
        if self._factory and isinstance(self._factory, MIBAddressMixin) and self._factory.MIBAddressEnabled():
            self.configureMIBAddress(str(id(self)), self._factory, self._factory.MIBRegistrar())
            
    def connectionLost(self, reason=None):
        TwistedProtocol.connectionLost(self, reason)
        self.transport=None
        self._factory = None
        self.disableMIBAddress()
        
    def changeTimerClass(self, timerClass=None, getTime=None):
        if timerClass:
            self.__timerClass = timerClass
        else:
            self.__timerClass = OneshotTimer
        if getTime:
            self.__getTime = getTime
        else:
            self.__getTime = time.time
        
    def callLater(self, callDelaySeconds, cb):
        return self.__timerClass(cb).run(callDelaySeconds)
    
    def protocolTime(self):
        return self.__getTime()
        
    def dataReceived(self, buf):
        """
        Subclasses should NOT overwrite this method!
        """
        logger.info("%s received %d bytes" % (self, len(buf)))
        if self.__dataHandlingMode == "internet":
            self.__internetDataReceived(buf)
        else:
            self.__playgroundDataReceived(buf)
        
    def __playgroundDataReceived(self, buf):
        self.__packetStorage.append(buf)
        logger.debug("New buffer received. Buffer count %s" %  len(self.__packetStorage))
        while self.__packetStorage and self.__packetStorage[0]:
            logger.debug("Stream deser. first buffer size is %d" % len(self.__packetStorage[0]))
            if not self.__streamIterator:
                self.__streamIterator = MessageData.DeserializeStream(self.__packetStorage)
            try:
                messageBuilder = self.__streamIterator.next()
            except StopIteration:
                messageBuilder = None
                self.__streamIterator = None
                self.reportError("Could not get messageBuilder")
                return
            except Exception, e:
                logger.error("Current first 50 bytes of buf when error happened: %s" % buf[:50])
                logger.error("Buf count %d" % len(self.__packetStorage))
                self.reportException(e, explicitReporter=Protocol.dataReceived)
                self.__streamIterator = None
                return
            if not messageBuilder:
                logger.debug("Not enough bytes to completely deserialize")
                return
            else:
                logger.debug("Message deserialized")
                self.__streamIterator = None
                self.messageReceived(messageBuilder)
        
    def __internetDataReceived(self, buf):
        self.__packetStorage.update(buf)
        packetBytes = self.__packetStorage.popPacket()
        while packetBytes != None:
            try:
                msgBuilder, bytesConsumed = (MessageData.Deserialize(packetBytes))
            except Exception, e:
                self.reportException(e, explicitReporter=Protocol.dataReceived)
            if not msgBuilder:
                self.reportError("Could not get messageBuilder.")
            else:
                logger.info("Consumed %d bytes rebuilding %s" % (bytesConsumed, msgBuilder))
                self.messageReceived(msgBuilder)
            packetBytes = self.__packetStorage.popPacket()
            
    def messageReceived(self, msg):
        raise Exception("Must be implemented by subclasses")
    
class StackingProtocolMixin(object):
    def setHigherProtocol(self, higherProtocol):
        self.__higherProtocol = higherProtocol
        
    def getHigherProtocol(self):
        try:
            return self.__higherProtocol
        except:
            return None
        
    def getApplicationLayer(self):
        higherLayer = self.getHigherProtocol()
        if not higherLayer: return self
        if isinstance(higherLayer, StackingProtocolMixin): 
            nextHigherLayer = higherLayer.getApplicationLayer()
            if nextHigherLayer:
                higherLayer = nextHigherLayer
        return higherLayer
    
class StackingFactoryMixin(MIBAddressMixin):
    __higherFactory = None
    __configuredHigherMIB = False
    
    def setHigherFactory(self, f):
        self.__higherFactory = f
        
    def higherFactory(self):
        return self.__higherFactory
    
    # The mixin is designed to mixin with ClientApplicationServer and
    # ClientApplicationFactory, which are already MIBAddressMixin's
    # Yes, this is all very pooly designed. A re-write is needed.
    def configureMIBAddress(self, localKey, parent, mibRegistration):
        factoryName = "_"+self.__class__.__name__
        localKey = localKey+factoryName
        MIBAddressMixin.configureMIBAddress(self, localKey, parent, mibRegistration)
        if self.__higherFactory and isinstance(self.__higherFactory, MIBAddressMixin):
            if not self.__higherFactory.MIBAddressEnabled():
                self.__configuredHigherMIB = True
                self.__higherFactory.configureMIBAddress(localKey, parent, mibRegistration)
            
    def disableMIBAddress(self):
        MIBAddressMixin.disableMIBAddress(self)
        if self.__higherFactory and isinstance(self.__higherFactory, MIBAddressMixin):
            if self.__configuredHigherMIB:
                self.__higherFactory.disableMIBAddress()
    
    def buildProtocol(self, addr):
        myProt = self.Protocol(self, addr)
        if self.__higherFactory:
            higherProt = self.__higherFactory.buildProtocol(addr)
            myProt.setHigherProtocol(higherProt)
        return myProt