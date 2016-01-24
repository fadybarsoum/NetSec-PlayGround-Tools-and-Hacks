'''
Created on Oct 23, 2013

@author: sethjn
'''

from twisted.internet.protocol import Protocol as TwistedProtocol

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
        self._store = PacketStorage()
        self._factory = factory
        self._addr = addr
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
        logger.debug("%s received %d bytes" % (self, len(buf)))
        self._store.update(buf)
        message = self._store.popMessage(errorReporter=self)
        while message:
            packetTrace(logger, message, "Message received by protocol %s." % str(self.__class__))
            self.messageReceived(message)
            message = self._store.popMessage()
            
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