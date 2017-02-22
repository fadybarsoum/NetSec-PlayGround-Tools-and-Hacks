'''
Created on Sep 10, 2016

@author: sethjn
'''

from playground.network.message.definitions.playground.base import Gate2GateReservation,\
    Gate2GateResponse

from zope.interface import implements
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint, connectProtocol
from twisted.internet.interfaces import IStreamServerEndpoint, IStreamClientEndpoint, ITransport
from twisted.internet.interfaces import IListeningPort

import random, logging, imp
from twisted.internet.defer import Deferred
from playground.twisted.error.Failure import SimpleFailure as Failure
from playground.error.ErrorHandler import GetErrorReporter
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.config import GlobalPlaygroundConfigData
from playground.network.common.Timer import callLater
from playground.network.gate import ConnectionData
from twisted.internet.error import ConnectError
from playground.network.common.Protocol import StackingTransport, MessageStorage,\
    StackingProtocolMixin, StackingFactoryMixin
from playground.network.common.PlaygroundAddress import PlaygroundAddressPair

errReporter = GetErrorReporter(__name__)
g_logger = logging.getLogger(__name__)
gateEndpointConfig = GlobalPlaygroundConfigData.getConfig(__name__)
    

class GateService(object):
    logger = logging.getLogger(__name__+".GateService")
    CALLBACK_PORT_START = 9100
    CALLBACK_PORT_END = 65000
    
    CALLBACK_TYPE_RESERVATION = "Reservation"
    CALLBACK_TYPE_CONNECT = "Connect"
    CALLBACK_TYPE_SPAWN = "Spawn"
    CALLBACK_TYPE_CONNECT_COMPLETE = "Connect Complete"
    
    GATES = {}
    
    @classmethod
    def ConnectToGate(cls, reactor, gateAddr, gatePort, callbackPort = None):
        if callbackPort == None:
            callbackPort = random.randint(cls.CALLBACK_PORT_START,cls.CALLBACK_PORT_END/2)
        cls.logger.info("Connecting to gate %s %d with callback port %d" % 
                        (gateAddr, gatePort, callbackPort))
        callbackProtocolFactory = GateCallbackFactory()
        point = TCP4ServerEndpoint(reactor, callbackPort)
        connectD = Deferred()
        d = point.listen(callbackProtocolFactory)
        d.addCallback(cls.__listenerStarted, reactor, gateAddr, gatePort, callbackPort, callbackProtocolFactory, point, connectD)
        d.addErrback(cls.__listenerFailed, reactor, gateAddr, gatePort, callbackPort, connectD)
        return connectD
    
    @classmethod
    def __listenerStarted(cls, result, reactor, gateAddr, gatePort, callbackPort, callbackProtocolFactory, point, connectD):
        gateKey = (gateAddr, gatePort)
        if cls.GATES.has_key(gateKey):
            cls.logger.info("Already connected.")
            cls.__controlConnected("Already Connected", callbackPort, cls.GATES[gateKey][1], 
                                   callbackProtocolFactory, point, connectD)
            #d = Deferred()
        else:
            cls.logger.info("Starting outbound connection to gate.")
            gatePoint = TCP4ClientEndpoint(reactor, gateAddr, gatePort)
            gateProtocol = GateProtocol()
            cls.GATES[gateKey] = (gatePoint, gateProtocol)
            d = connectProtocol(gatePoint, gateProtocol)
            d.addCallback(cls.__controlConnected, callbackPort, gateProtocol, 
                           callbackProtocolFactory, point, connectD)
            d.addErrback(cls.__controlConnectFailed, gateKey, connectD)
    
    @classmethod        
    def __listenerFailed(cls, failure, reactor, gateAddr, gatePort, callbackPort, connectD):
        cls.logger.info("Could not reserve callback port %d. Trying %d" % (callbackPort, callbackPort+1))
        callbackPort += 1
        if callbackPort == cls.CALLBACK_PORT_END:
            f = Failure("No Callback Port Found")
            connectD.errback(f)
            return f
        nextTryD = cls.ConnectToGate(reactor, gateAddr, gatePort, callbackPort)
        nextTryD.addCallback(connectD.callback)
        nextTryD.addErrback(connectD.errback)
        # must return failure, or the success callback will be called
        return failure
            
    @classmethod
    def __controlConnected(cls, result, callbackPort, gateProtocol, callbackProtocolFactory, point, connectD):
        cls.logger.info("Connection to Gate established.")
        connectD.callback((point, callbackProtocolFactory, callbackPort, gateProtocol))
        
    @classmethod
    def __controlConnectFailed(cls, failure, gateKey, connectD):
        errReporter.warning("Could not get control channel connection: %s" % failure)
        del cls.GATES[gateKey]
        connectD.errback(failure)
        return failure

class GateServerEndpoint(object):
    implements(IStreamServerEndpoint)
    
    class ListeningPort(object):
        implements(IListeningPort)
        
        def __init__(self, address, port, stopCallback):
            self.address = address
            self.port = port
            self.stopCallback = stopCallback
            
        def startListening(self):
            pass
        
        def stopListening(self):
            return self.stopCallback(self)
        
        def getHost(self):
            return self.address
    
    @classmethod
    def CreateFromConfig(cls, reactor, listenPort, confKey=None, defaultKey=None, networkStack=None):
        g2gConfig = ConnectionData.CreateFromConfig(confKey, defaultKey)
        gatePort = g2gConfig.gatePort
        gateAddr = "127.0.0.1"
        return cls(reactor, listenPort, gateAddr, gatePort, networkStack)
    
    def __init__(self, reactor, listenPort, gateAddr, gatePort, networkStack=None):
        self.__logger = logging.getLogger(self.__class__.__name__+".listener_%d" % listenPort)
        self.__reactor = reactor
        self.__gateAddr = gateAddr
        self.__gatePort = gatePort
        self.__listenAddr = None
        self.__listenPort = listenPort
        self.__listenD = None
        self.__listenFactory = None
        self.__networkStack = networkStack
            
    def __gateConnected(self, result):
        self.__logger.info("Gate connection complete.")
        self.__callbackPoint, self.__callbackProtocolFactory, self.__callbackPort, self.__gateProtocol = result
        self.__gateProtocol.reservePort(self.__listenPort, self.__callbackPort, self)
        
    def __stopListening(self, *args):
        raise NotImplementedError("stopListening not yet implemented")
        
    def gateback(self, result):
        callbackType = result[0]
        self.__logger.info("Received response from gate of type %s" % callbackType)
        if callbackType == GateService.CALLBACK_TYPE_RESERVATION:
            srcAddr, srcPort, msg = result[1:]
            if srcPort != self.__listenPort:
                errReporter.error("Got a reservation callback for port %d, but expected %d" % (srcPort, self.__listenPort))
                return
            self.__listenAddr = srcAddr
            listenD = self.__listenD
            self.__listenD = None
            self.__logger.info("Now listening on %s:%d" % (srcAddr, srcPort))
            listenD.callback(self.ListeningPort(srcAddr, srcPort, self.__stopListening))
        elif callbackType == GateService.CALLBACK_TYPE_SPAWN:
            dstAddr, dstPort, connPort, msg = result[1:]
            
            if isinstance(self.__listenFactory, StackingFactoryMixin):
                spawnProtocol = self.__listenFactory.buildProtocolStack((self.__listenAddr, self.__listenPort))
            else:
                spawnProtocol = self.__listenFactory.buildProtocol((self.__listenAddr, self.__listenPort))
            self.__logger.info("Spawn connection from %s %d" % (dstAddr, dstPort))
            self.__callbackProtocolFactory.initializeCallbackProtocol(connPort,
                                                                      self.__listenAddr, self.__listenPort,
                                                                      dstAddr, dstPort,
                                                                      spawnProtocol, Deferred())
            # TODO: Have the deferred passwed here connect to something
        else:
            errReporter.error("Got an unexpected callback type %s" % callbackType)
            
    def gateerr(self, failure):
        errReporter.error("Gate reported error %s" % failure)
        if self.__listenD:
            self.__listenD.errback(failure)
        # todo: close factory?
        
    def listen(self, factory):
        if self.__listenFactory:
            raise Exception("Method 'listen' can only be called once.")

        if self.__networkStack:
            self.__listenFactory = self.__networkStack.ListenFactory.Stack(factory)
        else:
            self.__listenFactory = factory
    
        d = GateService.ConnectToGate(self.__reactor, self.__gateAddr, self.__gatePort)
        d.addCallback(self.__gateConnected)
        self.__listenD = Deferred()
        d.addErrback(self.__listenD.errback)
        return self.__listenD
    
class GateClientEndpoint(object):
    implements(IStreamClientEndpoint)
    
    @classmethod
    def CreateFromConfig(cls, reactor, dstAddr, dstPort, confKey=None, defaultKey=None, networkStack=None):
        g2gConfig = ConnectionData.CreateFromConfig(confKey, defaultKey)
        gatePort = g2gConfig.gatePort
        gateAddr = "127.0.0.1"
        return cls(reactor, dstAddr, dstPort, gateAddr, gatePort, networkStack)
    
    def __init__(self, reactor, dstAddr, dstPort, gateAddr, gatePort, networkStack=None):
        self.__logger = logging.getLogger(self.__class__.__name__+".oubtound_%s_%d" % (dstAddr, dstPort))
        self.__reactor = reactor
        self.__gateAddr = gateAddr
        self.__gatePort = gatePort
        self.__dstAddr = dstAddr
        self.__dstPort = dstPort
        self.__srcAddr = None
        self.__srcPort = None
        self.__connectD = None
        self.__connectFactory = None
        self.__networkStack = networkStack
        
    def __gateConnected(self, result):
        self.__logger.info("Gate connection complete.")
        self.__callbackPoint, self.__callbackProtocolFactory, self.__callbackPort, self.__gateProtocol = result
        self.__gateProtocol.connect(self.__dstAddr, self.__dstPort, self.__callbackPort, self)
        
    def gateback(self, result):
        callbackType = result[0]
        self.__logger.info("Received response from gate of type %s" % callbackType)
        if callbackType == GateService.CALLBACK_TYPE_CONNECT:
            # OK, we've asked to connect, but the callback isn't complete yet.
            # We do have our src port though
            
            self.__srcAddr, self.__srcPort, dstAddr, dstPort, msg = result[1:]
            if dstAddr != self.__dstAddr or dstPort != self.__dstPort:
                raise Exception("Got a connection for %s:%s but expected %s:%s" % 
                                (dstAddr, dstPort, self.__dstAddr, self.__dstPort))
            self.__logger.info("Connection half-open from %s %s to %s %s" % 
                             (self.__srcAddr, self.__srcPort, dstAddr, dstPort))
        elif callbackType == GateService.CALLBACK_TYPE_CONNECT_COMPLETE:
            connPort, msg = result[1:]
            if isinstance(self.__connectFactory, StackingFactoryMixin):
                connectProtocol = self.__connectFactory.buildProtocolStack((self.__srcAddr, self.__srcPort))
            else:
                connectProtocol = self.__connectFactory.buildProtocol((self.__srcAddr, self.__srcPort))
            self.__logger.info("Completing outbound connection")
            self.__callbackProtocolFactory.initializeCallbackProtocol(connPort,
                                                                      self.__srcAddr, self.__srcPort,
                                                                      self.__dstAddr, self.__dstPort,
                                                                      connectProtocol, self.__connectD)
        else:
            errReporter.error("Got an unexpected callback type %s" % callbackType)
            
    def gateerr(self, failure):
        errReporter.error("Gate reported error %s" % failure)
        if self.__connectD:
            self.__connectD.errback(failure)
        # todo: close factory?
        
    def connect(self, factory):
        if self.__connectFactory:
            raise Exception("Method 'connect' can only be called once.")
        if self.__networkStack:
            self.__connectFactory = self.__networkStack.ConnectFactory.Stack(factory)
        else:
            self.__connectFactory = factory
        
        d = GateService.ConnectToGate(self.__reactor, self.__gateAddr, self.__gatePort)
        d.addCallback(self.__gateConnected)
        self.__connectD = Deferred()
        d.addErrback(self.__connectD.errback)
        return self.__connectD

class GateCallbackProtocol(Protocol, StackingProtocolMixin):
    def __init__(self, addr, factory):
        self._addr = addr
        self.factory = factory
        self.backlog = []
    
    def connectionMade(self):
        g_logger.info("Gate Callback connection made to %s" % self.transport.getPeer())
        self.factory.registerCallbackProtocol(self.transport.getPeer().port, self)
        
    def connectionLost(self, reason=None):
        g_logger.info("Gate Callback connection lost. Disconnecting higher protocol. reason=%s" % reason)
        if self.higherProtocol(): 
            self.higherProtocol().connectionLost(reason)
            self.setHigherProtocol(None)
        self.factory.unregisterCallbackProtocol(self)
        Protocol.connectionLost(self, reason)
        
    def completeConnection(self, higherTransport):
        g_logger.info("Setting higher layer transport %s" % higherTransport)
        self.higherProtocol().makeConnection(higherTransport)
        for data in self.backlog:
            self.higherProtocol().dataReceived(data)
        self.backlog = []
        
    def dataReceived(self, data):
        if not self.higherProtocol():
            self.backlog.append(data)
        else:
            self.higherProtocol().dataReceived(data)
            
class GateTransport(StackingTransport):
    
    def __init__(self, srcAddr, srcPort, dstAddr, dstPort, twistedTransport):
        StackingTransport.__init__(self, twistedTransport)
        self.__srcAddr, self.__srcPort = srcAddr, srcPort
        self.__dstAddr, self.__dstPort = dstAddr, dstPort
        
    def write(self, data):
        self.lowerTransport().write(data)
        
    def getHost(self):
        return PlaygroundAddressPair(self.__srcAddr, self.__srcPort)
    
    def getPeer(self):
        return PlaygroundAddressPair(self.__dstAddr, self.__dstPort)
    
    def loseConnection(self):
        g_logger.info("GateTransport %s to %s lose connection" % (self.getHost(),
                                                                  self.getPeer()))
        return StackingTransport.loseConnection(self)
    
class GateCallbackFactory(Factory):
    def __init__(self):
        self.__uninitializedConnections = {}
        self.__initializedConnections = {}
        
    def registerCallbackProtocol(self, peerPort, protocol):
        g_logger.info("Callback protocol %s created and connected to TCP port %d, but not yet initialized with gate data" %
                      (protocol, peerPort))
        self.__uninitializedConnections[peerPort] = protocol
        
    def initializeCallbackProtocol(self, peerPort, srcAddr, srcPort, dstAddr, dstPort, higherProtocol, d, retryCount=10):
        if not self.__uninitializedConnections.has_key(peerPort):
            if retryCount:
                callLater(.25, self.initializeCallbackProtocol, peerPort, srcAddr, srcPort, dstAddr, dstPort, higherProtocol, d, retryCount-1)
                return
            # retry exhausted
            errReporter.warning("Received 'init' for a connection %d that does not exist." % peerPort)
            d.errback(ConnectError)
            return
        protocol = self.__uninitializedConnections[peerPort]
        g_logger.info("Callback protocol %s initialized for gate %s:%d to %s:%d" % 
                      (protocol, srcAddr, srcPort, dstAddr, dstPort))
        del self.__uninitializedConnections[peerPort]
        self.__initializedConnections[protocol] = higherProtocol
        transport = GateTransport(srcAddr, srcPort, dstAddr, dstPort, protocol.transport)
        protocol.setHigherProtocol(higherProtocol)
        protocol.completeConnection(transport)
        connectionMade_d = protocol.waitForHigherConnection()
        connectionMade_d.addCallback(self.__higherProtocolConnected, d)
        connectionMade_d.addErrback(d.errback)
        
    def __higherProtocolConnected(self, protocol, d):
        if isinstance(protocol, StackingProtocolMixin):
            if protocol.higherProtocol() == None:
                d.callback(protocol)
            else:
                connectionMade_d = protocol.waitForHigherConnection()
                connectionMade_d.addCallback(self.__higherProtocolConnected, d)
                connectionMade_d.addErrback(d.errback)
        else:
            d.callback(protocol)
        
    def unregisterCallbackProtocol(self, protocol):
        if self.__initializedConnections.has_key(protocol):
            del self.__initializedConnections[protocol]
        
    def buildProtocol(self, addr):
        return GateCallbackProtocol(addr, self)

class GateProtocol(Protocol):

    @classmethod
    def GetNextResvId(cls):
        return random.randint(0,2**32)
    
    def __init__(self):
        self.__buffer = MessageStorage()
        self.__listenLookup = {}
        self.__connLookup = {}
        
    def reservePort(self, srcPort, callbackPort, serverEndpoint):
        resvId = self.GetNextResvId()
        g_logger.info("Sending G2G port reservation to gate with ID %d for srcPort %d" %
                      (resvId, srcPort))
        resv = Gate2GateReservation(resvType = Gate2GateReservation.RESV_TYPE_LISTEN, resvId=resvId,
                                    callbackAddr = self.transport.getHost().host,
                                    callbackPort = callbackPort,
                                    srcPort = srcPort)
        self.transport.write(resv.__serialize__())
        self.__listenLookup[resvId] = serverEndpoint
    
    def connect(self, dstAddr, dstPort, callbackPort, clientEndpoint):
        resvId = self.GetNextResvId()
        g_logger.info("Sending G2G outbound reservation to gate with ID %d for connection to %s:%d" % 
                      (resvId, dstAddr, dstPort))
        resv = Gate2GateReservation(resvType = Gate2GateReservation.RESV_TYPE_CONNECT, resvId=resvId,
                                    callbackAddr = self.transport.getHost().host,
                                    callbackPort = callbackPort,
                                    dstAddr = dstAddr, dstPort = dstPort)
        self.transport.write(resv.__serialize__())
        self.__connLookup[resvId] = clientEndpoint
        
    def dataReceived(self, data):
        self.__buffer.update(data)
        for g2gMessage in self.__buffer.iterateMessages():
            self.__handleG2gResponse(g2gMessage)
        
    def __handleG2gResponse(self, g2gMessage):
        if g2gMessage.resvType == Gate2GateReservation.RESV_TYPE_LISTEN:
            self.__handleG2gResvListen(g2gMessage)
        elif g2gMessage.resvType == Gate2GateReservation.RESV_TYPE_CONNECT:
            self.__handleG2gResvConnect(g2gMessage)
            
    def __handleG2gResvListen(self, g2gMessage):
        resvId, respType = g2gMessage.resvId, g2gMessage.respType
        error = ""
        if not self.__listenLookup.has_key(resvId):
            errReporter.warning("Unexpected response with Resevation Id %d" % resvId)
            return
        if g2gMessage.success:
            if respType == Gate2GateResponse.RESP_TYPE_INITIAL:
                # this is a generic reservation response
                self.__listenLookup[resvId].gateback((GateService.CALLBACK_TYPE_RESERVATION,
                                                     g2gMessage.srcAddr, g2gMessage.srcPort,
                                                     g2gMessage.msg))
            elif respType == Gate2GateResponse.RESP_TYPE_CALLBACK:
                # this means there's a newly spawned connection on the reserved port
                self.__listenLookup[resvId].gateback((GateService.CALLBACK_TYPE_SPAWN,
                                                     g2gMessage.dstAddr, g2gMessage.dstPort,
                                                     g2gMessage.connPort,
                                                     g2gMessage.msg))
            else:
                error = "Got an unexpected response type %s" % respType
        else:
            error = "Gate reported error msg: %s" % g2gMessage.msg
        
        if error:
            self.__listenLookup[resvId].gateerr(Failure(error))
            del self.__listenLookup[resvId]
            
    def __handleG2gResvConnect(self, g2gMessage):
        resvId, respType = g2gMessage.resvId, g2gMessage.respType
        error = ""
        if not self.__connLookup.has_key(resvId):
            errReporter.warning("Unexpected response for reservation Id %d" % resvId)
            return
        if g2gMessage.success:
            if respType == Gate2GateResponse.RESP_TYPE_INITIAL:
                self.__connLookup[resvId].gateback((GateService.CALLBACK_TYPE_CONNECT,
                                                    g2gMessage.srcAddr, g2gMessage.srcPort,
                                                    g2gMessage.dstAddr, g2gMessage.dstPort,
                                                    g2gMessage.msg))
            elif respType == Gate2GateResponse.RESP_TYPE_CALLBACK:
                self.__connLookup[resvId].gateback((GateService.CALLBACK_TYPE_CONNECT_COMPLETE,
                                                    g2gMessage.connPort,
                                                    g2gMessage.msg))
            else:
                error = "Got an unexpected response type %s" % respType
        else:
            error = "Gate reported error msg: %s" % g2gMessage.msg
        
        if error:
            self.__listenLookup[resvId].gateerr(Failure(error))
            del self.__listenLookup[resvId]
