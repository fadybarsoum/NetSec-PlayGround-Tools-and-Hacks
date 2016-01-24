'''
Created on Oct 23, 2013

@author: sethjn
'''

from playground.config import GlobalPlaygroundConfigData
from playground.network.message import MessageData

from playground.network.common import SimpleMessageHandler, Protocol, StackingProtocolMixin, Packet, PlaygroundAddress, PlaygroundAddressPair
from playground.network.common import MIBAddressMixin
from playground.network.common import Error as NetworkError
from playground.network.common import Timer

from playground.crypto import CertificateDatabase

from playground.error import ErrorHandlingMixin, Common, PlaygroundError

from MIBClient import SimpleMIBClientProtocol, SimpleMIBClientFactory, MIBServer
from ClientMessageHandlers import Client2ClientHandler, ClientRegisteredHandler
from ClientConnectionState import ClientConnectionState
from ClientApplicationTransport import ClientApplicationTransport
from ClientApplicationServer import ClientApplicationServer

from playground.network.message.definitions import playground

from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet import reactor

import traceback, logging, sys, os, time

from playground.playgroundlog import packetTrace
logger = logging.getLogger(__name__)

configData = GlobalPlaygroundConfigData.getConfig(__name__)

class ConnectionTypeFactory(object):
    def __init__(self, config):
        self.__types = {}
        typesListString = config.get("connection_types.list","")
        typesList = typesListString.split(",")
        for t in typesList:
            t = t.strip()
            if not t: continue
            clientFactory = config.get("connection_types.%s.client"%t, None)
            serverFactory = config.get("connection_types.%s.server"%t, None)
            self.__types[t.strip()] = (clientFactory, serverFactory)
            #(self.__loadFactoryModule(clientFactory), self.__loadFactoryModule(serverFactory))
            
    def __loadFactoryModule(self, moduleName):
        if moduleName == None or moduleName.lower() == "none": 
            return lambda topFactory: topFactory
        dottedParts = moduleName.split(".")
        modulePath, factoryMethod = ".".join(dottedParts[:-1]), dottedParts[-1]
        __import__(modulePath)
        module = sys.modules[modulePath]
        return module.__dict__[factoryMethod]
        
    def getClientFactory(self, connectionType):
        if not self.__types.has_key(connectionType):
            raise Exception("No Playground Connection Type: %s" % connectionType)
        if isinstance(self.__types[connectionType][0], str):
            self.__types[connectionType] = (self.__loadFactoryModule(self.__types[connectionType][0]), self.__types[connectionType][1])
        return self.__types[connectionType][0]
    
    def getServerFactory(self, connectionType):
        if not self.__types.has_key(connectionType):
            raise Exception("No Playground Connection Type: %s" % connectionType)
        if isinstance(self.__types[connectionType][1], str):
            self.__types[connectionType] = (self.__types[connectionType][0], self.__loadFactoryModule(self.__types[connectionType][1]))
        return self.__types[connectionType][1]
ConnectionTypeFactoryInstance = ConnectionTypeFactory(configData)

class PortData(object):
    PORT_TYPE_INCOMING = 1
    PORT_TYPE_OUTGOING = 2
    
    @classmethod
    def CreateIncomingPort(cls, listeningFactory):
        portData = PortData(cls.PORT_TYPE_INCOMING)
        portData.listeningFactory = listeningFactory
        portData.incomingConnections = {}
        return portData
        
    @classmethod
    def CreateOutgoingPort(cls, connectionProtocol, destination):
        portData = PortData(cls.PORT_TYPE_OUTGOING)
        portData.connectionProtocol = connectionProtocol
        portData.destination = destination
        return portData
        
    def __init__(self, portType):
        self.portType = portType
        self.listeningFactory = None
        self.incomingConnections = None
        self.connectionProtocol = None
        self.destination = None
        
    def isListening(self):
        return self.listeningFactory != None
    
    def spawnNewConnection(self, srcAddrPair, dstAddrPair):
        if self.portType == PortData.PORT_TYPE_INCOMING:
            if self.incomingConnections.has_key(dstAddrPair):
                return False, "Already have a connection for this destination"
            self.incomingConnections[dstAddrPair] = self.listeningFactory.buildProtocol(srcAddrPair)
            return True, self.incomingConnections[dstAddrPair]
        else:
            return False, "Outgoing connections cannot spawn new connections"
    
    def isConnectedTo(self, dstAddrPair):
        if self.portType == PortData.PORT_TYPE_INCOMING:
            return self.incomingConnections.has_key(dstAddrPair)
        else:
            return self.destination == dstAddrPair
        
    def getConnectionList(self):
        if self.portType == PortData.PORT_TYPE_INCOMING:
            return self.incomingConnections.keys()
        else:
            return [self.destination]
        
    def getConnectionProtocol(self, dstAddrPair):
        if self.portType == PortData.PORT_TYPE_INCOMING:
            return self.incomingConnections.get(dstAddrPair,None)
        elif self.portType == PortData.PORT_TYPE_OUTGOING:
            logger.debug("PortData::getConnectionProtocol outgoing. Compare %s with %s" % (self.destination,
                                                                                           dstAddrPair))
            if self.destination == dstAddrPair:
                logger.debug("%s equals %s" % (self.destination, dstAddrPair))
                return self.connectionProtocol
            logger.debug("%s != %s" % (self.destination, dstAddrPair))
            return None
        return None

class ClientBase(Factory, SimpleMessageHandler, MIBAddressMixin, ErrorHandlingMixin):
    """
    ClientBase represents the basic connection to the Playground network. To
    build a Playground Application, one creates a Server Factory/Protocol that plugs into
    the ClientBase using 'listen' and then creates a client factory/Protocol
    that connects to the installed client server over PLAYGROUND using the
    'connect' method.
    
    For asychronous handling, use the method runWhenConnected() to start processing
    after the initial connection to PLAYGROUND is achieved. Alternatively, call
    getPeers with a callback to start processing after getting the currently connected
    peer addresses.
    """
    class ConnectionState:
        PRE_CONNECT = ClientConnectionState(0, "No connection to Playground Server")
        NEGOTIATING = ClientConnectionState(1, "Negotiating with Playground Server")
        CONNECTED =  ClientConnectionState(2, "Connected to Playground Server")
        DISCONNECTED = ClientConnectionState(3, "Disconnected from Playground Server")
        
    class Mibs:
        CURRENT_STATE = "CurrentState"
        PORTS_IN_USE = "PortsInUse"
        

    def __getChangeStateFunctor(self, newState, requiredPreviousState=None):
        def functor():
            if requiredPreviousState and requiredPreviousState != self.__connectionState:
                self.reportError("Could not change state to %s. Previous state was not %s" % (newState, requiredPreviousState))
                return
            self.__connectionState = newState
        return functor
        
    def __init__(self, addr):
        SimpleMessageHandler.__init__(self)
        #SimpleMIBClientProtocol.__init__(self, addr)
        
        if not isinstance(addr, PlaygroundAddress):
            raise Common.InvalidArgumentException("Expected a PlaygroundAddress")
        self.__addr = addr
        self.__connectionState = self.ConnectionState.PRE_CONNECT
        self.__protocol = None
        self.__ports = {}
        self.__connectionData = None
        self.__peerCallbacks = []
        self.__waitForPlayground = []
        self.__mibServer = None
        self.__mibAuthInfo = {}
        self.__mibProtocols = {}
        self.__mibAddressesConfigured = {}
        self.__initMibServer()
        
        """ Register all Message Handlers """
        self.registerMessageHandler(
                                    playground.base.ClientRegistered, 
                                    ClientRegisteredHandler(self.__playgroundConnected,
                                                            self.__getChangeStateFunctor(self.ConnectionState.DISCONNECTED)
                                                            )
                                    )
        self.registerMessageHandler(playground.base.ClientToClientMessage, Client2ClientHandler(self.__ports, self.__closeConnection))
        self.registerMessageHandler(playground.base.Peers, self.__peersReceived)
        
    def __initMibServer(self):
        mibServerConfig = configData.get("mib_server", {})
        if mibServerConfig.get("enable", "False").lower() == "true":
            port = int(mibServerConfig["port"])
            connType = mibServerConfig.get("connection_type", None)
            authCert = mibServerConfig.get("authorized_cert", None)
            if authCert:
                authCert = CertificateDatabase.GetDatabase().loadX509(authCert)
            trustedPrefix = mibServerConfig.get("trusted_prefix", "")
            self.__mibServer = MIBServer.GetMibServerForAddr(self.__addr, authCert, trustedPrefix)
            self.listen(self.__mibServer, port, connType)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.Mibs.CURRENT_STATE, self.__mibResponder)
            self.registerLocalMIB(self.Mibs.PORTS_IN_USE, self.__mibResponder)
        
    def __mibResponder(self, mib, args):
        if mib.endswith(self.Mibs.CURRENT_STATE):
            return [str(self.__connectionState)]
        elif mib.endswith(self.Mibs.PORTS_IN_USE):
            portInfo = []
            for port, portData in self.__ports.items():
                if portData.portType == PortData.PORT_TYPE_INCOMING:
                    portInfo.append("Port %d: %s" % (port, str(portData.listeningFactory)))
                    for destAddr, destPort in portData.incomingConnections.keys():
                        appProt = portData.incomingConnections[(destAddr, destPort)].getApplicationLayer()
                        portInfo.append("%d serving %s protocol to %s/%d" % (port, str(appProt), destAddr, destPort))
                else:
                    appProt = portData.connectionProtocol.getApplicationLayer()
                    destAddr, destPort = portData.destination
                    portInfo.append("Src port %d open %s protocol to %s/%d" % (port, str(appProt), destAddr, destPort))
            return portInfo
        return []
        
    def __playgroundConnected(self, connectionPod):
        self.__getChangeStateFunctor(self.ConnectionState.CONNECTED)()
        self.__connectionData = connectionPod

        if self.__mibServer:
            myMibAddress = "ClientBase_"+str(self.__addr)+"_"+str(self.__protocol.transport.getHost())
            self.configureMIBAddress(myMibAddress, None, self.__mibServer)
            self.__loadMibs()
        mibClientConfig = configData.get("mib_client",{})
        if mibClientConfig.get("enable", "False").lower() == "true":
            authKeyFile = mibClientConfig.get("server_auth_key",None)
            if authKeyFile:
                authKey = CertificateDatabase.GetDatabase().loadPrivateKey(authKeyFile)
                self.__protocol.setMIBServerAuthData(authKey)
            self.__mibAuthInfo["server"] = [None, authKey]
            for k in mibClientConfig.keys(topLevelOnly=True):
                if k.startswith("phone_book_"):
                    authInfo = mibClientConfig[k]
                    prefix = authInfo["addr_prefix"]
                    connectionType = authInfo.get("connection_type", None)
                    authKey = authInfo.get("auth_key",None)
                    if authKey:
                        authKey = CertificateDatabase.GetDatabase().loadPrivateKey(authKey)
                    if prefix[-1] == ".":
                        prefix = prefix[:-1]
                    if self.__mibAuthInfo.has_key(prefix):
                        raise Exception("Invalid configuration. Duplicate prefix " + prefix)
                    self.__mibAuthInfo[prefix] = [connectionType, authKey]
        while self.__waitForPlayground:
            functor = self.__waitForPlayground.pop(0)
            functor()
        
    def __peersReceived(self, protocol, msg):
        packetTrace(logger, msg, "Got response from server")
        
        peerList = msg["peers"].data()
        for cb in self.__peerCallbacks:
            cb(peerList)
        self.__peerCallbacks = []
        
    def __closeConnection(self, srcAddrPair, dstAddrPair, reason=None):
        srcPort = srcAddrPair.port
        dstAddr = dstAddrPair.host
        dstPort = dstAddrPair.port
        
        protocolToClose = None
        if self.__ports.has_key(srcPort):
            portData = self.__ports[srcPort]
            if portData.portType == PortData.PORT_TYPE_INCOMING:
                if portData.incomingConnections.has_key(dstAddrPair):
                    protocolToClose = portData.incomingConnections[dstAddrPair]
                    logger.info("ClientBase closing protocol %s connected to peer %s because %s" % (protocolToClose, dstAddrPair, reason))
                    del portData.incomingConnections[dstAddrPair]
                else:
                    logger.error("ClientBase tried to close %s server connection to %s but not found." % (srcAddrPair, dstAddrPair))
            elif portData.portType == PortData.PORT_TYPE_OUTGOING:
                if portData.destination == dstAddrPair:
                    if self.__mibAddressesConfigured.has_key(srcPort):
                        self.__mibAddressesConfigured[srcPort].disableMIBAddress()
                        del self.__mibAddressesConfigured[srcPort]
                    protocolToClose = portData.connectionProtocol
                    del self.__ports[srcPort]
                else:
                    logger.error("ClientBase tried to close %s outgoing connection to %s but not found" % (srcAddrPair, dstAddrPair))
        else:
            logger.error("ClientBase tried to close %s connection to %s, but not found." % (srcAddrPair, dstAddrPair))
        if protocolToClose:
            protocolToClose.connectionLost(reason)
        
    def getAddress(self): return PlaygroundAddress.FromString(self.__addr.toString())
        
    def getPlaygroundState(self): return self.__connectionState
    
    def listen(self, protFactory, port, connectionType=None):
        """
        Install a client application server on a port for this client base.
        Incoming packets not previously identified will produce a new protocol
        """
        if self.__ports.has_key(port):
            logger.error("Server already exists on port %d" % port)
            return False
        if connectionType:
            clientFactoryStack = ConnectionTypeFactoryInstance.getServerFactory(connectionType)
            protFactory = clientFactoryStack(protFactory)
        if self.__mibServer and not protFactory.MIBAddressEnabled():
            self.__mibAddressesConfigured[port] = protFactory
            self.runWhenConnected(lambda: protFactory.configureMIBAddress("ClientServer_%d" % port, self, self.__mibServer))
        self.__ports[port] = PortData.CreateIncomingPort(protFactory)
        return True
        
    def close(self, port):
        if not self.__ports.has_key(port):
            logger.error("No server on port %d" % port)
            return False
        if self.__mibAddressesConfigured.has_key(port):
            self.__mibAddressesConfigured[port].disableMIBAddress()
            del self.__mibAddressesConfigured[port]
        # if this has active connections, try to close them all
        portData = self.__ports[port]
        for addrPair in portData.getConnectionList():
            protocol = portData.getConnectionProtocol(addrPair)
            if protocol:
                protocol.connectionLost(reason="Port forcibly closed")
        del self.__ports[port]
        return True
        
    def connect(self, protFactory, dstAddr, dstPort, connectionType=None, getFullStack=False):
        """
        Open a connection to another Playground Node. 'protFactory' is
        used even though we'll only need one protocol to keep standard with twisted
        usage
        """
        if connectionType:
            serverStack = ConnectionTypeFactoryInstance.getClientFactory(connectionType)
            protFactory = serverStack(protFactory)
        
        """ Hardcoded 'client' ports range from 1000-9000... change this later """
        for srcPort in range(1000,65536):
            """ If there is something on this port, it is either a server or an open connection """
            """ Either way, we can't use it """
            if not self.__ports.has_key(srcPort):
                # We don't need a factory on this port because it will not receive 
                # incoming connections.
                srcAddrPair = PlaygroundAddressPair(self.__addr, srcPort)
                dstAddrPair = PlaygroundAddressPair(dstAddr, dstPort)
                transport = ClientApplicationTransport(self.__protocol.transport, srcAddrPair, dstAddrPair, self.__closeConnection, self.__protocol.multiplexingProducer())
                prot = protFactory.buildProtocol(srcAddrPair)
                fullstack = [prot]
                while isinstance(fullstack[-1], StackingProtocolMixin) and fullstack[-1].getHigherProtocol():
                    fullstack.append(fullstack[-1].getHigherProtocol())
                
                if self.__mibServer and not protFactory.MIBAddressEnabled():
                    key = "%s_(%d)" % (str(dstAddr), dstPort)
                    protFactory.configureMIBAddress("ClientConnection_to_"+key, self, self.__mibServer)
                    self.__mibAddressesConfigured[srcPort] = protFactory
                logger.info("Creating outgoing port on %d with dst %s " % (srcPort, dstAddrPair))
                self.__ports[srcPort] = PortData.CreateOutgoingPort(prot, dstAddrPair)
                
                prot.makeConnection(transport)
                if getFullStack: return (srcPort, fullstack)
                else: return (srcPort, fullstack[-1])
        logger.error("No available port between 1000,65536!")
        return (None, None)
    
    def getPortData(self, port):
        if self.__ports.has_key(port):
            if self.__ports[port].portType == PortData.PORT_TYPE_INCOMING:
                return ("SERVER",self.__ports[port].listeningFactory,self.__ports[port].incomingConnections.items())
            elif self.__ports[port].portType == PortData.PORT_TYPE_OUTGOING:
                return ("CLIENT",self.__ports[port].connectionProtocol,self.__ports[port].destination)
        else:
            return ("CLOSED",)
        
    def getPeers(self, callback):
        """
        Get the peers from the server. The callback will be called when the peers are received.
        There is currently no way to signal to the callback if something has failed.
        """
        if self.__connectionState != self.ConnectionState.CONNECTED:
            raise PlaygroundError("Cannot call getPeers unless the client is connected to the server") 
        
        getPeersMsg = MessageData.GetMessageBuilder(playground.base.GetPeers)
        if getPeersMsg == None:
            raise Exception("Cannot find GetPeers definition")
        
        self.__peerCallbacks.append(callback)
        
        packetTrace(logger, getPeersMsg, "Sending to playground server")
        self.__protocol.transport.write(Packet.SerializeMessage(getPeersMsg))
        
    def __checkMibProtocolFreshness(self, addr):
        if not self.__mibProtocols.has_key(addr):
            return
        mibProt, lastAccess = self.__mibProtocols[addr]
        if time.time()-lastAccess > 2*60: # 2 minute timeout
            try:
                mibProt.transport.loseConnection()
            except Exception, e:
                self.reportException(e)
            del self.__mibProtocols[addr]
        else:
            Timer.callLater(2*60, lambda: self.__checkMibProtocolFreshness(addr))
        
    def sendMIB(self, addr, port, mib, args, callback, timeout=30):
        if addr == "server":
            if not self.__mibAuthInfo.has_key("server"):
                raise Exception("Not configured to query server for mib")
            return self.__protocol.sendMIB(mib, args, callback, timeout=timeout)
        else:
            if self.__mibProtocols.has_key(str(addr)):
                mibProt, lastAccess = self.__mibProtocols[str(addr)]
                if not mibProt.alive():
                    del self.__mibProtocols[str(addr)]
                else:
                    self.__mibProtocols[str(addr)] = (mibProt, time.time())
                    return mibProt.sendMIB(mib, args, callback, timeout=timeout)
            if not isinstance(addr, PlaygroundAddress):
                addr = PlaygroundAddress.FromString(addr)
            addrParts = str(addr).split(".")
            while addrParts:
                authAddr = ".".join(addrParts)
                if self.__mibAuthInfo.has_key(authAddr):
                    connType, privKey = self.__mibAuthInfo[authAddr]
                    prot = self.connect(SimpleMIBClientFactory(), addr, port, connType)
                    prot = prot.getApplicationLayer()
                    prot.setMIBServerAuthData(privKey)
                    self.__mibProtocols[str(addr)] = [prot, time.time()]
                    Timer.callLater(2*60, lambda: self.__checkMibProtocolFreshness(str(addr)))
                    return prot.sendMIB(mib, args, callback, timeout=timeout)
                addrParts.pop(-1)
            raise Exception("Not configured to get mib from " + str(addr))
        
    def buildProtocol(self, addr):
        self.__protocol = ClientBaseProtocol(self, self.__addr,
                                             connectionMadeCallback = self.__getChangeStateFunctor(self.ConnectionState.NEGOTIATING),
                                             connectionLostCallback = self.__getChangeStateFunctor(self.ConnectionState.DISCONNECTED))
        
        return self.__protocol
    
    def connectToChaperone(self, ipAddress, tcpPort, runReactor=True):
        """
        Connect to the playground server and start the Twisted reactor loop. If you need to
        connect to the server without starting the reactor, use this as any other Twisted factory
        """
        point = TCP4ClientEndpoint(reactor, ipAddress, tcpPort)
        point.connect(self)
        if runReactor: reactor.run()
        
    def runWhenConnected(self, f):
        """
        Store functors that are to be executed when the client succesfully
        connects to the playground server.
        
        Generally, it is when the client connects to the playground server that
        the system is generally thought of as "started"
        """
        if self.__connectionState != self.ConnectionState.CONNECTED:
            self.__waitForPlayground.append(f)
        else:
            Timer.callLater(0, f)
        
    def disconnectFromPlaygroundServer(self, stopReactor=False):
        if self.__protocol:
            self.__protocol.transport.loseConnection()
        if stopReactor: 
            reactor.disconnectAll()
            reactor.stop()
            
class ClientTransportMultiplexingProducer(object):
    def __init__(self):
        self.__producers = {}
        self.__minBacklogToClear = 0
        
    def signalRawWrite(self):
        if self.__minBacklogToClear:
            self.__minBacklogToClear
            if not self.__minBacklogToClear:
                self.resumeProducing()
        
    def registerProducer(self, producer, registeringTransport):
        if self.__producers.has_key(producer):
            raise Exception("Cannot double register a producer")
        self.__producers[producer] = registeringTransport
        
    def unregisterProducer(self, producer):
        del self.__producers[producer]
        
    def resumeProducing(self):
        for p in self.__producers.keys():
            ptransport = self.__producers[p]
            transportBacklog = ptransport and ptransport.productionBacklog() or 0
            if not transportBacklog: # no backlog on this producer's transport. Let it resume
                p.resumeProducing()
            else:
                if not self.__minBacklogToClear: # There was a backlog and we have no global backlog. Set it.
                    self.__minBacklogToClear = transportBacklog
                else: # minimize our wait 
                    self.__minBacklogToClear = min(self.__minBacklogToClear, transportBacklog)
        
    def pauseProducing(self):
        for p in self.__producers.keys(): p.pauseProducing()
        
    def stopProducing(self):
        for p in self.__producers.keys(): p.stopProducing()

class ClientBaseProtocol(SimpleMIBClientProtocol):
    def __init__(self, client, playgroundAddress, connectionMadeCallback, connectionLostCallback):
        SimpleMIBClientProtocol.__init__(self, client, playgroundAddress)
        self.__client = client
        self.__addr = playgroundAddress
        self.__connectionMade  = connectionMadeCallback
        self.__connectionLost = connectionLostCallback
        self.__transportProducer = ClientTransportMultiplexingProducer()
        
    def multiplexingProducer(self): return self.__transportProducer
        
    def connectionLost(self, reason=None):
        self.__connectionLost()
        """ clear circular connections """
        self.__client = None
        self.transport.unregisterProducer()
        
    def connectionMade(self):
        registerClientMsg = MessageData.GetMessageBuilder(playground.base.RegisterClient)
        if registerClientMsg == None:
            raise Exception("Cannot find RegisterClient definition")
        registerClientMsg["address"].setData(self.__addr.toString())
        packetBuffer = Packet.SerializeMessage(registerClientMsg)
        self.transport.registerProducer(self.__transportProducer, True)
        self.__connectionMade()
        
        packetTrace(logger, registerClientMsg, "Sending registration to playground server")
        self.transport.write(packetBuffer)
        
    def messageReceived(self, msg):
        packetTrace(logger, msg, "Msg received by client base protocol. Passing to handler")
        
        try:
            success = self.handleMessage(self, msg)
            if not success:
                success = self.__client.handleMessage(self, msg)
            if not success:
                self.__client.reportException(NetworkError.NoSuchMessageHandler(msg))
        except Exception, e:
            self.__client.reportException(e)