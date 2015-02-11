'''
Created on Oct 23, 2013

@author: sethjn
'''

from playground.config import GlobalPlaygroundConfigData
from playground.network.message import MessageData

from playground.network.common import SimpleMessageHandler, Protocol, Packet, PlaygroundAddress, PlaygroundAddressPair
from playground.network.common import MIBAddressMixin
from playground.network.common import Error as NetworkError

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
            self.__types[t.strip()] = (self.__loadFactoryModule(clientFactory), self.__loadFactoryModule(serverFactory))
            
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
        return self.__types[connectionType][0]
    
    def getServerFactory(self, connectionType):
        if not self.__types.has_key(connectionType):
            raise Exception("No Playground Connection Type: %s" % connectionType)
        return self.__types[connectionType][1]
ConnectionTypeFactoryInstance = ConnectionTypeFactory(configData)

class ClientBase(Factory, SimpleMessageHandler, MIBAddressMixin, ErrorHandlingMixin):
    """
    ClientBase represents the basic connection to the Playground network. To
    build a Playground Application, one creates a Server Factory/Protocol that plugs into
    the ClientBase using installClientServer and then creates a client factory/Protocol
    that connects to the installed client server over PLAYGROUND using the
    openClientConnection method.
    
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
        self.__servers = {}
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
        self.registerMessageHandler(playground.base.ClientToClientMessage, Client2ClientHandler(self.__servers, self.__closeConnection))
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
            self.installClientServer(self.__mibServer, port, connType)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.Mibs.CURRENT_STATE, self.__mibResponder)
            self.registerLocalMIB(self.Mibs.PORTS_IN_USE, self.__mibResponder)
        
    def __mibResponder(self, mib, args):
        if mib.endswith(self.Mibs.CURRENT_STATE):
            return [str(self.__connectionState)]
        elif mib.endswith(self.Mibs.PORTS_IN_USE):
            portData = []
            for port in self.__servers.keys():
                server, connections = self.__servers[port]
                if server:
                    portData.append("Port %d: %s" % (port, str(server)))
                    for destAddr, destPort in connections.keys():
                        appProt = connections[(destAddr, destPort)].getApplicationLayer()
                        portData.append("%d serving %s protocol to %s/%d" % (port, str(appProt), destAddr, destPort))
                else:
                    for destAddr, destPort in connections.keys():
                        appProt = connections[(destAddr, destPort)].getApplicationLayer()
                        portData.append("Src port %d open %s protocol to %s/%d" % (port, str(appProt), destAddr, destPort))
            return portData
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
        dstKey = (dstAddr.toString(), dstPort)
        
        if self.__servers.has_key(srcPort) and self.__servers[srcPort][1].has_key(dstKey):
            protocolToClose = self.__servers[srcPort][1][dstKey]
            protocolToClose.connectionLost(reason)
            del self.__servers[srcPort][1][dstKey]
            if self.__servers[srcPort][0] == None:
                # this is an outgoing connection. Delete srcPort
                # disable mib address if we configured it
                if self.__mibAddressesConfigured.has_key(srcPort):
                    self.__mibAddressesConfigured[srcPort].disableMIBAddress()
                    del self.__mibAddressesConfigured[srcPort]
                del self.__servers[srcPort]
        
    def getAddress(self): return PlaygroundAddress.FromString(self.__addr.toString())
        
    def getPlaygroundState(self): return self.__connectionState
    
    def installClientServer(self, protFactory, port, connectionType=None):
        """
        Install a client application server on a port for this client base.
        Incoming packets not previously identified will produce a new protocol
        """
        if self.__servers.has_key(port):
            raise Exception("Server already exists on port %d" % port)
        if connectionType:
            clientFactoryStack = ConnectionTypeFactoryInstance.getServerFactory(connectionType)
            protFactory = clientFactoryStack(protFactory)
        if self.__mibServer and not protFactory.MIBAddressEnabled():
            self.__mibAddressesConfigured[port] = protFactory
            self.runWhenConnected(lambda: protFactory.configureMIBAddress("ClientServer_%d" % port, self, self.__mibServer))
        self.__servers[port] = (protFactory, {})
        
    def closeClientServer(self, port):
        if not self.__servers.has_key(port):
            raise Exception("No server on port %d" % port)
        if self.__mibAddressesConfigured.has_key(port):
            self.__mibAddressesConfigured[port].disableMIBAddress()
            del self.__mibAddressesConfigured[port]
        del self.__servers[port]
        
    def openClientConnection(self, protFactory, dstAddr, dstPort, connectionType=None):
        """
        Open a connection to another Playground Client (server). 'protFactory' is
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
            if not self.__servers.has_key(srcPort):
                # We don't need a factory on this port because it will not receive 
                # incoming connections.
                srcAddrPair = PlaygroundAddressPair(self.__addr, srcPort)
                dstAddrPair = PlaygroundAddressPair(dstAddr, dstPort)
                transport = ClientApplicationTransport(self.__protocol.transport, srcAddrPair, dstAddrPair, self.__closeConnection)
                prot = protFactory.buildProtocol(srcAddrPair)
                
                if self.__mibServer and not protFactory.MIBAddressEnabled():
                    key = "%s_(%d)" % (str(dstAddr), dstPort)
                    protFactory.configureMIBAddress("ClientConnection_to_"+key, self, self.__mibServer)
                    self.__mibAddressesConfigured[srcPort] = protFactory
                self.__servers[srcPort] = (None, {(dstAddr.toString(), dstPort): prot})
                
                prot.makeConnection(transport)
                return prot
        raise PlaygroundError("No available port between 1000,65536!")
        
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
            self.__protocol.callLater(2*60, lambda: self.__checkMibProtocolFreshness(addr))
        
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
                    prot = self.openClientConnection(SimpleMIBClientFactory(), addr, port, connType)
                    prot = prot.getApplicationLayer()
                    prot.setMIBServerAuthData(privKey)
                    self.__mibProtocols[str(addr)] = [prot, time.time()]
                    self.__protocol.callLater(2*60, lambda: self.__checkMibProtocolFreshness(str(addr)))
                    return prot.sendMIB(mib, args, callback, timeout=timeout)
                addrParts.pop(-1)
            raise Exception("Not configured to get mib from " + str(addr))
        
    def buildProtocol(self, addr):
        self.__protocol = ClientBaseProtocol(self, self.__addr,
                                             connectionMadeCallback = self.__getChangeStateFunctor(self.ConnectionState.NEGOTIATING),
                                             connectionLostCallback = self.__getChangeStateFunctor(self.ConnectionState.DISCONNECTED))
        
        return self.__protocol
    
    def connectToPlaygroundServer(self, ipAddress, tcpPort, runReactor=True):
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
            reactor.callLater(0, f)
        
    def disconnectFromPlaygroundServer(self, stopReactor=False):
        if self.__protocol:
            self.__protocol.transport.loseConnection()
        if stopReactor: reactor.stop()

class ClientBaseProtocol(SimpleMIBClientProtocol):
    def __init__(self, client, playgroundAddress, connectionMadeCallback, connectionLostCallback):
        SimpleMIBClientProtocol.__init__(self, client, playgroundAddress)
        self.__client = client
        self.__addr = playgroundAddress
        self.__connectionMade  = connectionMadeCallback
        self.__connectionLost = connectionLostCallback
        
    def connectionLost(self, reason=None):
        self.__connectionLost()
        """ clear circular connections """
        self.__client = None
        
    def connectionMade(self):
        registerClientMsg = MessageData.GetMessageBuilder(playground.base.RegisterClient)
        if registerClientMsg == None:
            raise Exception("Cannot find RegisterClient definition")
        registerClientMsg["address"].setData(self.__addr.toString())
        packetBuffer = Packet.SerializeMessage(registerClientMsg)
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