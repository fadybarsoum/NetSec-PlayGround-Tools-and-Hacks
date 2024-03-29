'''
Overview:

Service has two ports. One for data, and one for
control messages. Data is purely pass-through. It
does no processing whatsoever, except to route the
data to the correct app, or from an app to the
Chaperone. It does not do any checking to make sure
that outgoing packets have the right src data.

The control port accepts reservation data. Reservation
data identifies a data channel for an outgoing port,
or identifying a data channel for receiving incoming
data.

           [   G2G Service   ]
[APP] ---> [   G2G Control   ]
[APP] <--> [Service|Transport] <--> [Chaperone]

App:
  openG2G(dstAddress, dstPort)
    - Creates an outgoing protocol that serializes g2g messages.
    - Sends a message to Service control protocol reserving an outgoing port
    - Gets a callback. At this point, confirms the connection.
  write(data):
    - Locally creates the g2g message
    - Sends to service data port
    - Service sends without deserializing
    
  listenG2G(srcPort)


App creating outbound connection:
  Sends Gate2GateReservation
    ResvType = Connect
    IpCallback
    TcpCallback
  
  G2GService reserves a playground srcPort
    
  G2GService calls back on IpCallback, TcpCallback
  
  If App doesn't hear back within a timeout, is a failure.
    
  Data from Chaperone comes in to G2GService
    Lookup key (srcPort, dstPort, dstAddress) -> G2GServiceProtocol
    
  G2GService sends data back to app
  
App creating listener:
  Sends Gate2GateReverseReservation
    SrcPort
    
  G2GService reserves requested SrcPort
  
  G2GService sends back Gate2GateReserved message with just SrcPort
  
  Data from Chaperone comes in to G2GService
    Lookup key (srcPort, dstPort, dstAddress)
      if no match, but match srcPort
        G2GService sends back success message with all four parameters
    Send data 

Modified: Feb 25, 2017 by fml
'''
import logging, time

from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint, connectProtocol
from twisted.internet.protocol import Protocol, Factory, connectionDone

from playground.error import GetErrorReporter

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.playground.base import Gate2GateMessage, Gate2GateReservation
from playground.network.message.definitions.playground.base import Gate2GateResponse
from playground.network.message.definitions.playground.base import RegisterGate

from ChaperoneProtocol import ChaperoneProtocol, ListGrabber
from ChaperoneDemuxer import ChaperoneDemuxer, Port
from ConnectionData import ConnectionData
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

class SingleConnectionComponents(object):
    def __init__(self, reactor, revAddr, revPort, serviceProtocol, chaperoneProtocol):
        self.reactor = reactor
        self.revAddr = revAddr
        self.revPort = revPort
        self.serviceProtocol = serviceProtocol
        self.chaperoneProtocol = chaperoneProtocol

class ServiceControlProtocol(Protocol):
    
    def __init__(self):
        self.__buffer = ""
        self.__responsiblePorts = set([])
        
    def connectionLost(self, reason=None):
        for port in self.__responsiblePorts:
            self.factory.clearReservation(port)
        
    def dataReceived(self, data):
        self.__buffer += data
        try:
            g2gMessage, bytesUsed = Gate2GateReservation.Deserialize(self.__buffer)
        except Exception, e:
            errReporter.warning("Expected G2GReservation failed.", exception=e)
            return
        if not g2gMessage: 
            errReporter.warning("Expected G2GReservation returned nothing.")
            return
        self.__buffer = self.__buffer[bytesUsed:]
        
        logger.info("Gate service received G2G Reservation %s %d from %s" % 
                    (g2gMessage.resvType, g2gMessage.resvId, self.transport.getPeer()))
        g2gResponse = Gate2GateResponse(resvType = g2gMessage.resvType, resvId = g2gMessage.resvId, respType = Gate2GateResponse.RESP_TYPE_INITIAL, srcAddr = self.factory.gateAddress())
        if g2gMessage.resvType == Gate2GateReservation.RESV_TYPE_CONNECT:
            result, port, msg = self.factory.registerConnection(g2gMessage.resvId, g2gMessage.dstAddr, g2gMessage.dstPort, self, g2gMessage.callbackAddr, g2gMessage.callbackPort)
            g2gResponse.dstAddr = g2gMessage.dstAddr
            g2gResponse.dstPort = g2gMessage.dstPort
            g2gResponse.srcPort = port
            g2gResponse.success = result
            g2gResponse.msg = msg
        elif g2gMessage.resvType == Gate2GateReservation.RESV_TYPE_LISTEN:
            result, msg = self.factory.registerListener(g2gMessage.resvId, g2gMessage.srcPort, self, g2gMessage.callbackAddr, g2gMessage.callbackPort)
            g2gResponse.srcPort = g2gMessage.srcPort
            g2gResponse.success = result
            g2gResponse.msg = msg
        else:
            g2gResponse.srcPort = 0
            g2gResponse.msg = "Error, unknown reservation type %s" % g2gMessage.resvType
            g2gResponse.success = False 
        
        if g2gResponse.success:
            self.__responsiblePorts.add(g2gResponse.srcPort)
   
        self.transport.write(g2gResponse.__serialize__())
        if self.__buffer: self.dataReceived("")
        
    def sendNewConnection(self, resvId, dstAddr, dstPort, connPort):
        logger.info("Spawning new connection for listener with resvId %d for %s %d on local TCP port %d" % 
                    (resvId, dstAddr, dstPort, connPort))
        g2gResponse = Gate2GateResponse(resvType = Gate2GateReservation.RESV_TYPE_LISTEN, resvId=resvId, respType = Gate2GateResponse.RESP_TYPE_CALLBACK, dstAddr = dstAddr, dstPort = dstPort, connPort = connPort, success = True, msg = "Spawn")
        self.transport.write(g2gResponse.__serialize__())
        
    def completeConnection(self, resvId, connPort):
        logger.info("Completing callback circuit for outbound connect with resvId %d on local TCP port %d" % 
                    (resvId, connPort))
        g2gResponse = Gate2GateResponse(resvType = Gate2GateReservation.RESV_TYPE_CONNECT, resvId=resvId, respType = Gate2GateResponse.RESP_TYPE_CALLBACK, connPort = connPort, success = True, msg = "Connect Complete")
        self.transport.write(g2gResponse.__serialize__())

class G2GDataProtocol(Protocol):
    def __init__(self, closer, chaperoneWriter):
        self.closer = closer
        self.chaperoneWriter = chaperoneWriter
        
    def dataReceived(self, data):
        self.chaperoneWriter(data)
        
    def connectionLost(self, reason=connectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.closer()
        
class GateDataPort(Port):
    class ConnectionData(Port.ConnectionData):
        def __init__(self):
            super(GateDataPort.ConnectionData,self).__init__()
            self.deferred = None
            self.endpoint = None
            
    def __init__(self, portNum, portType, connComponents):
        super(GateDataPort, self).__init__(portNum, portType)
        self._connComponents = connComponents
    
    def _createDataProtocol(self, dstAddr, dstPort, closer):
        return G2GDataProtocol(closer, lambda data: self._connComponents.chaperoneProtocol.send(self._portNum, dstAddr, dstPort, data))

class IncomingPort(GateDataPort):
    def __init__(self, resvId, num, connComponents):
        GateDataPort.__init__(self, num, Port.PORT_TYPE_INCOMING, connComponents)
        self.__resvId = resvId
        
    def __revConnected(self, result, resvId, dstAddr, dstPort, point, gConn):
        connectionData = self._connections[(dstAddr, dstPort)]
        spawnD = connectionData.deferred
        
        self._connComponents.serviceProtocol.sendNewConnection(resvId, dstAddr, dstPort, gConn.transport.getHost().port)
        
        connectionData.protocol = gConn
        connectionData.encpoint = point
        connectionData.deferred = None
        spawnD.callback("connected")
        
    def __revFailed(self, failure, dstAddr, dstPort):
        try:
            connectionData = self.__connections[(dstAddr, dstPort)]
            connectionData.deferred.errback(failure)
        except:
            pass
        try:
            del self._connections[(dstAddr, dstPort)]
        except:
            pass
        
    def clearConnection(self, dstAddr, dstPort):
        if self._connections.has_key((dstAddr, dstPort)):
            logger.info("Clearing server connection to %s:%s" % (dstAddr, dstPort))
            del self._connections[(dstAddr, dstPort)]
        else:
            logger.debug("Cannot clear connection %s %s, does not exist" % (dstAddr, dstPort))
        
    def spawnNewConnection(self, dstAddr, dstPort):
        if self._connections.has_key((dstAddr, dstPort)):
            d = Deferred()
            self._connComponents.reactor.callLater(0, d.errback, Failure("Already have a connection for this destination"))
            return d
        logger.info("Port map for %d (resvId %d) spawning new connection from %s %d" % 
                    (self._portNum, self.__resvId, dstAddr, dstPort))
        gConn = self._createDataProtocol(dstAddr, dstPort, lambda: self.clearConnection(dstAddr, dstPort))
        point = TCP4ClientEndpoint(self._connComponents.reactor, 
                                   self._connComponents.revAddr, self._connComponents.revPort)
        
        spawnD = Deferred()
        d = connectProtocol(point, gConn)
        
        connectionData = self.ConnectionData()
        connectionData.deferred = spawnD
        
        self._connections[(dstAddr, dstPort)] = connectionData
        d.addCallback(self.__revConnected, self.__resvId, dstAddr, dstPort, point, gConn)
        d.addErrback(self.__revFailed, dstAddr, dstPort)
        
        return spawnD
    
class OutgoingPort(GateDataPort):
    def __init__(self, resvId, num, dstAddr, dstPort, connComponents, closer): 
        GateDataPort.__init__(self, num, Port.PORT_TYPE_OUTGOING, connComponents)
        logger.info("Port map for %d (resvId %d) connecting to outbound %s %d using callback addr %s:%d" %
                    (num, resvId, dstAddr, dstPort, connComponents.revAddr, connComponents.revPort))
        gConn = self._createDataProtocol(dstAddr, dstPort, closer)
        point = TCP4ClientEndpoint(connComponents.reactor, 
                                   connComponents.revAddr, connComponents.revPort)
        connectionData = self.ConnectionData()
        connectionData.endpoint = point
        connectionData.protocol = gConn
        self._connections[(dstAddr, dstPort)] = connectionData
        d = connectProtocol(point, gConn)
        d.addCallback(self.__connectComplete, resvId, gConn)
        
    def __connectComplete(self, result, resvId, gConn):
        self._connComponents.serviceProtocol.completeConnection(resvId, gConn.transport.getHost().port)
        
        
class Service(Factory, ChaperoneDemuxer):
    protocol = ServiceControlProtocol
    
    def __init__(self, reactor, gateAddr):
        ChaperoneDemuxer.__init__(self)
        self.__reactor = reactor
        self.__gateAddr = gateAddr
        self.__chaperoneProtocol = ChaperoneProtocol(gateAddr, self)
        
        
    def gateAddress(self):
        return self.__gateAddr

    def registerConnection(self, resvId, dstAddr, dstPort, controller, callbackAddr, callbackPort):
        components = SingleConnectionComponents(self.__reactor, callbackAddr, callbackPort, controller, self.__chaperoneProtocol)
        srcPort = self.getFreeSrcPort()
        port = OutgoingPort(resvId, srcPort, dstAddr, dstPort, components, lambda: self.clearReservation(srcPort))
        self.reservePort(srcPort, port)
        logger.info("Gate Service registering new outbound connection to %s %d with srcport %d" %
                    (dstAddr, dstPort, srcPort))
        #"open to callback"
        #"use g2gdataprotocol with playgroundTransport"
        return True, srcPort, "Success"
        
    def registerListener(self, resvId, srcPort, controller, callbackAddr, callbackPort):
        if self.portInUse(srcPort):
            logger.error("Gate service could not register port %d because it is already in use" % srcPort)
            return False, "Port already in use"
        components = SingleConnectionComponents(self.__reactor, callbackAddr, callbackPort, controller, self.__chaperoneProtocol)
        port = IncomingPort(resvId, srcPort, components)
        self.reservePort(srcPort, port)
        logger.info("Gate Service registering new listener on port %d" % srcPort)
        return True, "Success"
    
    def start(self, result, chaperoneEndpoint, gatePort):
        self.__chaperoneEndpoint = chaperoneEndpoint
        self.__gateEndpoint = TCP4ServerEndpoint(self.__reactor, gatePort)
        self.__gateEndpoint.listen(self)
        logger.info("Gate Service listening on TCP port %d" % gatePort)
        
    def handleDataNoConnection(self, srcAddress, srcPort, dstPort, connectionData, fullPacket):
        """ OLD WAY
        if connectionData.endpoint == None:
            if self.__portMappings[dstPort].isListening():
                logger.info("Spawning new connection from %s:%d to port %s" % (srcAddress, srcPort, dstPort))
                self.__portMappings[dstPort].spawnNewConnection(srcAddress, srcPort)
                connectionData = self.__portMappings[dstPort].getConnectionData(srcAddress, srcPort)
        """
                
        if connectionData.endpoint == None:
            errReporter.warning("Data received for %s:%d, but no connection" % (srcAddress, srcPort))
            return
        elif connectionData.deferred:         
            logger.debug("Data received for port %d, but port not ready. Buffering" % dstPort)       
            # TODO: replace string with parameter
            d = connectionData.deferred # we're not really connected yet
            d.addCallback(self.__sendPendingData, dstPort, srcAddress, srcPort, fullPacket)
        else:
            logger.debug("Unknown Error")
            
    def handleData(self, srcAddress, srcPort, dstPort, connectionData, fullPacket):
            logger.debug("Gate service forwarding %d bytes for srcPort %d" % (len(fullPacket), srcPort))
            connectionData.protocol.transport.write(fullPacket)
            
    def __sendPendingData(self, result, dstPort, srcAddress, srcPort, data):
        if not self.__portMappings[dstPort].isConnectedTo(srcAddress, srcPort):
            return
        connectionData = self.__portMappings[dstPort].getConnectionData(srcAddress, srcPort)
        if not connectionData.endpoint or connectionData.deferred:
            return
        logger.debug("Gate service forwarding %d buffered bytes for srcPort %d" % (len(data), srcPort))
        connectionData.protocol.transport.write(data)
        
    @classmethod
    def CreateFromConfig(cls, reactor, configKey=None, defaultKey="default"):
        g2gConnect = ConnectionData.CreateFromConfig(configKey, defaultKey)
        cls.Create(reactor, g2gConnect)
        
    @classmethod
    def Create(cls, reactor, g2gConnect, servclass=None):
        if not servclass:
            servclass = cls
        gateService = servclass(reactor, g2gConnect.playgroundAddr)
        point = TCP4ClientEndpoint(reactor, g2gConnect.chaperoneAddr, g2gConnect.chaperonePort)
        d = connectProtocol(point, gateService.__chaperoneProtocol)
        d.addCallback(gateService.start, point, g2gConnect.gatePort)
        
class LGService(Service):
    def __init__(self, reactor, gateAddr):
        ChaperoneDemuxer.__init__(self)
        self.__reactor = reactor
        self.__gateAddr = gateAddr
        self.__chaperoneProtocol = ListGrabber(gateAddr, self)
        self.grabber = self.__chaperoneProtocol

    @classmethod
    def CreateFromConfig(cls, reactor, configKey=None, defaultKey="default"):
        g2gConnect = ConnectionData.CreateFromConfig(configKey, defaultKey)
        return cls.Create(reactor, g2gConnect)

    @classmethod
    def Create(cls, reactor, g2gConnect):
        gateService = LGService(reactor, g2gConnect.playgroundAddr)
        point = TCP4ClientEndpoint(reactor, g2gConnect.chaperoneAddr, g2gConnect.chaperonePort)
        d = connectProtocol(point, gateService.__chaperoneProtocol)
        d.addCallback(gateService.start, point, g2gConnect.gatePort)
        return gateService
        
class HPService(Service):
    def __init__(self, reactor, gateAddr):
        Service.__init__(self, reactor, gateAddr)
        try:
            filename = "./hp/"+time.strftime("%Y_%m_%d %H_%M_%S ")+str(gateAddr)+" hp.txt"
            self.outputfile = open(filename, "a")
            print "Saving packets to file: ", filename
        except Exception, e:
            print "Couldn't open a file: ", e
    def demux(self, srcAddress, srcPort, dstPort, data, fragInfo=None):
        try:
            self.outputfile.write("[&#TS> %s] %s:%s -> %s:%s [&#MD>\n%s\n<&#MD]\n" % (time.time(), srcAddress,srcPort, self.gateAddress(), dstPort, data))
            self.outputfile.flush()
        except:
            print("Couldn't save packet to file")
        Service.demux(self, srcAddress, srcPort, 9876, data, fragInfo)

    @classmethod
    def Create(cls, reactor, g2gConnect):
        Service.Create(reactor, g2gConnect, HPService)

            