'''
Created on Aug 20, 2013

@author: sethjn
'''
#from playground.network.common import Protocol, SimpleMessageHandler, MIBServerProtocol
#from playground.network.common import MIBServerImpl, StandardMIBProtocolAuthenticationMixin
from playground.network.common import Error as NetworkError
from playground.network.common import SimpleMessageHandler
from playground.network.common.Packet import PacketStorage, IterateMessages
from playground.error import GetErrorReporter
from playground.network.message.definitions import playground
#from playground.error import ErrorHandlingMixin
#from playground.crypto import CertificateDatabase

from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor

from playground.network.chaperone.ChaperoneMessageHandlers import *
from ChaperoneInterceptHandler import encapsulatedMessageHandler, messageInterceptor, ChaperoneInterceptHandler

import random, os, array, copy

errReporter = GetErrorReporter(__name__)

class BacklogProducer(object):
    def __init__(self):
        self.backlog = []
        self.producing = False
        self.paused = False
        
    def init(self, transport):
        self.transport = transport
        transport.registerProducer(self, streaming=True)
        self.resumeProducing()
        
    def close(self):
        self.transport = None
        
    def resumeProducing(self):
        self.paused = False
        self.producing = True
        while not self.paused and self.backlog:
            msg = self.backlog.pop(0)
            self.transport.write(msg)
        if not self.backlog:
            self.producing = False
        
    def pauseProducing(self):
        self.paused = True
        
    def stopProducing(self):
        pass
    
    def write(self, msg):
        self.backlog.append(msg)
        if not self.producing and not self.paused:
            self.resumeProducing()

class ChaperoneProtocol(Protocol):
    '''
    The protocol class for the PLAYGROUND central server.
    '''
    def __init__(self, server):
        '''
        Creates an instance of the ChaerponeProtocol class with the
        server as the argument.
        '''
        #Protocol.__init__(self)
        #MIBServerProtocol.__init__(self, server, "ChaperoneServer")
        self.server = server
        self.__addressData = {}
        self.__producer = BacklogProducer()
        self.__packetStorage = PacketStorage()
        self.__dispatcher = SimpleMessageHandler()
        self.__interceptHandler = ChaperoneInterceptHandler()
        self.__interceptHandler.registerMessages(self.__dispatcher)
        
    def dataReceived(self, buf):
        self.__packetStorage.update(buf)
        for msg in IterateMessages(self.__packetStorage):
            self.messageReceived(msg)
        
    def messageReceived(self, message):
        """
        Handles an incoming message. The message handling is deferred to the
        Chaperone class.
        """
        success = self.__dispatcher.handleMessage(self, message)
        if not success:
            success = self.server.handleMessage(self, message)
        if not success:
            errReporter.error("Unexpected message received", exception=NetworkError.NoSuchMessageHandler(message))
            
    def connectionMade(self):
        #MIBServerProtocol.connectionMade(self)
        self.__producer.init(self.transport)
            
    def connectionLost(self, reason=None):
        self.server.connectionLost(self, reason)
        """ Clear circular connections """
        self.server = None
        self.__producer.close()
        self.__interceptHandler.close()
        
    def producerWrite(self, msg):
        self.__producer.write(msg)
        
class ServerStatistics(object):
    def __init__(self):
        self.bytesRouted = 0
        self.packetsRouted = 0
        self.bytesCorrupted = 0
        self.packetsCorrupted = 0
        self.packetsDropped = 0
        self.zeroTime = time.time()
        
    def elapsed(self):
        return time.time()-self.zeroTime
        
class Chaperone(Factory):#, MIBServerImpl, SimpleMessageHandler, 
                       #StandardMIBProtocolAuthenticationMixin, ErrorHandlingMixin):
    """
    The factory class for the Chaperone. You can start the server using
    the provided run() method which invokes the Twisted reactor. Or, alternatively,
    you can pass this class (which is a Twisted Factory) to the Twisted reactor
    in a customized fashion.
    """
    MAX_BYTES_BEFORE_OVERFLOW = 2**64
    
    CURRENT_CONNECTIONS_MIB = ("playground.network.server","CurrentConnections")
    
    protocol = ChaperoneProtocol
    def __init__(self, ipAddress, port):
        #SimpleMessageHandler.__init__(self)
        #MIBServerImpl.__init__(self)
        #db = CertificateDatabase.GetDatabase()
        #self.loadAuthData(db.loadX509("MIBServer_signed.cert"))
        
        self.__ipAddress = ipAddress
        self.__tcpPort = port
        self.__addressToConnection = {}
        self.__connectionToAddress = {}
        self.__dispatcher = SimpleMessageHandler()
        self.setNetworkLossRate(0, 0, 0)
        self.setNetworkErrorRate(0, 0, 0)
        
        gate2GateHandler = Gate2GateHandler(self, self.__addressToConnection)
        gate2GateHandler.registerAdditionalHandler(messageInterceptor)
        gate2GateHandler.registerAdditionalHandler(self.__networkErrorPacketHandler)
        
        """ Register all message handlers """
        self.__dispatcher.registerMessageHandler(
                                    playground.base.RegisterGate, 
                                    RegisterGateHandler(self.__registerAddressProtocolPair))
        self.__dispatcher.registerMessageHandler(
                                    playground.base.UnregisterGate,
                                    UnregisterGateHandler(self.__unregisterAddressProtocolPair))
        self.__dispatcher.registerMessageHandler(
                                    playground.base.Gate2GateMessage,
                                    gate2GateHandler)
        self.__dispatcher.registerMessageHandler(
                                    playground.base.GetPeers,
                                    GetPeersHandler(self, self.__addressToConnection))
        self.__dispatcher.registerMessageHandler(playground.intercept.EncapsulatedC2C, encapsulatedMessageHandler)
        #self.__loadMibs()
        self.__resetStatistics()
        
    def handleMessage(self, protocol, message):
        return self.__dispatcher.handleMessage(protocol, message)
        
    def __resetStatistics(self):
        self.__statistics = ServerStatistics()
        
    """def __loadMibs(self):
        MIBServerImpl.registerMIB(self, self.CURRENT_CONNECTIONS_MIB[0], self.CURRENT_CONNECTIONS_MIB[1], self.__currentConnections)
        
    def __currentConnections(self, mib, args):
        connections = []
        for address in self.__addressToConnection.keys():
            for protocol in self.__addressToConnection[address]:
                transport = protocol.transport
                connections.append("%s <==> %s" % (str(address), str(transport.getPeer())))
        return connections"""
        
    def __computeErrorBytes(self):
        self.__byteCounter = 0
        minErrorsInNBytes, maxErrorsInNBytes, nBytes = self.__errorRate
        actualErrors = random.randint(minErrorsInNBytes, maxErrorsInNBytes)
        self.__errorBytes = []
        errorByteGenerator = xrange(nBytes)
        for i in range(actualErrors):
            self.__errorBytes.append(random.choice(errorByteGenerator))
        self.__errorBytes.sort()
        #print "computed error bytes count", len(self.__errorBytes)
            
    def __computeLostPackets(self):
        self.__pktCounter = 0
        minLostInNPkts, maxLostInNPkts, pkts = self.__lossRate
        actualLosses = random.randint(minLostInNPkts, maxLostInNPkts)
        lossPktGenerator = xrange(pkts)
        self.__lostPackets = []
        for i in range(actualLosses):
            self.__lostPackets.append(random.choice(lossPktGenerator))
        
    def __registerAddressProtocolPair(self, address, protocol):
        if not self.__addressToConnection.has_key(address):
            self.__addressToConnection[address] = set([])
        self.__addressToConnection[address].add(protocol)
        self.__connectionToAddress[protocol].add(address)
        
        """ This function returns false if something goes wrong...
        currently there is nothing to go wrong so always return True"""
        return True
    
    def __unregisterAddressProtocolPair(self, address, protocol):
        if self.__addressToConnection.has_key(address) and protocol in self.__addressToConnection[address]:
            self.__addressToConnection[address].remove(protocol)
            if self.__connectionToAddress.has_key(protocol) and address in self.__connectionToAddress[protocol]:
                self.__connectionToAddress[protocol].remove(address)
            else:
                errReporter.error("The protocol was associated with the address, but not the other way around!")
            
            """ Remove the entry for the address if there are no more protocols associated with it """
            """ We don't do the same thing with protocol... the protocol remains in the table until """
            """ the connection is lost """
            if len(self.__addressToConnection[address]) == 0:
                del self.__addressToConnection[address]
            return True
        return False
    
    def __networkErrorPacketHandler(self, serializedMessage, originalMessage):
        if self.__lossRate[2] > 0:
            curPacket = self.__pktCounter
            self.__pktCounter += 1
            if self.__pktCounter == self.__lossRate[2]:
                self.__computeLostPackets()
            elif self.__pktCounter > self.__lossRate[2]:
                raise Exception("Shouldn't happen")
            if curPacket in self.__lostPackets:
                #print "Dropping current packet"
                self.updateStatistics(len(serializedMessage), 1, 0, 0, 1)
                return ""
        
        bytesCorrupted = 0
        if self.__errorRate[2] > 0:
            #print "computing byte errors. Byte counter", self.__byteCounter
            messageArray = array.array('B', serializedMessage)
            byteIndex = 0
            while byteIndex < len(messageArray):
                # len(messageArray)-byteIndex is how many message bytes are left in this message
                # self.__errorRate[2] - self.__errorRate[2] - self.__bytecounter are how many bytes are left in this period
                bytesToCorrupt = min(len(messageArray)-byteIndex, self.__errorRate[2] - self.__byteCounter)
                
                # while we have error bytes and they're inside our number of bytes to corrupt
                while self.__errorBytes and self.__errorBytes[0] < (self.__byteCounter + bytesToCorrupt):
                    byteToCorrupt = self.__errorBytes.pop(0) - self.__byteCounter
                    #print "Corrupting byte %d in packet chunk of len %d" % (byteToCorrupt, len(messageArray)-byteIndex)
                    messageArray[byteToCorrupt] ^= 0xff
                    bytesCorrupted += 1
                self.__byteCounter += bytesToCorrupt
                byteIndex += bytesToCorrupt
                if self.__byteCounter == self.__errorRate[2]:
                    #if self.__errorBytes:
                    #    print "oddly, we're recomputing bytes before finished.", len(self.__errorBytes)
                    self.__computeErrorBytes()
                elif self.__byteCounter > self.__errorRate[2]:
                    raise Exception("Shouldn't happen")
            serializedMessage = messageArray.tostring()
        packetCorrupted = bytesCorrupted > 0 and 1 or 0
        self.updateStatistics(len(serializedMessage), 1, bytesCorrupted, packetCorrupted, 0)
        return serializedMessage
    
    
    def setNetworkErrorRate(self, minErrorsInN, maxErrorsInN, n):
        self.__errorRate = (minErrorsInN, maxErrorsInN, n)
        self.__computeErrorBytes()
        
    def setNetworkLossRate(self, minLossInN, maxLossInN, n):
        self.__lossRate = (minLossInN, maxLossInN, n)
        self.__computeLostPackets()
        
    def updateStatistics(self, bytes, packets, errorBytes, corruptedPackets, droppedPackets):
        if self.__statistics.bytesRouted + bytes > self.MAX_BYTES_BEFORE_OVERFLOW:
            self.__resetStatistics()
        self.__statistics.bytesRouted += bytes
        self.__statistics.packetsRouted += packets
        self.__statistics.bytesCorrupted += errorBytes
        self.__statistics.packetsDropped += droppedPackets
        self.__statistics.packetsCorrupted += corruptedPackets
        
    def statistics(self):
        return copy.copy(self.__statistics)
        
    def buildProtocol(self, address):
        newProtocol = ChaperoneProtocol(self)
        self.__connectionToAddress[newProtocol] = set([])
        return newProtocol
    
    def connectionLost(self, protocol, reason=None):
        """
        Report that a protocol is no longer connected. Reason is not currently used.
        """
        if self.__connectionToAddress.has_key(protocol):
            """ Python sets cannot change during for loop iteration. Use while not empty instead """
            while len(self.__connectionToAddress[protocol]) > 0:
                """ Sets don't have a "peak" method... hackingly use "iter" to get one element """
                address = self.__connectionToAddress[protocol].__iter__().next()
                self.__unregisterAddressProtocolPair(address, protocol)
            del self.__connectionToAddress[protocol]
        
    def callLater(self, delay, cb):
        reactor.callLater(delay, cb)
        
    def run(self):
        endpoint = TCP4ServerEndpoint(reactor, self.__tcpPort)
        endpoint.listen(self)
        reactor.run()
        
    def stop(self):
        reactor.stop()
