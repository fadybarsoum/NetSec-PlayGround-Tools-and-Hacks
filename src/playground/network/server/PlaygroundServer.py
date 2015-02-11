'''
Created on Aug 20, 2013

@author: sethjn
'''
from playground.network.common import Protocol, SimpleMessageHandler, MIBServerProtocol
from playground.network.common import MIBServerImpl, StandardMIBProtocolAuthenticationMixin
from playground.network.common import Error as NetworkError
from playground.network.message.definitions import playground
from playground.error import ErrorHandlingMixin
from playground.crypto import CertificateDatabase

from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor

from ServerMessageHandlers import *

import random, os

class PlaygroundServerProtocol(MIBServerProtocol):
    '''
    The protocol class for the PLAYGROUND central server.
    '''
    def __init__(self, server):
        '''
        Creates an instance of the PlaygroundServerProtocol class with the
        server as the argument.
        '''
        Protocol.__init__(self)
        MIBServerProtocol.__init__(self, server, "PlaygroundServer")
        self.server = server
        self.__addressData = {}
        
    def messageReceived(self, message):
        """
        Handles an incoming message. The message handling is deferred to the
        PlaygroundServer class.
        """
        success = self.handleMessage(self, message)
        if not success:
            success = self.server.handleMessage(self, message)
        if not success:
            self.server.reportException(NetworkError.NoSuchMessageHandler(message))
            
    def connectionLost(self, reason=None):
        self.server.connectionLost(self, reason)
        """ Clear circular connections """
        self.server = None
        
class PlaygroundServer(Factory, MIBServerImpl, SimpleMessageHandler, 
                       StandardMIBProtocolAuthenticationMixin, ErrorHandlingMixin):
    """
    The factory class for the PlaygroundServer. You can start the server using
    the provided run() method which invokes the Twisted reactor. Or, alternatively,
    you can pass this class (which is a Twisted Factory) to the Twisted reactor
    in a customized fashion.
    """
    
    # This is the number of bytes considered for errors at one time
    ERROR_BYTE_STREAM_SIZE = 10*1024*1024 # 10 MB
    
    CURRENT_CONNECTIONS_MIB = ("playground.network.server","CurrentConnections")
    
    protocol = PlaygroundServerProtocol
    def __init__(self, ipAddress, port):
        SimpleMessageHandler.__init__(self)
        MIBServerImpl.__init__(self)
        #db = CertificateDatabase.GetDatabase()
        #self.loadAuthData(db.loadX509("MIBServer_signed.cert"))
        
        self.__ipAddress = ipAddress
        self.__tcpPort = port
        self.__addressToConnection = {}
        self.__connectionToAddress = {}
        self.setNetworkLossRate(0.0)
        self.setNetworkErrorRate(0.0)
        
        client2ClientHandler = ClientToClientHandler(self, self.__addressToConnection)
        client2ClientHandler.registerAdditionalHandler(self.__networkErrorPacketHandler)
        
        """ Register all message handlers """
        self.registerMessageHandler(
                                    playground.base.RegisterClient, 
                                    RegisterClientHandler(self.__registerAddressProtocolPair))
        self.registerMessageHandler(
                                    playground.base.UnregisterClient,
                                    UnregisterClientHandler(self.__unregisterAddressProtocolPair))
        self.registerMessageHandler(
                                    playground.base.ClientToClientMessage,
                                    client2ClientHandler)
        self.registerMessageHandler(
                                    playground.base.GetPeers,
                                    GetPeersHandler(self, self.__addressToConnection))
        self.__loadMibs()
        
    def __loadMibs(self):
        MIBServerImpl.registerMIB(self, self.CURRENT_CONNECTIONS_MIB[0], self.CURRENT_CONNECTIONS_MIB[1], self.__currentConnections)
        
    def __currentConnections(self, mib, args):
        connections = []
        for address in self.__addressToConnection.keys():
            for protocol in self.__addressToConnection[address]:
                transport = protocol.transport
                connections.append("%s <==> %s" % (str(address), str(transport.getPeer())))
        return connections
        
    def __computeErrorBytes(self):
        self.__errorBytes = []
        self.__streamPointer = 0
        self.__errorStreamSize = 0
        
        if self.__errorRate == 0: return
        
        # Pick a stream size which is either the stream size large enough for 1 error or 10MB, which ever is larger
        self.__errorStreamSize = max (int(1.0/self.__errorRate), self.ERROR_BYTE_STREAM_SIZE)
        expectedErrors = int(round(self.__errorStreamSize * self.__errorRate))
        expectedBytesUntilError = self.__errorStreamSize/(expectedErrors+1)
        errStreamPointer = 0
        while errStreamPointer < self.__errorStreamSize:
            actualBytesUntilError = int(random.gauss(expectedBytesUntilError, .25*expectedBytesUntilError))
            if actualBytesUntilError == 0:
                actualBytesUntilError = 1
            errStreamPointer += actualBytesUntilError
            if errStreamPointer < self.__errorStreamSize:
                self.__errorBytes.append(errStreamPointer)
        
    def __corruptMessage(self, msg):
        errorBytesThisBuffer = []
        if self.__streamPointer > self.ERROR_BYTE_STREAM_SIZE:
            self.__computeErrorBytes()
        while self.__errorBytes and ((self.__errorBytes[0] - self.__streamPointer) < len(msg)):
            errorBytesThisBuffer.append(self.__errorBytes.pop(0)-self.__streamPointer)
        self.__streamPointer += len(msg)
        
        for byteIndex in errorBytesThisBuffer:
            if byteIndex < 0 or byteIndex >= len(msg): continue
            corruptedByte = chr( ord(msg[byteIndex]) ^ 0xff )
            msg = msg[0:byteIndex] + corruptedByte + msg[byteIndex+1:]
        return msg
        
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
                self.reportError("The protocol was associated with the address, but not the other way around!")
            
            """ Remove the entry for the address if there are no more protocols associated with it """
            """ We don't do the same thing with protocol... the protocol remains in the table until """
            """ the connection is lost """
            if len(self.__addressToConnection[address]) == 0:
                del self.__addressToConnection[address]
            return True
        return False
    
    def __networkErrorPacketHandler(self, serializedMessage, originalMessage):
        if self.__lossRate > 0.0 and random.random() < self.__lossRate:
            return ""
        if self.__errorRate > 0.0:            
            return self.__corruptMessage(serializedMessage)
            
        return serializedMessage
    
    
    def setNetworkErrorRate(self, errorRate):
        self.__errorRate = errorRate
        self.__computeErrorBytes()
        
    def setNetworkLossRate(self, lossRate):
        self.__lossRate = lossRate
        
    def buildProtocol(self, address):
        newProtocol = PlaygroundServerProtocol(self)
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
        
    def run(self):
        endpoint = TCP4ServerEndpoint(reactor, self.__tcpPort)
        endpoint.listen(self)
        reactor.run()
