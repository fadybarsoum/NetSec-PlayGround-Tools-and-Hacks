'''
Created on Feb 18, 2017

@author: sethjn
'''

import logging
from playground.error import GetErrorReporter

errReporter = GetErrorReporter(__name__)
logger = logging.getLogger(__name__)

class Port(object):
    PORT_TYPE_INCOMING = 1
    PORT_TYPE_OUTGOING = 2
    PORT_TYPE_CLOSED = 0
    
    class ConnectionData(object):
        def __init__(self):
            self.protocol = None
    
    def __init__(self, portNum, portType):
        self._portNum = portNum
        self._portType = portType
        self._connections = {}
        
    def portType(self):
        return self._portType
    
    def number(self):
        return self._portNum
        
    def isListening(self):
        return self._portType == self.PORT_TYPE_INCOMING
    
    def isConnectedTo(self, dstAddr, dstPort):
        return self._connections.has_key((dstAddr, dstPort))
    
    def getConnectionList(self):
        return self._connections.keys()
    
    def getConnectionData(self, dstAddr, dstPort):
        return self._connections.get((dstAddr, dstPort), self.ConnectionData())
    
    def spawnNewConnection(self, dstAddr, dstPort):
        if self._portType != self.PORT_TYPE_INCOMING:
            raise Exception("Can't spawn a connection on a listening port")
        raise Exception("Must be overwritten by subclasses")


class ChaperoneDemuxer(object):
    MIN_FREE_PORT = 1000
    MAX_FREE_PORT = 9999
    
    
    def __init__(self):
        self.__portMappings = {}
        self.__messageBuffers = {}
        self.__agedIds = set([])
        
    def getFreeSrcPort(self):
        for i in range(self.MIN_FREE_PORT, self.MAX_FREE_PORT+1):
            if not self.__portMappings.has_key(i): return i
        raise Exception("PORTS EXHAUSTED!")
    
    def close(self):
        logger.info("Demuxer closed. All connections closing")
        self.__portMappings = {}
        
    def reservePort(self, portNumber, portObject):
        if self.__portMappings.has_key(portNumber):
            return False
        self.__portMappings[portNumber] = portObject
        
    def clearReservation(self, srcPort):
        if self.__portMappings.has_key(srcPort):
            logger.info("Closing reservation on port %d" % srcPort)
            del self.__portMappings[srcPort]
        
    def portInUse(self, portNumber):
        return self.__portMappings.has_key(portNumber)
    
    def handleDataNoConnection(self, srcAddress, srcPort, dstPort, connectionData, fullPacket):
        logger.debug("Data received, but no connection on port %d. Dropping %d byltes" % (dstPort, len(fullPacket)))
        
    def handleData(self, srcAddress, srcPort, dstPort, connectionData, fullPacket):
        raise Exception("Must be overridden by subclass")
    
    def demux(self, srcAddress, srcPort, dstPort, data, fragInfo=None):
        if not self.__portMappings.has_key(dstPort) or (not self.__portMappings[dstPort].isListening() and not self.__portMappings[dstPort].isConnectedTo(srcAddress, srcPort)):
            logger.debug("Dropping %d bytes from %s::%d because destination port %d is not connected" % 
                         (len(data), srcAddress, srcPort, dstPort))
            return
        fullPacket = None
        if fragInfo:
            msgId, msgIndex, msgLast = fragInfo
            # The message buffers is a list of received fragments
            # each at the index specified in the packet. There is
            # a sentinal at the end containing a count of missing
            # packets and whether the last packet has been received.

            if not self.__messageBuffers.has_key(msgId):
                self.__messageBuffers[msgId] = []
                maxIndex, fragsMissing, lastReceived = 0, 0, False
            else:
                maxIndex, fragsMissing, lastReceived = self.__messageBuffers[msgId].pop(-1)
            
            if msgIndex < maxIndex:
                if self.__messageBuffers[msgId][msgIndex] == 0:
                    fragsMissing = fragsMissing - 1
                self.__messageBuffers[msgId][msgIndex] = data
            else:
                missingCount = msgIndex - maxIndex
                if missingCount:
                    self.__messageBuffers[msgId] += [0] * missingCount
                self.__messageBuffers[msgId].append(data)
                fragsMissing += missingCount
                maxIndex = msgIndex+1
                
            lastReceived = lastReceived or msgLast
            
            if lastReceived and fragsMissing == 0:
                # combine all the data
                fullPacket = "".join(self.__messageBuffers[msgId])
                del self.__messageBuffers[msgId]
            else:   
                self.__messageBuffers[msgId].append([maxIndex, fragsMissing, lastReceived])
        else:
            fullPacket = data
        if fullPacket:
            connectionData = self.__portMappings[dstPort].getConnectionData(srcAddress, srcPort)
            if not connectionData.protocol and self.__portMappings[dstPort].isListening():
                logger.info("Spawning new connection from %s:%d to port %s" % (srcAddress, srcPort, dstPort))
                self.__portMappings[dstPort].spawnNewConnection(srcAddress, srcPort)
                connectionData = self.__portMappings[dstPort].getConnectionData(srcAddress, srcPort)
                if not connectionData.protocol:
                    logger.error("Failed to launch protocol for new incoming connection")
            if not connectionData.protocol:
                self.handleDataNoConnection(srcAddress, srcPort, dstPort, connectionData, fullPacket)
            else: self.handleData(srcAddress, srcPort, dstPort, connectionData, fullPacket)
            