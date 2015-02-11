'''
Created on Dec 4, 2013

@author: sethjn
'''
from playground.error import Common
from playground.network.common import Packet
from playground.network.message import MessageData
from playground.network.message import definitions

from playground.playgroundlog import packetTrace
import logging, random
logger = logging.getLogger(__name__)

#from twisted.internet.interfaces import ITransport

#TODO: figure out how ITransport works...

class ClientApplicationTransport(object):
    '''
    ClientApplicationTransport is an encapsulated transport for use in 
    ClientApplicationServers and so forth. It takes a message and
    encapsulates it in a C2C message before sending it on to the playground
    server.
    
    It is used like a twisted ITransport, but does not yet implement the
    weird, non-python interface of ITransport
    '''


    def __init__(self, lowerTransport, addrPair, peerPair, closer):
        #ITransport.__init__(self, addrPair, peerPair)
        '''
        Constructor creates a ClientApplicationTransport wrapped around
        a lower level transport with an PlaygroundAddressPairs for the host
        and peer.
        '''
        self.__transport = lowerTransport
        self.__addrPair = addrPair
        self.__peerPair = peerPair
        self.__maxMsgSize = (2**16)-1
        self.__closer = closer
        
    def write(self, msgStr):
        msgStrFragments = []
        while msgStr:
            msgStrFragments.append( msgStr[:self.__maxMsgSize] )
            msgStr = msgStr[self.__maxMsgSize:]
        if len(msgStrFragments) == 0:
            msgStrFragments = ['']
            
        toClientMsg = MessageData.GetMessageBuilder(definitions.playground.base.ClientToClientMessage)
        toClientMsg["dstAddress"].setData(self.__peerPair.host.toString())
        toClientMsg["dstPort"].setData(self.__peerPair.port)
        toClientMsg["srcAddress"].setData(self.__addrPair.host.toString())
        toClientMsg["srcPort"].setData(self.__addrPair.port)
        msgID = random.getrandbits(64)
        toClientMsg["ID"].setData(msgID)
        for msgIndex in range(len(msgStrFragments)):
            msgStrToSend = msgStrFragments[msgIndex]
            toClientMsg["clientPacket"].setData(msgStrToSend)
            toClientMsg["index"].setData(msgIndex)
            if msgIndex == len(msgStrFragments)-1:
                toClientMsg["lastPacket"].setData(True)
            else: toClientMsg["lastPacket"].setData(False)
            
            packetTrace(logger, toClientMsg, "Sending c2c packet from %s to %s" % (toClientMsg["srcAddress"].data(),
                                                                                   toClientMsg["dstAddress"].data()))
            self.__transport.write(Packet.SerializeMessage(toClientMsg))
        
    def writeMessage(self, msg):
        packetTrace(logger, msg, "Transport received upper layer packet for transport")
        self.write(Packet.SerializeMessage(msg))
        
    def writeSequence(self, msgStrs):
        for msgStr in msgStrs: self.write(msgStr)
        
    def writeMessages(self, msgs):
        for msg in msgs:
            self.writeMessage(msg)
            
    def loseConnection(self):
        self.__closer(self.__addrPair, self.__peerPair)
        #raise Common.UnimplementedException(self.__class__, self.loseConnection, "Current Playground Transports are not Stateful")
    
    def getPeer(self):
        return self.__peerPair
    
    def getHost(self):
        return self.__addrPair
