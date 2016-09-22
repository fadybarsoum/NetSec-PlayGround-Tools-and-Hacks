'''
Created on Sep 8, 2016

@author: sethjn
'''

import logging, random

from twisted.internet.protocol import Protocol

from playground.error import GetErrorReporter

from playground.network.common.statemachine import StateMachine as FSM
from playground.network.common.statemachine import StateMachineError
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.playground.base import GateRegistered
from playground.network.message.definitions.playground.base import Gate2GateMessage
from playground.network.message.definitions.playground.base import RegisterGate

from playground.playgroundlog import packetTrace

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

class ChaperoneProtocol(Protocol):
    STATE_DISCONNECTED = "Chaperone Protocol: disconnected"
    STATE_NEGOTIATING  = "Chaperone Protocol: negotiating"
    STATE_CONNECTED    = "Chaperone Protocol: connected"
    STATE_CLOSED       = "Chaperone Protocol: closed"
    
    SIGNAL_REG_SENT     = "Chaperone Protocol: registration sent to chaperone"
    SIGNAL_REG_RECEIVED = "Chaperone Protocol: chaperone sent registration"
    SIGNAL_REG_FAILED   = "Chaperone Protocol: chaperone denied registration"
    SIGNAL_UNREG_SENT   = "Chaperone Protocol: unregistration sent to chaperone"
    
    MAX_MSG_SIZE = (2**16)-1
    FRAMING_SIZE = (2**12)
    MAX_FRAG_AGE = 10*60 # Ten minute time-out on G2gMessage Frags
    
    def __init__(self, gateAddress, demuxer):
        self.__packetStorage = PacketStorage()
        self.__gateAddress = gateAddress
        self.__demuxer = demuxer
        
        self.__fsm = FSM("Chaperone Protocol FSM")
        self.__fsm.addState(self.STATE_DISCONNECTED,
                            # transitions
                            (self.SIGNAL_REG_SENT, self.STATE_NEGOTIATING))
        
        self.__fsm.addState(self.STATE_NEGOTIATING,
                            # transitions
                            (GateRegistered,           self.STATE_NEGOTIATING),
                            (self.SIGNAL_REG_RECEIVED, self.STATE_CONNECTED),
                            (self.SIGNAL_REG_FAILED,   self.STATE_CLOSED),
                            # callbacks
                            onEnter=self.__checkNegotiation)
        
        self.__fsm.addState(self.STATE_CONNECTED,
                            # transitions
                            (self.SIGNAL_UNREG_SENT, self.STATE_DISCONNECTED),
                            (Gate2GateMessage,       self.STATE_CONNECTED),
                            # callbacks
                            onEnter=self.__handleConnectedMessages)
        
        self.__fsm.start(self.STATE_DISCONNECTED)
        

    def connectionMade(self):
        registerGateMessage = RegisterGate()
        registerGateMessage.address = self.__gateAddress
        
        self.transport.write(Packet.MsgToPacketBytes(registerGateMessage))
        self.__fsm.signal(self.SIGNAL_REG_SENT, registerGateMessage)
        
    def dataReceived(self, data):
        self.__packetStorage.update(data)
        for msg in IterateMessages(self.__packetStorage, logger, errReporter):
            try:
                self.__fsm.signal(msg.__class__, msg)
            except StateMachineError, e:
                errReporter.error(("State machine error after receiving %s. Error:\n%s") % (msg, e))
                self.transport.loseConnection()
                
    def send(self, srcPort, dstAddress, dstPort,  data):
        if not self.__fsm.currentState() == self.STATE_CONNECTED:
            return
        g2gMessage = Gate2GateMessage(dstAddress = dstAddress,
                                      dstPort    = dstPort,
                                      srcAddress = self.__gateAddress,
                                      srcPort    = srcPort,
                                      ID         = random.getrandbits(64))
        
        index = 0
        while data:
            g2gMessage.index = index
            g2gMessage.gatePacket = data[:self.MAX_MSG_SIZE]
            
            data = data[self.MAX_MSG_SIZE:]
            index += 1
            
            # if there's no data left, this is the last packet
            if not data: g2gMessage.lastPacket = True
            
            # transmit packet
            print "Sending packet %d to Chaperone" % index
            self.transport.write(Packet.MsgToPacketBytes(g2gMessage))
            
    # Negotiation State Enter Callback
    def __checkNegotiation(self, signal, data):
        if signal == GateRegistered:
            if data.success:
                self.__fsm.signal(self.SIGNAL_REG_RECEIVED, data)
            else:
                self.__fsm.signal(self.SIGNAL_REG_FAILED, data)
                
    # Connected State Enter Callback
    def __handleConnectedMessages(self, signal, data):
        if signal == Gate2GateMessage:
            self.__demuxer.demux(data.srcAddress, data.srcPort, data.dstPort, data.gatePacket,
                                 (data.ID != MessageDefinition.UNSET and (data.ID, data.index, data.lastPacket) or None))
            