'''
Created on Nov 26, 2013

@author: sethjn
'''
from playground.network.common import Packet, PlaygroundAddress, PlaygroundNetworkError
from playground.network.message import MessageData
from playground.network.message.definitions import playground

import time

class Gate2GateHandler(object):
    """
    The Server G2G handler passes the gate message to other
    gates registered as the receiving address.
    
    Registered handlers process the message before transmission.
    """
    def __init__(self, server, connectionTable):
        self.__server = server
        self.__connectionTable = connectionTable
        self.__additionalHandlers = []
        
    def registerAdditionalHandler(self, h):
        self.__additionalHandlers.append(h)
        return len(self.__additionalHandlers)
        
    def removeAdditionalHandler(self, h):
        self.__additionalHandlers.remove(h)
        
    def __formatMessage(self, msg):
        serializedMessage = Packet.MsgToPacketBytes(msg)
        for handler in self.__additionalHandlers:
            serializedMessage = handler(serializedMessage, msg)
            if len(serializedMessage) == 0: break
        return serializedMessage
    
    def __call__(self, protocol, msg):
        playgroundDestAddressString = msg.dstAddress
        
        serializedMessage = self.__formatMessage(msg)
        if len(serializedMessage) == 0: return
        
        for gate in self.__connectionTable.get(playgroundDestAddressString, []):
            gate.producerWrite(serializedMessage)
            
class UnregisterGateHandler(object):
    def __init__(self, unregistrationCallback):
        self.__callback = unregistrationCallback
        
    def __call__(self, protocol, msg):
        playgroundAddressString = msg.address
        success = self.__callback(playgroundAddressString, protocol)
        if not success:
            playgroundAddressString = ""
        unregisterGateMsg = playground.base.GateUnregistered()
        
        """ Create the response packet """
        unregisterGateMsg.success = success
        unregisterGateMsg.address = playgroundAddressString
        """ Packet created. """
        
        packetBuffer = Packet.MsgToPacketBytes(unregisterGateMsg)
        protocol.transport.write(packetBuffer)

class RegisterGateHandler(object):
    def __init__(self, registrationCallback):
        self.__callback = registrationCallback
        
    def __call__(self, protocol, msg):
        playgroundAddressString = msg.address
        success = True
        try:
            """ Make sure the address is valid (can be converted back to an PlaygroundAddress) """
            PlaygroundAddress.FromString(playgroundAddressString)
        except PlaygroundNetworkError, e:
            success = False
        if success:
            success = self.__callback(playgroundAddressString, protocol)
        registerGateMsg = playground.base.GateRegistered()
        
        if not success:
            playgroundAddressString = "" #TODO: should there be an "error address"?
        
        """ Create the response packet """
        registerGateMsg.success = success
        registerGateMsg.address = playgroundAddressString
        """ Packet created. """
        
        packetBuffer = Packet.MsgToPacketBytes(registerGateMsg)
        protocol.transport.write(packetBuffer)
        
class GetPeersHandler(object):
    def __init__(self, server, connectionTable):
        self.__server = server
        self.__connTable = connectionTable
        
    def __call__(self, protocol, msg):
        peersMsg = playground.base.Peers()
        peersMsg.time = time.time()
        peersMsg.peers = self.__connTable.keys()
        packetBuffer = Packet.MsgToPacketBytes(peersMsg)
        protocol.transport.write(packetBuffer)