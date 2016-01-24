'''
Created on Nov 26, 2013

@author: sethjn
'''
from playground.network.common import Packet, PlaygroundAddress, PlaygroundNetworkError
from playground.network.message import MessageData
from playground.network.message.definitions import playground

import time

class ClientToClientHandler(object):
    """
    The Server C2C handler passes the client message to other
    clients registered as the receiving address.
    
    Registered handlers process the message before trasnsmission.
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
        serializedMessage = Packet.SerializeMessage(msg)
        for handler in self.__additionalHandlers:
            serializedMessage = handler(serializedMessage, msg)
            if len(serializedMessage) == 0: break
        return serializedMessage
    
    def __call__(self, protocol, msg):
        playgroundDestAddressString = msg["dstAddress"].data()
        
        serializedMessage = self.__formatMessage(msg)
        if len(serializedMessage) == 0: return
        
        for client in self.__connectionTable.get(playgroundDestAddressString, []):
            client.producerWrite(serializedMessage)
            
class UnregisterClientHandler(object):
    def __init__(self, unregistrationCallback):
        self.__callback = unregistrationCallback
        
    def __call__(self, protocol, msg):
        playgroundAddressString = msg["address"].data()
        success = self.__callback(playgroundAddressString, protocol)
        if not success:
            playgroundAddressString = ""
        unregisterClientMsg = MessageData.GetMessageBuilder(playground.base.ClientUnregistered)
        if unregisterClientMsg == None:
            raise Exception("Cannot find UnregisterClient definition")
        
        """ Create the response packet """
        unregisterClientMsg["success"].setData(success)
        unregisterClientMsg["address"].setData(playgroundAddressString)
        """ Packet created. """
        
        packetBuffer = Packet.SerializeMessage(unregisterClientMsg)
        protocol.transport.write(packetBuffer)

class RegisterClientHandler(object):
    def __init__(self, registrationCallback):
        self.__callback = registrationCallback
        
    def __call__(self, protocol, msg):
        playgroundAddressString = msg["address"].data()
        success = True
        try:
            """ Make sure the address is valid (can be converted back to an PlaygroundAddress) """
            PlaygroundAddress.FromString(playgroundAddressString)
        except PlaygroundNetworkError, e:
            success = False
        if success:
            success = self.__callback(playgroundAddressString, protocol)
        registerClientMsg = MessageData.GetMessageBuilder(playground.base.ClientRegistered)
        if registerClientMsg == None:
            raise Exception("Cannot find RegisterClient definition")
        
        if not success:
            playgroundAddressString = "" #TODO: should there be an "error address"?
        
        """ Create the response packet """
        registerClientMsg["success"].setData(success)
        registerClientMsg["address"].setData(playgroundAddressString)
        """ Packet created. """
        
        packetBuffer = Packet.SerializeMessage(registerClientMsg)
        protocol.transport.write(packetBuffer)
        
class GetPeersHandler(object):
    def __init__(self, server, connectionTable):
        self.__server = server
        self.__connTable = connectionTable
        
    def __call__(self, protocol, msg):
        peersMsg = MessageData.GetMessageBuilder(playground.base.Peers)
        peersMsg["time"].setData(time.time())
        addresses = self.__connTable.keys()
        peersMsg["peers"].add(len(addresses))
        for index in range(len(addresses)):
            peersMsg["peers"][index].setData(addresses[index])
        packetBuffer = Packet.SerializeMessage(peersMsg)
        protocol.transport.write(packetBuffer)