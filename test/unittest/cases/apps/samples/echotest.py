import unittest, os
from apps.samples.echotest import EchoServer, EchoServerProtocol
from apps.samples.echotest import EchoProtocolMessage
from playground.network.message import MessageData
from playground.network.common import PlaygroundAddress
from tools import DummyTransportToProtocol, DummyTransportToStorage

class TestEchoServer(unittest.TestCase):
    def setUp(self):
        self.echoServerFactory = EchoServer()
        self.serverAddress = PlaygroundAddress(1,2,3,4)
        self.clientAddress = PlaygroundAddress(4,3,2,1)
        self.serverProtocol = EchoServerProtocol(self.echoServerFactory, 
                                                 self.serverAddress)
        self.serverTransport = DummyTransportToStorage(self.serverAddress, 
                                                       self.clientAddress)
        self.clientTransport = DummyTransportToProtocol(self.clientAddress, 
                                                        self.serverAddress,
                                                        self.serverProtocol)
        self.serverProtocol.makeConnection(self.serverTransport)
        
    def test_basicProtocol(self):
        for messageSize in [0, 1, 100, 100000, 1000000]:
            randomMessage = os.urandom(messageSize)
            echoMessage = MessageData.GetMessageBuilder(EchoProtocolMessage)
            echoMessage["original"].setData("True")
            echoMessage["data"].setData(randomMessage)
            self.clientTransport.writeMessage(echoMessage)
            response = self.serverTransport.storage.pop()
            responseMessageBuilder, bytesConsumed = MessageData.Deserialize(response)
            responseData = responseMessageBuilder.data()
            self.assertEqual(responseData.original, False, "Echo response should not be original")
            self.assertEqual(responseData.data, randomMessage, "Echo message doesn't match")
            self.assertEqual(len(response), bytesConsumed, "Message only took up %d bytes of %d byte response" % (bytesConsumed, len(response)))
            
if __name__ == '__main__':
    unittest.main(verbosity=3)