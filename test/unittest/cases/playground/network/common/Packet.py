import unittest, os
from playground.network.common import Packet
from playground.network.message.StandardMessageSpecifiers import STRING
from playground.network.message import MessageDefinition, MessageData

class DummyMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "test.unittest.cases.playground.network.common.DummyMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [("data",STRING)]

class TestEchoServer(unittest.TestCase):
    def fixedSizeTemplate(self, n, m):
        bytes = ""
        msgBuilder = MessageData.GetMessageBuilder(DummyMessage)
        for i in range(1,n):
            msgBuilder["data"].setData(str(i)*m)
            bytes += Packet.MsgToPacketBytes(msgBuilder)
            
        bufferOffset = 0
        for i in range(1,n):
            resultCode, result = Packet.RestorePacket(bytes, bufferOffset)
        
            # check that we got a message
            self.assertEqual(resultCode, Packet.BUFFER_STATUS_CONTAINS_MESSAGE,
                             "Message %d failed: %s" % (i, resultCode))
        
            # deserialize the message 
            restoredData, bufferOffset = result
            restoredMsgBuilder, bytesUsed = MessageData.Deserialize(restoredData)
        
            # make sure the data matches
            self.assertEqual(restoredMsgBuilder["data"].data(), str(i)*m,
                             "Restoration of message %d failed. Bad data" % i)
            self.assertEqual(bytesUsed, len(restoredData),
                             "Didn't use up all bytes in message %d deserialization" % i)
        # make sure that we used up all the bytes
        self.assertEqual(bufferOffset, len(bytes),"Didn't use up all bytes in packet processing")
        
    def test_zeroMessage(self):
        self.fixedSizeTemplate(1, 0)
        
    def test_smallMessage(self):
        self.fixedSizeTemplate(1, 50)
        
    def test_mediumMessage(self):
        self.fixedSizeTemplate(1, 1000)
        
    def test_largeMessage(self):
        self.fixedSizeTemplate(1, 50000)
    
    def test_manySmallMessages(self):
        self.fixedSizeTemplate(100, 10)
        
    def test_manyMediumMessages(self):
        self.fixedSizeTemplate(50, 1000)
        
    def test_manyLargeMessages(self):
        self.fixedSizeTemplate(10, 50000)
        
if __name__ == '__main__':
    unittest.main(verbosity=3)