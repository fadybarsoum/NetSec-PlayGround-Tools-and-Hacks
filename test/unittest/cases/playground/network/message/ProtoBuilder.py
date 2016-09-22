import unittest, os
from playground.network.message import ProtoBuilder
from playground.network.message.StandardMessageSpecifiers import STRING, UINT2, FLOAT4, LIST
from playground.network.message import MessageDefinition

class DummyMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "test.unittest.cases.playground.network.message.DummyMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("uint2_field1", UINT2),
            ("float4_field1", FLOAT4),
            ("list_string_field1", LIST(STRING))]

class TestMessageBuilding(unittest.TestCase):
    def test_basic1(self):
        m1 = DummyMessage()
        m1.uint2_field1 = 300
        m1.float4_field1 = 3.14159
        m1.list_string_field1 = ["test1", "test2"]
        m1Serialized = str(m1)
        m1_ds, bytesUsed = DummyMessage.Deserialize(m1Serialized)
        assert(m1_ds.uint2_field1 == m1.uint2_field1)
        
        # float's aren't perfectly equal after deserialization. This is close enough
        assert(((m1_ds.float4_field1 - m1.float4_field1)**2) < 0.1 )
        assert(m1_ds.list_string_field1 == m1.list_string_field1)

if __name__ == '__main__':
    unittest.main(verbosity=3)