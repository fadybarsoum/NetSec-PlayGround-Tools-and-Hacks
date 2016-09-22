'''
Created on Nov 26, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier
    
class Gate2GateMessagev1_0(MessageDefinition):

    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("dstAddress", STRING),
            ("dstPort", UINT2),
            ("srcAddress", STRING),
            ("srcPort", UINT2),
            ("gatePacket", STRING),
            ("ID", UINT8, OPTIONAL),
            ("index", UINT8, OPTIONAL),
            ("lastPacket", BOOL1, OPTIONAL),
            ]
    
CURRENT_VERSION = Gate2GateMessagev1_0