'''
Created on Nov 26, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class ClientToClientMessagev1_0(MessageDefinition):
    '''
    A Client-to-Client message definition. Used for simple routing across the PLAYGROUND.
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("dstAddress", STRING),
            ("dstPort", UINT2),
            ("srcAddress", STRING),
            ("srcPort", UINT2),
            ("clientPacket", STRING)
            ]
    
class ClientToClientMessagev1_1(MessageDefinition):
    '''
    The v1.1 update to C2C allows for multiple packets to be reassembled. This
    eliminates the 65K message limitation.
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.1"
    BODY = [
            ("dstAddress", STRING),
            ("dstPort", UINT2),
            ("srcAddress", STRING),
            ("srcPort", UINT2),
            ("clientPacket", STRING),
            ("ID", UINT8, OPTIONAL),
            ("index", UINT8, OPTIONAL),
            ("lastPacket", BOOL1, OPTIONAL),
            ]
    
CURRENT_VERSION = ClientToClientMessagev1_1
VERSION_DATA = {(1,0):ClientToClientMessagev1_0}