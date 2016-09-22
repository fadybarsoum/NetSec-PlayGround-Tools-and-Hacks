'''
Created on Aug 9, 2016

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier
    
class Gate2GateReservationv1_0(MessageDefinition):

    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    
    RESV_TYPE_CONNECT = 1
    RESV_TYPE_LISTEN = 2
    RESV_TYPE_CANCEL = 3
    
    
    BODY = [
            ("resvType", UINT1, Enum(RESV_TYPE_CONNECT, RESV_TYPE_LISTEN, RESV_TYPE_CANCEL)),
            ("resvId", UINT4),
            ("callbackAddr", STRING),
            ("callbackPort", UINT2),
            
            # Set based on resvType
            ("srcPort", UINT2,  OPTIONAL),   # Only for RESV_TYPE_LISTEN
            ("dstAddr", STRING, OPTIONAL),   # Only for RESv_TYPE_CONNECt
            ("dstPort", UINT2,  OPTIONAL)    # Only for RESV_TYPE_CONNECT
            ]
    
CURRENT_VERSION = Gate2GateReservationv1_0