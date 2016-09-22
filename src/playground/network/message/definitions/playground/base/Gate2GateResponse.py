'''
Created on Aug 9, 2016

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

from Gate2GateReservation import CURRENT_VERSION as Gate2GateReservation
    
class Gate2GateResponsev1_0(MessageDefinition):

    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    
    RESP_TYPE_INITIAL  = 1
    RESP_TYPE_CALLBACK = 2
    
    BODY = [
            ("resvType", UINT1, Enum(Gate2GateReservation.RESV_TYPE_CONNECT, Gate2GateReservation.RESV_TYPE_LISTEN)),
            ("resvId",  UINT4),
            ("respType", UINT1, Enum(RESP_TYPE_INITIAL, RESP_TYPE_CALLBACK)),
            
            # the following fields are sent back based on resvType and respType
            ("srcAddr", STRING,OPTIONAL),  # respType INITIAL
            ("srcPort", UINT2, OPTIONAL),  # respType INITIAL
            ("dstAddr", STRING,OPTIONAL),  # resvType CONNECT respType INITIAL
                                            # AND resvType LISTEN respType CALLBACK
            ("dstPort", UINT2, OPTIONAL),  # resvType CONNECT respType INITIAL
                                            # AND resvType LISTEN respType CALLBACK
            ("connPort",UINT2, OPTIONAL),  # respType CALLBACK
            ("success", BOOL1),
            ("msg", STRING)
            ]
    
CURRENT_VERSION = Gate2GateResponsev1_0