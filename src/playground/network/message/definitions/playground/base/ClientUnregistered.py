'''
Created on Dec 10, 2013

@author: sethjn
'''
from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class ClientUnregisteredv1_0(MessageDefinition):
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("success", BOOL1),
            ("address", STRING),
            ]

CURRENT_VERSION = ClientUnregisteredv1_0