'''
Created on Oct 23, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class RegisterClientv1_0(MessageDefinition):
    '''
    classdocs
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("address", STRING)
            ]
    
CURRENT_VERSION = RegisterClientv1_0