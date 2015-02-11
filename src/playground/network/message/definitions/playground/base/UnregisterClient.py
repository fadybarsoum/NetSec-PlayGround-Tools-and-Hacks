'''
Created on Dec 10, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class UnregisterClientv1_0(MessageDefinition):
    '''
    Message definition for unregistering an address for a client.
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("address", STRING)
            ]
    
CURRENT_VERSION = UnregisterClientv1_0