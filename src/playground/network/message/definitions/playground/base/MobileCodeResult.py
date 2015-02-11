'''
Created on Dec 2, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier



class MobileCodeResultv1_0(MessageDefinition):
    '''
    classdocs
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("ID", UINT8),
            ("success", BOOL1),
            ("result", STRING, OPTIONAL),
            ("resultPickled", STRING, OPTIONAL),
            ("exception", STRING, OPTIONAL),
            ("exceptionPickled", STRING, OPTIONAL)
            ]
    
CURRENT_VERSION = MobileCodeResultv1_0