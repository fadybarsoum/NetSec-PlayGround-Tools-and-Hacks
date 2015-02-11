'''
Created on Nov 26, 2013

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class RunMobileCodev1_1(MessageDefinition):
    '''
    classdocs
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.1"
    BODY = [
            ("ID", UINT8),
            ("mechanism", STRING),
            ("strict", BOOL1, DEFAULT_VALUE(False)),
            ("pythonCode", STRING),
            ]
CURRENT_VERSION = RunMobileCodev1_1

class RunMobileCodev1_0(MessageDefinition):
    '''
    classdocs
    '''
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("ID", UINT8),
            ("pythonCode", STRING),
            ]