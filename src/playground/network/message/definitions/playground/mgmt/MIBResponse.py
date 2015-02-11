'''
Created on Apr 18, 2014

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import DOUBLE8, LIST, STRING, BOOL1
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class MIBResponsev1_0(MessageDefinition):
    PLAYGROUND_IDENTIFIER = playgroundIdentifier(__name__)
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("ID", DOUBLE8),
            ("success", BOOL1),
            ("responses",LIST(STRING))
            ]

CURRENT_VERSION = MIBResponsev1_0