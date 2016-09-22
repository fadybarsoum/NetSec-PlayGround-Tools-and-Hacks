'''
Created on Nov 26, 2013

@author: sethjn
'''
from playground.error import PlaygroundError

class PlaygroundNetworkError(PlaygroundError): pass

class PacketReconstructionError(PlaygroundNetworkError): pass

class PacketSerializationError(PlaygroundNetworkError): pass

class InvalidPlaygroundAddressString(Exception): pass

class InvalidPlaygroundFormat(Exception): pass

class DuplicateClientMessageHandler(PlaygroundNetworkError):
    def __init__(self, messageType):
        Exception.__init__(self, "Received a duplicate handler for messages of type %s" % messageType.PLAYGROUND_IDENTIFIER)
        
class NoSuchMessageHandler(PlaygroundNetworkError):
    def __init__(self, msg):
        Exception.__init__(self, "Could not find a message handler for %s" % msg)
        self.msg = msg