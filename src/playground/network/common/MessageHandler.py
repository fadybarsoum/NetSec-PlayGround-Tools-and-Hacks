'''
Created on Nov 25, 2013

@author: sethjn
'''
from playground.network.message import MessageDefinition
from playground.error import Common

from Protocol import Protocol
from Error import DuplicateClientMessageHandler
from playground.network.common import Error as NetworkError

from playground.playgroundlog import packetTrace
import logging
logger = logging.getLogger(__name__)


class MessageHandlerInterface(object):
    """
    Interface class for PLAYGROUND message handling. The basic
    idea is to register a different handler for each type of
    message received by a PLAYGROUND protocol.
    """
    def registerMessageHandler(self, messageType, handler):
        """
        Abstract method for registering a handler to a messageType.
        """
        pass
    def unregisterMessageHandler(self, messageType):
        """
        Abstract method for unregistering a handler to a messageType.
        """
        pass
    def handleMessage(self, protocol, msg):
        """
        Abstract method for handling a message. Note that the
        receiving protocol is passed so that the handler has access
        to the return channel (i.e., protocol.transport)
        
        This method returns True if a handler was found for
        the message and False otherwise
        """
        return False

class SimpleMessageHandler(MessageHandlerInterface):
    '''
    SimpleMessageHandler is a straight-forward impelementation of the
    MessageHandlerInterface and suitable for most implementing classes.
    '''

    def __init__(self):
        '''
        Constructor
        '''
        self.__messageHandlers = {}
        
    def registerMessageHandler(self, messageType, handler):
        if not issubclass(messageType, MessageDefinition):
            raise Common.InvalidArgumentException("Expected a MessageDefinition")
        
        versionMajorString, versionMinorString = messageType.MESSAGE_VERSION.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        
        if not self.__messageHandlers.has_key(messageType.PLAYGROUND_IDENTIFIER):
            self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER] = {}
        if not self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER].has_key(versionMajor):
            self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor] = {}
        if self.__messageHandlers.has_key(versionMinor):
            raise DuplicateClientMessageHandler(messageType)
        self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor][versionMinor] = handler
        
    def unregisterMessageHandler(self, messageType):
        if not issubclass(messageType, MessageDefinition):
            raise Common.InvalidArgumentException("Expected a MessageDefinition")
        
        versionMajorString, versionMinorString = messageType.MESSAGE_VERSION.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        if self.__messageHandlers.has_key(messageType.PLAYGROUND_IDENTIFIER):
            if self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER].has_key(versionMajor):
                if self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor].has_key(versionMinor):
                    del self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor][versionMinor]
                if len(self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor]) == 0:
                    del self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER][versionMajor]
            if len(self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER]) == 0:
                del self.__messageHandlers[messageType.PLAYGROUND_IDENTIFIER]
            
    def handleMessage(self, protocol, msg):
        pgId, version = msg.topLevelData()
        versionMajorString, versionMinorString = version.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        
        msgHandlerVersions = self.__messageHandlers.get(pgId, None)
        if not msgHandlerVersions:
            return False
        
        msgHandlerSpecificVersions = msgHandlerVersions.get(versionMajor, None)
        if not msgHandlerSpecificVersions:
            return False
        
        handler = msgHandlerSpecificVersions.get(versionMinor, None)
        if not handler:
            otherVersions = msgHandlerSpecificVersions.keys()
            otherVersions.append(versionMinor)
            otherVersions.sort()
            myIndex = otherVersions.index(versionMinor)
            if myIndex < len(otherVersions)-1:
                nextHighestVersion = otherVersions[myIndex+1]
                handler = msgHandlerSpecificVersions[nextHighestVersion]
                if handler:
                    # TODO: Put log message here about handling one version with another
                    pass
                
        if not handler:
            return False
        try:
            handler(protocol, msg)
        except Exception, e:
            protocol.reportException(e, explicitReporter=handler)
        return True
        
class SimpleMessageHandlingProtocol(Protocol, SimpleMessageHandler):
    """
    A convenience class combining a Protocol and the SimpleMessageHandler.
    When a message is received, it is passed to the message handling routine,
    and errors are reported in the case of exceptions or the handler
    not found.
    """
    def __init__(self, factory=None, addr=None):
        Protocol.__init__(self, factory, addr)
        SimpleMessageHandler.__init__(self)
        
    def messageReceived(self, msg):
        logger.debug("Message received for protocol %s" % self._connectionId())
        try:
            success = self.handleMessage(self, msg)
            if not success:
                self.reportException(NetworkError.NoSuchMessageHandler(msg))
        except Exception, e:
            self.reportException(e, explicitReporter=SimpleMessageHandlingProtocol)
            try:
                self.transport.loseConnection()
            except:
                pass
