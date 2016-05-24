'''
Created on Nov 27, 2013

@author: sethjn
'''
from playground.playgroundlog import packetTrace
from playground.network.message import definitions
from playground.network.message import MessageData
from playground.network.common import Packet, Protocol

from playground.network.common import SimpleMessageHandlingProtocol, StackingFactoryMixin
from playground.error import ErrorHandlingMixin, PlaygroundError
from playground.network.common import Error as NetworkError

from ClientMessageHandlers import RunMobileCodeHandler, MobileCodeCallbackHandler

from twisted.internet.protocol import Factory
import pickle, logging

logger = logging.getLogger(__name__)

class ClientApplicationServer(StackingFactoryMixin): 
    """
    This class is the base class of all Client application servers.
    The problem is that, at present, it doesnt' do much. More functionality
    may be added later.
    """
    # buidProtocol now in StackingFactoryMixin
    
class ClientMobileCodeServer(ClientApplicationServer):
    """
    An exemplary (or potentially base) mobile code server class. The class
    itself is fairly basic, simply handing the code off to a RunMobileCodeHandler.
    
    Note, the class ClientMobileCodeServer is a Twisted Factory that, by itself,
    does almost nothing. But for each connection, a new ClientMobileCodeServer.Protocol
    instance is built that handles that connection.
    
    Note, because python does not do qualified names, the inner Protocol class is named
    ClientMobileCodeServerProtocol rather than Protocol (with a qualified name of
    ClientMobileCodeServer.Protocol). Maybe some day python will solve this.
    """
    class ClientMobileCodeServerProtocol(SimpleMessageHandlingProtocol):
        def __init__(self, factory, addr):
            SimpleMessageHandlingProtocol.__init__(self, factory, addr)
            self.registerMessageHandler(definitions.playground.base.RunMobileCode, RunMobileCodeHandler(self, **factory.CodeHandlers))
    Protocol=ClientMobileCodeServerProtocol
    CodeHandlers={}

class ClientApplicationClient(StackingFactoryMixin):
    """
    This class is the base class of all Client application clients.
    The problem is that, at present, it doesn't do much. More functionality
    may be added later.
    """
    # build protocol now in stacking factory mixin

class MobileCodeClient(ClientApplicationClient):
    """
    An exemplary (or potentially base) mobile code client. This class is
    a Twisted factory, so it builds a protocol for every outbound connection.
    It has no shared stated between protocol instances, so the nomenclature
    is a little off. In the future, MobileCodeClient could be extended to
    keep track of all of its connections and share state between them.
    
    Because python doesn't do qualified class names, the inner Protocol class
    is named MobileCodeClientProtocol instead of just Protocol (with a qualified
    name of MobileCodeClient.Protocol). Maybe some day python will deal with this.
    """
    class CodeCallback(object):
        """
        The interface for all code callbacks that should be passed in as
        a parameter to sendPythonCode
        """
        def handleCodeResult(self, resultStr, resultObj):
            pass
        def handleCodeException(self, exceptionStr, exceptionObj):
            pass
        def handleDroppedCodeResult(self):
            pass
        
    class MobileCodeClientProtocol(SimpleMessageHandlingProtocol):
        def __init__(self, factory, addr):
            #ClientApplicationServer.__init__(self)
            SimpleMessageHandlingProtocol.__init__(self, factory, addr)
            self.__callBackHandler = MobileCodeCallbackHandler()
            self.__id = 0
            self.registerMessageHandler(definitions.playground.base.MobileCodeResult, self.__callBackHandler)
            self.__preconnectBacklog = []
            self.__connected = False
            
        def connectionMade(self):
            if not self.__connected:
                self.__connected = True
                while self.__preconnectBacklog:
                    codeUnit, callback = self.__preconnectBacklog.pop(0)
                    self.sendPythonCode(codeUnit, callback)
        
        def sendPythonCode(self, codeString, callback):
            """
            Send a python codeUnit to the remote mobile code server.
            When the call completes (or fails), the callback object will
            be called with the appropriate method
            """
            
            if not self.__connected:
                self.__preconnectBacklog.append((codeStr, callback))
                return
            
            """ Create our mobile code message """
            sendCodeMsg = MessageData.GetMessageBuilder(definitions.playground.base.RunMobileCode)
            
            self.__id += 1
            sendCodeMsg["ID"].setData(self.__id)
            sendCodeMsg["pythonCode"].setData(codeString)
            sendCodeMsg["mechanism"].setData("exec")
            
            """ This overly simple client assumes that all responses will come back"""
            self.__callBackHandler.registerCallback(self.__id, callback)
            packetTrace(logger, sendCodeMsg, "Sending remote code to " + self.transport.getPeer().host.toString())
            self.transport.writeMessage(sendCodeMsg)
    Protocol=MobileCodeClientProtocol