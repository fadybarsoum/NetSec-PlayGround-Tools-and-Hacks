'''
Created on Feb 15, 2014

@author: sethjn

This sample shows how to do some basic things with playground.
It does not use the PlaygroundNode interface. To see an example
of that, check out computePi.py.
'''
# Import playgroundlog to enable logging
from playground import playgroundlog

# We will use "BOOL1" and "STRING" in our message definition
from playground.network.message.StandardMessageSpecifiers import BOOL1, STRING

from playground.network.common import PlaygroundAddress, Packet

# SimpleMessageHandlingProtocol is a convenient way to setup a Playground Protocol
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.message.ProtoBuilder import MessageDefinition

# MessageData has a static method used for constructing a serializable class
from playground.network.message import MessageData

# ClientBase is the way we connect into Playground
from playground.network.client import ClientBase

# ClientApplicationServer and ClientApplicationClient are base classes for creating the 
# Server and Client Protocol factories
from playground.network.client.ClientApplicationServer import ClientApplicationServer, ClientApplicationClient

from twisted.internet import defer, stdio
from twisted.protocols import basic

import sys, time, os

class EchoProtocolMessage(MessageDefinition):
    """
    EchoProtocolMessage is a simple message for sending a bit of 
    data and getting the same data back as a response (echo). The
    "header" is simply a 1-byte boolean that indicates whether or
    not it is the original message or the echo.
    """
    
    # We can use **ANY** string for the identifier. The convention is to
    # Do a fully qualified name of some set of messages. I have been
    # putting my messages under playground.fall2013.base. You can 
    # put your in a package, or have them flat like shown below
    PLAYGROUND_IDENTIFIER = "TestEchoProtocolMessageID"
    
    # Message version needs to be x.y where x is the "major" version
    # and y is the "minor" version. All Major versions should be
    # backwards compatible. Look at "ClientToClientMessage" for
    # an example of multiple versions
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("original", BOOL1),
            ("data", STRING)
            ]


class EchoServerProtocol(SimpleMessageHandlingProtocol):
    """
    This is our class for the Server's protocol. It simply receives
    an EchoProtocolMessage and sends back a response
    """
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        
        # Register "self.__handleEchoMessage" as a handler for messages of type
        # "EchoProtocolMessage"
        self.registerMessageHandler(EchoProtocolMessage, self.__handleEchoMessage)
        self.lastMessage = 0
    
    def __handleEchoMessage(self, protocol, msg):
        
        self.lastMessage = time.time()
        # Convert the "message builder" version of the message into a simple data structure
        msgObj = msg.data()
        
        # Get the Message Builder for "EchoProtocolMessage". Note that you can use it's ID
        # instead of it's class if you want.
        responseMessageBuilder = MessageData.GetMessageBuilder("TestEchoProtocolMessageID")
        
        # Set the fields of the EchoProtocolMessage
        responseMessageBuilder["original"].setData(False)
        responseMessageBuilder["data"].setData(msgObj.data)
        
        # Use the transport to write the data back. Now, just so you know, self.transport
        # is of type  ClientApplicationTransport. Internally, it is wrapping your message
        # into a Client-to-Client message.
        self.transport.writeMessage(responseMessageBuilder)
        if msgObj.data == "__QUIT__":
            self.callLater(0, self.__closeConnection)
        else:
            self.callLater(60, self.__checkConnection)
        
    def __closeConnection(self):
        if not self.transport: return
        self.transport.loseConnection()
        self.transport = None
        
    def __checkConnection(self):
        if not self.transport: return
        if time.time() > self.lastMessage + 30:
            self.__closeConnection()
        else: self.callLater(30, self.__checkConnection)
        
        
class EchoClientResponse_StdOutHandler(object):
    """
    This class shows you how you can use a class as a message handler using
    __call__. Note that this is a "std out" handler (prints the message to 
    the screen). You could conceive of a EchoClientResponse_FileHandler
    that would record the result to a file.
    """
    
    def __init__(self, banner, chainedCb):
        """
        The constructor takes a "banner" argument that is used to printout 
        the response.
        
        The chained call back is called after this one
        """
        self.__banner = banner
        self.__chainedCb = chainedCb
        
    def __call__(self, protocol, msg):
        print("%s: %s" % (self.__banner, msg.data().data))
        self.__chainedCb(protocol, msg)
        
        
class EchoClientProtocol(SimpleMessageHandlingProtocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        
        # Set self.__handleServerResponse as a handler for the EchoProtocolMessage
        self.registerMessageHandler(EchoProtocolMessage, 
                                    EchoClientResponse_StdOutHandler("GOT RESPONSE FROM SERVER: ",
                                                                     self.__nextCallback))
        self.__connected = False
        self.__backlog = []
        self.__d = None
        self.__closeD = defer.Deferred()
        self.__connectD = defer.Deferred()
        
    def close(self):
        self.__sendMessageActual("__QUIT__")
    
    def notifyClosed(self):
        return self.__closeD
    
    def notifyConnected(self):
        if self.__connected: return True
        return self.__connectD
    
    def connectionLost(self, reason=None):
        if self.__closeD:
            d = self.__closeD
            self.__closeD = None
            # We do this first, because self.__d could get set by callback 
            d.callback(reason)
        
    def connectionMade(self):
        self.__connected = True
        for m in self.__backlog:
            self.__sendMessageActual(m)
        self.__connectD.callback(True)
        
    def sendMessage(self, msg):
        self.__d = defer.Deferred()
        if self.__connected:
            self.__sendMessageActual(msg)
        else:
            self.__backlog.append(msg)
        return self.__d
        
    def __sendMessageActual(self, msg):
        # Get the builder for the EchoProtocolMessage
        echoMessageBuilder = MessageData.GetMessageBuilder(EchoProtocolMessage)
        
        # Set the fields of the message
        echoMessageBuilder["original"].setData(True)
        echoMessageBuilder["data"].setData(msg)
        
        # In this example, instead of calling transport.writeMessage, we serialize ourselves
        self.transport.write(echoMessageBuilder.serialize())
        
    def __nextCallback(self, protocol, msg):
        """
        This callback is given as a chained callback to the 
        message handler. It simply calls any callbacks deferred
        to calling code.
        """
        if self.__d:
            d = self.__d
            self.__d = None
            # We do this first, because self.__d could get set by callback 
            d.callback(None)
        
class EchoServer(ClientApplicationServer):
    Protocol=EchoServerProtocol
    
class EchoClientFactory(ClientApplicationClient):
    Protocol=EchoClientProtocol
    
class ClientTest(basic.LineReceiver):
    """
    This class is used to test sending a bunch of messages over
    the echo protocol.
    """
    delimiter = os.linesep
    
    def __init__(self, client, echoServerAddr, connectionType="RAW"):
        
        self.__client = client
        self.__echoServerAddr = echoServerAddr
        self.__protocol = None
        self.__d = None
        self.__connectionType = connectionType
        
    def connectionMade(self):
        srcPort, self.__protocol = client.connect(EchoClientFactory(), echoServerAddr, 101,
                                                      connectionType=self.__connectionType)
        print "Waiting for server."
        d1 = self.__protocol.notifyClosed()
        d1.addCallback(self.exit)
        d2 = self.__protocol.notifyConnected()
        if d2 == True:
            self.echoConnectionMade(True)
        else:
            d2.addCallback(self.echoConnectionMade)
            
    def echoConnectionMade(self, status):
        self.transport.write("Message to send to %s (quit to exit): " % self.__echoServerAddr)
        
    def lineReceived(self, line):
        if self.__d:
            self.transport.write("Waiting for previous echo. (Ctrl-C if it's stuck)\n")
            return
        message = line
        if message.lower().strip() in ["quit", "__quit__"]:
            self.__protocol.close()
            self.__d = defer.Deferred() # empty place holder while we wait for close
            return
        else:
            self.__d = self.__protocol.sendMessage(message)
            self.__d.addCallback(lambda result: self.reset())
            
    def reset(self):
        self.__d = None
        self.transport.write("\nMessage to send to %s (quit to exit): " % self.__echoServerAddr)
        
    def exit(self, reason=None):
        print "Shutdown of echo test client. Reason =", reason
        if self.transport:
            self.transport.loseConnection()
        if self.__client:
            self.__client.disconnectFromPlaygroundServer(stopReactor=True)
            self.__client = None
        

USAGE = """usage: echotest <playgroundAddr> <chaperone addr> <mode> [STREAM_TYPE]
  mode is either 'server' or a server's address (client mode)"""

if __name__=="__main__":
    try:
        playgroundAddr, chaperoneAddr, mode = sys.argv[1:4]
    except:
        sys.exit(USAGE)
    if len(sys.argv) == 5:
        connectionType = sys.argv[4]
    else:
        connectionType = "RAW"

    myAddress = PlaygroundAddress.FromString(playgroundAddr)
    
    # Turn on logging
    logctx = playgroundlog.LoggingContext()
    logctx.nodeId = myAddress.toString()
    
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True
    
    playgroundlog.startLogging(logctx)
    
    # Set up the client base
    client = ClientBase(myAddress)
    #serverAddress, serverPortString = sys.argv[1:3]
    chaperonePort = 9090#int(serverPortString)
    
    if mode.lower() == "server":
        # This guy will be the server. Create an instance of the factory
        echoProtocolServer = EchoServer()
        
        # install the echoProtocolServer (factory) on playground port 101
        client.listen(echoProtocolServer, 101, connectionType=connectionType)
        
        # tell the playground client to connect to playground server and start running
        client.connectToChaperone(chaperoneAddr, chaperonePort)
        
        
    else:
        try:
            echoServerAddr = PlaygroundAddress.FromString(mode)
        except:
            sys.exit(USAGE)
        # This guy will be the client. The server's address is hard coded
        
        tester = ClientTest(client, echoServerAddr, connectionType)
        
        client.runWhenConnected(lambda: stdio.StandardIO(tester))
        
        # Connect to Playground and go
        client.connectToChaperone(chaperoneAddr, chaperonePort)
