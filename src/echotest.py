'''
Created on Feb 15, 2014

@author: sethjn
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

import sys

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
    
    def __handleEchoMessage(self, protocol, msg):
        
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
        
class EchoClientResponse_StdOutHandler(object):
    """
    This class shows you how you can use a class as a message handler using
    __call__. Note that this is a "std out" handler (prints the message to 
    the screen). You could conceive of a EchoClientResponse_FileHandler
    that would record the result to a file.
    """
    
    def __init__(self, banner):
        """
        The constructor takes a "banner" argument that is used to printout 
        the response.
        """
        self.__banner = banner
        
    def __call__(self, protocol, msg):
        print("%s: %s" % (self.__banner, msg.data().data))
        
        
class EchoClientProtocol(SimpleMessageHandlingProtocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        
        # Set self.__handleServerResponse as a handler for the EchoProtocolMessage
        self.registerMessageHandler(EchoProtocolMessage, EchoClientResponse_StdOutHandler("GOT RESPONSE FROM SERVER:"))
        
    def sendMessage(self, msg):
        # Get the builder for the EchoProtocolMessage
        echoMessageBuilder = MessageData.GetMessageBuilder(EchoProtocolMessage)
        
        # Set the fields of the message
        echoMessageBuilder["original"].setData(True)
        echoMessageBuilder["data"].setData(msg)
        
        # In this example, instead of calling transport.writeMessage, we serialize ourselves
        self.transport.write(Packet.SerializeMessage(echoMessageBuilder))
        
class EchoServer(ClientApplicationServer):
    Protocol=EchoServerProtocol
    
class EchoClientFactory(ClientApplicationClient):
    Protocol=EchoClientProtocol

class ClientTest(object):
    """
    This class is used to test sending a bunch of messages over
    the echo protocol.
    """
    def __init__(self, messagesToSend):
        self.messagesToSend = messagesToSend
        
    def sendMessages(self, client, echoServerAddr):
        protocol = client.openClientConnection(echoProtocolClient, echoServerAddr, 101)
        for message in self.messagesToSend:
            protocol.sendMessage(message)

if __name__=="__main__":
    playgroundNode = int(sys.argv[3])
    
    # Create my address.
    myAddress = PlaygroundAddress(20134, 0, 0, playgroundNode)
    
    # Turn on logging
    logctx = playgroundlog.LoggingContext()
    logctx.nodeId = myAddress.toString()
    
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True
    
    playgroundlog.startLogging(logctx)
    
    # Set up the client base
    client = ClientBase(myAddress)
    serverAddress, serverPortString = sys.argv[1:3]
    serverPort = int(serverPortString)
    
    if playgroundNode == 1:
        # This guy will be the server. Create an instance of the factory
        echoProtocolServer = EchoServer()
        
        # install the echoProtocolServer (factory) on playground port 101
        client.installClientServer(echoProtocolServer, 101)
        
        # tell the playground client to connect to playground server and start running
        client.connectToPlaygroundServer(serverAddress, serverPort)
        
        
    elif playgroundNode == 0:
        # This guy will be the client. The server's address is hard coded
        echoServerAddr = PlaygroundAddress(20134, 0, 0, 1)
        
        # Create a echoProtocolClient (factory)
        echoProtocolClient = EchoClientFactory()
        
        # Create a tester with five strings:
        print("Enter five strings to send over echo protocol:")
        messagesToSend = []
        for i in range(5):
            messagesToSend.append( raw_input("\tMessage %d:" % i))
        tester=ClientTest(messagesToSend)
        
        # Tell the playground node to run this function when connected to PLAYGROUND
        client.runWhenConnected(lambda: tester.sendMessages(client, echoServerAddr))
        
        # Connect to Playground and go
        client.connectToPlaygroundServer(serverAddress, serverPort)