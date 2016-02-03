# Playground
## Overview
Playground is a network simulating tool.  It consists of two parts, a Chaperone and some number of Playground Nodes.  The Chaperone is designed to act as the wires of the Playground network - the nodes all connect to each other via the Chaperone and do not interact with the Chaperone itself.  A Playground Node is essentially anything that is connected to Playground - it could be anything from a simple echoserver to a more complicated zork server or client.  From the perspective of the Playground Nodes only other playground nodes exist, so for example the zork server and client would think they are sending messages directly to each other, even though those messages are being routed through the Chaperone.

For a more technical look at Playground see 'documentation/Playground_Framework.pdf'.

## Setup
### Prerequisites
As of this time Playground is not supported for Windows.  It can be run using Cygwin, but this is not recommended.  The recommended approach for Windows is to use VirtualBox to create a Unix virtual machine and run Playground in that.

Playground is written almost entirely in Python, and requires the following packages:

* [Python 2.6+](https://www.python.org/downloads/release/python-2711/)
* [Twisted](https://pypi.python.org/pypi/Twisted)
	* This has hidden dependency that pip didn't catch, I had to further install [pyOpenSSL](https://pypi.python.org/pypi/pyOpenSSL) 
* [pyasn1](https://pypi.python.org/pypi/pyasn1)
* [pyasn1-modules](https://pypi.python.org/pypi/pyasn1-modules)
* [crypto](https://pypi.python.org/pypi/crypto/1.4.1)

Installation of all of these packages can be done using [pip](https://pypi.python.org/pypi/pip) with the command 
`$ pip install --upgrade [package]`.

***NOTE:***  
After installion in order to allow python to find crypto you made need to change the name of the folder it was installed in from "crypto" to "Crypto".  You can find the directory it was installed into using `$ pip show crypto`.

Also be careful with the path your Playground resides in, in OSX there can be issues if any of the directories along the path have spaces in them.

### Installation
In order to begin you should fork this repository to make your own copy of it on BitBucket and then clone that repository (these options can be found under the '...' button on the left hand sidebar).  Once you've cloned the source code onto your machine you can run the installation script found at 'deploy/install2dir.py'.  The script takes a single argument, the path of the directory that Playground should be installed in - an example usage is `$ python install2dir.py /Documents/Playground`.

The installation script will move all of the source files to the named directory, creating a directory named 'src' with the necessary files in it.  Once you've verified that that directory was created you've finished installation!

## The Simplest Playground Network

Once you have all the dependencies installed you can set up a simple Playground network as a proof of concept.  This network will have a Chaperone and two nodes running on it, each running the apps/samples/echotest code.  When running Playground code its necessary to either run it from the src directory or to include that directory in your path like the following `$ PYTHONPATH=<path/to/src> python ...`  

In order to run our network we'll need 3 terminals - one to be the Chaperone, on to be the Client and one to be the Server.  Open three terminal windows and run the following commands:

```
# In Terminal 0:
$ python Chaperone.py
# In Terminal 1:
$ python -m apps.samples.echotest localhost 9090 0
# In Terminal 2:
$ python -m apps.samples.echotest localhost 9090 1
```
Once you've done this the echotest client should ask you to input some messages and, after you've input them, should echo them back to you. Once you see the messages echod back to you you've succesfully set up you network!


A little bit of explanation - the echotest program takes three options, the IP address of the Chaperone, the port of the Chaperone and a flag to determine if it is the server or the client.  Here the IP address of the Chaperone is imply `localhost` as the Chaperone is running locally on our machine.  The default port here is `9090`.  If the third option is a 1 then we're running a server, a 0 and we're running a client.  For further instructions on how to setup more complicated networks see 'documentation/Playground_Setup.pdf'.

## Learning the Framework
The best way to learn how to create Playground programs is to do it yourself, which we'll do in a moment.  But in order to have some understanding of how to make our own service we'll read through some of the sample code first.  A more in depth look at this code in 'documentation/Playground_Framework.py'. 

**Import Playground Information**  
In order to understand any Playground code it is important to understand the two main bulding blocks in a Playground application - Protocols and Factories.  Protocols serve two purposes, they define what messages look like and they serve as responses to events.  Factories use the later type of protocol and respond to events with them.  For example a protocol might dictate what to do when a message is received, and then whenever a message is received a factory would create that protocol object and pass it the message.

### Reading Echotest.py
First we'll read through the program we ran earlier - echotest.py.  It can be found under 'src/apps/samples/echotest.py'.  Open it up with your favorite editor, grab a mug of your favorite hot beverage, curl up by a fire and lets get to reading!

The first thing to note is the comment at the top that states that this program does not use the PlaygroundNode Interface - useful information but it means nothing to us for now.  The next twenty lines or so after this is imports which we'll ignore for now.  After this lines 36 - 60 outline a class called EchoProtocolMessage.

**Echo Protocol Message**  
Echo Protocol Message acts as the template for a message that follows the "echo protocol".  This is the first kind of protocol we talked about above, a message protocol.  An Echo Protocol Message has a unique identifier, a version and an xml-like layout of what goes in a message - in this case a boolean and a string.

**Echo Server Protocol**  
After the Echo Protocol Message comes the Echo Server Protocol.  This is the second kind of protocol we talked about, an event protocol, it will handle any incoming messages to the server.  Looking at its init() method we see it calls the init of SimpleMessageHandlingProtocol and then calls registerMessageHandler() and passes in its own handleEchoMessage() method. This method is part of the Twisted framework and is setting up the protocol to receive EchoProtocolMessages.

The next method, handleEchoMessage(), dictates what will actually happen when a message is received.  From experience we know that upon receiving a message the server will echo it back, but lets look at how it does it.  First it uses `msgObj = msg.data()` to convert the message into a data object.  Next we create a responseMessageBuilder that will, unsurprisingly, build the message we're going to send back.  The type of message the responseMessageBuilder builds will be a "TestEchoProtocolMessageID", which is the PLAYGROUND_IDENTIFIER we assigned to the EchoProtocolMessage earlier. Into the "original" field we place false (this in the reponse, not the original) and into the "data" field we copy the data from the message we were sent.  Then we send the message off using self.transport.writeMessage to send off the message we just built.

**Echo Client Response**  
This class is a simple I/O class that will accept messages and print them out, putting some banner in front of them.

**Echo Client Protocol**  
This is the mirror to Echo Server Protocol - its what the client uses to handle different events.  In its init method it follows the same steps as the Echo Server Protocol, setting itself up as a SimpleMessageHandlingProtocol and registering a Message Handler.  It also sets itself as "unconnected" and sets up a backlog - until it is connected any messages it receives will go in the backlog until they can be sent.  Once it is connected connectionMade() will be called and send out all of the messages in the backlog.  Until it is connected sendMessage() will deposit any messages it receives in the backlog - after it has connected sendMessage() will pass the message on to sendMessageActual() instead.

sendMessageActual() goes through the same process we saw above with a Message Builder that constructs the message and then sends it out - but this time we use self.transport.write() instead of self.transport.writeMessage(), so we need to explicitly serialize the message ourselves.

**Echo Server and Echo Client Factory**  
Both of these classes serve simply to define which protocol we should use, the Echo Server Protocol for the server and Echo Client Protocol for the client.  Which one we use depends on what mode we're running in.

**Client Test**
This is the class that will be responsible for invoking the Echo Client Protocol and using it to send the user's inputted messages.

**Main**  
For anyone unfamiliar with python the `if __name__ == __main__` syntax may look weird, but this is how python handles its main - essentially this will only execute the following code only if this file is the one that was evoked, not if its included in another file or imported into an environment.

The first part of main runs in both the client and the server.  It sets up our network connection using PlaygroundAddress(), which we will later use to register it with the Chaperone.

Next we get into the Server/Client specific actions.  The server creates an Echo Server Factory (which we know will produce EchoServerProtocols in response to incoming messages). It then specifies a port to listen on and then connects to the Chaperone.  As of this point we're all ready to receive messages!

The client first sets up a PlaygroundAddress for the server it wants to contact.  Next it sets up a Protocol Factory similarly to what the server did.  After that it prompts the user for 5 strings that it sends out as messages using the ClientTest class.  Finally it connects to Playground.

