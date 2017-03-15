'''
Created on Feb 25, 2017

@author: fml
'''

# Import playgroundlog to enable logging
from playground import playgroundlog

# We will use "BOOL1" and "STRING" in our message definition
from playground.network.message.StandardMessageSpecifiers import BOOL1, STRING

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import MessageStorage

from playground.twisted.endpoints import GateServerEndpoint
from playground.network.common.Timer import callLater
from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler

from twisted.internet import reactor
from twisted.internet.endpoints import connectProtocol
from twisted.internet.protocol import Protocol, Factory, connectionDone

import sys, os, logging
from LGGate import createLGService
from startGates import GateStarter

class HoneypotServerProtocol(Protocol):
    """
    This is our class for the Server's protocol. It simply receives
    an EchoProtocolMessage and sends back a response
    """
    def __init__(self):
        self.msgs = MessageStorage()
        
    def connectionLost(self, reason=connectionDone):
        print "Lost connection to client. Cleaning up."
        Protocol.connectionLost(self, reason=reason)
        
    def dataReceived(self, data):
        print("HP got: %s" % data)
        self.msgs.update(data)

        try:
            for msg in self.msgs.iterateMessages():
                self.processMessage(msg)
        except Exception, e:
            print "We had a deserialization error", e  
    
    def processMessage(self, msg):
        print(msg.__class__.__name__)
        print(msg)
        
class HoneypotServerFactory(Factory):
    protocol=HoneypotServerProtocol

def maintainGates(hpFactory,port,stack,logerror,grabber,starter):
    for addr in grabber.latestpeers:
        g2gconn = starter.createHPGate(addr)
        if g2gconn:
            callLater(.25, connectEndpointToGate, port, g2gconn,stack,hpFactory,logerror)
    grabber.updateList()
    callLater(1, maintainGates, hpFactory, port, networkStack,logerror, grabber,starter)

def connectEndpointToGate(port,g2gconn, stack, hpFactory, logerror):
    hpServerEndpoint = GateServerEndpoint(reactor, port, "127.0.0.1", g2gconn.gatePort, stack)
    d = hpServerEndpoint.listen(hpFactory)
    d.addErrback(logerror)

if __name__=="__main__":
    # Parse args
    gstarArgs = {}
    args= sys.argv[1:]
    i = 0
    for arg in args:
            if arg.startswith("-"):
                k,v = arg.split("=")
                gstarArgs[k]=v
            else:
                gstarArgs[i] = arg
                i+=1

    # Get the args you need
    chapAddr = gstarArgs.get("--cA", "127.0.0.1")
    chapPort = gstarArgs.get("--cP", "9090")

    gateKey = None # generated on the fly for each gate
    stack = None #"passthru"
    # playground port number - make sure this matches the one in playground.network.gate.Service.HPService.dmux(...)
    portNum = 9876
    if stack:
        exec("import " + stack)
        networkStack = eval(stack)
    else:
        networkStack = None
    
    # Do logging things
    logger = logging.getLogger(__name__)
    logctx = playgroundlog.LoggingContext("GATESTARTER_")

    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True

    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)

    # start grabber
    grabber = createLGService()

    # start gate starter
    starter = GateStarter(logctx, chapAddr, chapPort, None)

    # This guy will be the server. Create an instance of the factory
    hpProtocolServerFactory = HoneypotServerFactory()
    
    # tell the playground client to connect to playground server and start running
    callLater(1, maintainGates, hpProtocolServerFactory, portNum, networkStack, logger.error, grabber, starter)

    TwistedShutdownErrorHandler.HandleRootFatalErrors()
    reactor.run()
