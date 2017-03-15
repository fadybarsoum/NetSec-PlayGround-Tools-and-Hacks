'''
Created on Feb 25, 2017

@author: fml
'''

from playground import playgroundlog
from playground.network.gate import ConnectionData
from playground.network.gate.Service import LGService
from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler
from twisted.internet.task import deferLater
from twisted.internet import reactor
import sys

def createLGService(gatekey=None, logger = None, chapAddr = "127.0.0.1", chapPort = "9090"):
    print("createLGService() called: %s" % chapAddr)
    g2gConnect = ConnectionData(chapAddr,chapPort,19090, "1.1.1.1")
    return LGService.Create(reactor, g2gConnect).grabber

if __name__=="__main__":
    args= sys.argv[1:]
    if len(args) > 0:
        chapAddr = args[0]
    else:
        chapAddr = "127.0.0.1"
    if len(args) > 1:
        chapPort = args[1]
    else:
        chapPort = "9090"
    # Do logging things
    logctx = playgroundlog.LoggingContext("GATE_MAIN")
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True
    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)
    TwistedShutdownErrorHandler.HandleRootFatalErrors()
    
    createLGService(chapAddr = chapAddr, chapPort = chapPort).isMain = True
    deferLater(reactor, .75, reactor.stop)
    reactor.run()
