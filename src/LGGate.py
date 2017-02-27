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

def createLGService(gatekey=None, logger = None):
    g2gConnect = ConnectionData.CreateFromConfig(gatekey)
    return LGService.CreateFromConfig(reactor, gatekey).grabber

if __name__=="__main__":
    # Do logging things
    logctx = playgroundlog.LoggingContext("GATE_MAIN")
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True
    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)
    TwistedShutdownErrorHandler.HandleRootFatalErrors()

    createLGService().isMain = True
    deferLater(reactor, .75, reactor.stop)
    reactor.run()