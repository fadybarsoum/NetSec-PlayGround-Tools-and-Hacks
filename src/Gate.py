'''
Created on Sep 10, 2016

@author: sethjn
'''

from playground import playgroundlog
from playground.network.gate import Service, ConnectionData
from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler
from twisted.internet import reactor
import sys

if __name__=="__main__":
    gateConfig = len(sys.argv) == 2 and sys.argv[1] or None
    g2gConnect = ConnectionData.CreateFromConfig(gateConfig)
    logctx = playgroundlog.LoggingContext("GATE_%s" % g2gConnect.playgroundAddr)
    
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True

    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)
    TwistedShutdownErrorHandler.HandleRootFatalErrors()
    Service.CreateFromConfig(reactor, gateConfig)
    reactor.run()