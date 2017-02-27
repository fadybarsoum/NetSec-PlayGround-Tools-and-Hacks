
from twisted.internet import stdio
from twisted.internet.task import deferLater
from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver

from playground import playgroundlog
from playground.network.gate import Service, ConnectionData
from playground.network.gate.Service import HPService
from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler

import sys, os, logging

class GateStarter(LineReceiver):
    delimiter = os.linesep

    def __init__(self, log, chapAddr, chapPort, gatesFile = None):
        self.logger=log

        self.gates = dict()
        self.gatePort= 25600 # starting gate ports

        # Target Chaperone
        print("Starting Gates against Chaperone %s:%s" % (chapAddr,chapPort))
        self.chapAddr = chapAddr
        self.chapPort = chapPort

        gatesFile and self.pullGateAddressesFromFile(gatesFile)

    # Command line input. For now interpret as Gate Address
    def lineReceived(self, input):
        words = input.split(" ")
        self.createGate(words[0])
        deferLater(reactor, .1, self.reset)

    def createGate(self, gateAddrString, gatePort = "default", serviceClass = Service):
        if gateAddrString in self.gates:
            return False
        if gatePort == "default":
            gatePort = self.gatePort
        g2gConnect = ConnectionData(self.chapAddr,self.chapPort,self.gatePort, gateAddrString)
        self.gates[gateAddrString] = self.gatePort
        self.gatePort += 1

        self.logger = playgroundlog.LoggingContext("GATE_%s" % g2gConnect.playgroundAddr)
        serviceClass.Create(reactor, g2gConnect)
        return g2gConnect # return the "gate key" connection data

    def createHPGate(self, gateAddrString, gatePort = "default"):
        return self.createGate( gateAddrString, gatePort = self.gatePort, serviceClass = HPService)

    def createGates(self, addrlist):
        newCount = 0
        for addr in addrlist:
            if self.createGate(addr):
                newCount+=1
        return newCount

    # Not yet called nor tested
    def pullGateAddressesFromFile(self, filename):
        try:
            templist = []
            with open(filename, "r") as gFile:
                for addr in gFile: # each address will be on its own line
                    templist.append(addr)
            
            print("%s new gates pulled from %s in file" % (self.createGates(templist), len(templist)))

            # Uncomment below to continually check the file for changes
            #deferLater(reactor, 2, pullGateAddressesFromFile)
        except:
            print("[ERROR] Could not find file?")

    # Displays the command line entry prompt
    def reset(self):
        self.transport.write("\n[Active gates: %s] Start gate at Playground address: " % len(self.gates))

USAGE = """usage: startGates --cA=<chaperoneIPAddress> --cP=<chaperoneIPPort> --gFile=<gateAddressesFile>"""

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
    gatesFile = gstarArgs.get("--gFile", None)

    # Do logging things
    logger = logging.getLogger(__name__)
    logctx = playgroundlog.LoggingContext("GATESTARTER_MAIN")

    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True

    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)

    # Start the Gate Starter
    starter = GateStarter(logctx, chapAddr, chapPort, gatesFile)
    deferLater(reactor, .2, starter.reset)
    stdio.StandardIO(starter)

    TwistedShutdownErrorHandler.HandleRootFatalErrors()   
    reactor.run()