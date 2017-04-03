'''
Created by FMLB
March 29, 2017

Flood bot with reprogram ADDRESS packets with random addresses and passwords.
This helps to lose trackers and crackers by flooding our bot with multiple
reprogram ADDRESS commands with different addresses and incorrect passwords
such that someone would have to open listeners to all the addresses to try
and find the one our bot was actually moved to.

Adjust noiseSignalRatio based on Eve's capabilities

TODO:
- Make it functional by tying to bot.client.ReprogrammingClientProtocol
- Also send a reprogram PASSWORD to the actual new address (such that it
would be difficult to snoop it unless Eve has a robust and quick wiretap)
'''

from random import randint
from bot.common.network import ReprogrammingResponse, ReprogrammingRequest
from bot.common.util import InsertChecksum

from twisted.internet.protocol import Protocol
from playground.network.common.Protocol import MessageStorage
from twisted.internet.defer import Deferred
from playground.twisted.endpoints.GateEndpoint import GateClientEndpoint, PlaygroundNetworkSettings
from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.internet.endpoints import connectProtocol

# these are playground utils
from playground.utils.ui import CLIShell, stdio
from playground import playgroundlog

import sys, os, traceback, getpass
try:
    import ProtocolStack
except:
    print "WARNING, NO PROTOCOL STACK. RAW COMMUNICATIONS ONLY"
    ProtocolStack = None


class ReprogrammingClientProtocol(Protocol):
    def __init__(self):
        self.__storage = MessageStorage(ReprogrammingResponse)
        self.__requests = {}
        self.__reqId = 0
        
    def __nextId(self):
        self.__reqId += 1
        return self.__reqId
        
    def dataReceived(self, data):
        self.__storage.update(data)
        #print("\nReceived from %s ->" % self.transport.getPeer())
        for message in self.__storage.iterateMessages():
            if not self.__requests.has_key(message.RequestId):
                continue
            #print "getting callback for requestId", message.RequestId
            d = self.__requests[message.RequestId]
            d.callback(message.Data)
        
    def reprogram(self, password, subsystem, data, *additionalSubsystems):
        if len(additionalSubsystems) % 2 != 0:
            raise Exception("Arguments to reprogram is both a subsystem and the data")
        req = ReprogrammingRequest(RequestId=self.__nextId(),
                                   Opcode   =0)
        
        subsystems = [subsystem]
        programs = [data]
        
        while additionalSubsystems:
            subsystems.append(additionalSubsystems.pop(0))
            programs.append(additionalSubsystems.pop(0))
            
        subsystems = map(ReprogrammingRequest.SUBSYSTEMS.index, subsystems)
    
        req.Subsystems = subsystems
        req.Data = programs
        
        InsertChecksum(req, password=password)
        self.__requests[req.RequestId] = Deferred()
        self.transport.write(req.__serialize__())
        return self.__requests[req.RequestId]
    
    def status(self, password, *subsystems):
        subsystems = map(ReprogrammingRequest.SUBSYSTEMS.index, subsystems)
        req = ReprogrammingRequest(RequestId =self.__nextId(),
                                   Opcode    =1,
                                   Subsystems=subsystems,
                                   Data      =[])
        InsertChecksum(req, password=password)
        self.__requests[req.RequestId] = Deferred()
        self.transport.write(req.__serialize__())
        return self.__requests[req.RequestId]
    
    
class ReprogrammingShellProtocol(CLIShell):
    PROMPT = "<Reprogramming Shell>"
    
    RAW_PORT = 666
    ADV_PORT = 667
    
    def __init__(self, botAddress):
        CLIShell.__init__(self, prompt=self.PROMPT)
        self.__botAddress = botAddress
        self.__connectPort = self.RAW_PORT
        self.protocol = None
        self.password = "123456"
        self.toPassword = "NotSetYet"
        self.deferreds = []
        self.success = False
        self.finalAddr = "notsetyet"
        
    def connectionMade(self):
        self.connectToBot(self.__connectPort)
        self.__loadCommands()
        
    def __botConnectionMade(self, protocol):
        self.transport.write("Connected to Bot at %s\n" % self.__botAddress)
        self.protocol = protocol
        self.prompt = "[%s::%d] >>" % (self.__botAddress, self.__connectPort)
        
        self.drownAddrRP(100)
        
    def reprogram(self, writer, *args):
        print("\tPassword: %s" % (self.password))
        print("Reprogram %s to %s" % (args[0],args[1]))
        if not self.protocol:
            writer("Not yet connected. Cannot reprogram\n")
            return 
        subsystem, reprogramArgument = args
        if subsystem not in ReprogrammingRequest.SUBSYSTEMS:
            self.transport.write("Unknown subsystem %s. Options are %s." % (subsystem, ReprogrammingRequest.SUBSYSTEMS))
            return
        if subsystem in ["PASSWORD", "ADDRESS"]:
            dataToSend = reprogramArgument
        else:
            if not os.path.exists(reprogramArgument):
                self.transport.write("File not found %s" % reprogramArgument)
                return
            
            with open(reprogramArgument) as f:
                dataToSend = f.read()
        #writer("Sending %d byte program to subsystem %s\n" % (len(dataToSend), subsystem))
        d = self.protocol.reprogram(self.password, subsystem, dataToSend)
        d.addCallback(self.handleResponse)
        
    def __checkStatus(self, writer, *args):
        if not self.protocol:
            writer("Not yet connected. Cannot reprogram\n")
            return 
        subsystems = list(args)
        for subsystem in subsystems:
            if subsystem not in ReprogrammingRequest.SUBSYSTEMS:
                self.transport.write("Unknown subsystem %s. Options are %s." % (subsystem, ReprogrammingRequest.SUBSYSTEMS))
                return
        d = self.protocol.status(self.password, *subsystems)
        d.addCallback(self.handleResponse)
        
    def __changePassword(self, writer, *args):
        if args:
            writer("Change password takes no arguments.\n")
        self.password = getpass.getpass("Enter new bot password: ")
        
        writer("Password changed successfully.\n")
        
    def __loadCommands(self):
        toggleCommandHandler = CLIShell.CommandHandler("toggle","Toggle between raw and advanced connection",self.__toggleConnection)
        reprogramCommandHandler = CLIShell.CommandHandler("reprogram", "Reprogram the bot's subsystems", defaultCb=self.reprogram)
        getstatusCommandHandler = CLIShell.CommandHandler("status", "Get the bot's subsystems' status", defaultCb=self.__checkStatus)
        changePasswordCommandHandler = CLIShell.CommandHandler("passwd", "Change the bot's password", defaultCb=self.__changePassword)
        
        self.registerCommand(toggleCommandHandler)
        self.registerCommand(reprogramCommandHandler)
        self.registerCommand(getstatusCommandHandler)
        self.registerCommand(changePasswordCommandHandler)
        
    def __toggleConnection(self, writer):
        if self.__connectPort == self.RAW_PORT:
            self.connectToBot(self.ADV_PORT)
        else: self.connectToBot(self.RAW_PORT)
        
    def connectToBot(self, port):
        if self.protocol:
            self.transport.write("Closing old bot connection on %d\n" % self.__connectPort)
            self.protocol.transport.loseConnection()
            self.transport.write("Reloading protocol\n")
            self.protocol = None
            self.prompt = self.PROMPT
        self.__connectPort = port
        
        
        networkSettings = PlaygroundNetworkSettings()
        networkSettings.configureNetworkStack(port == self.ADV_PORT and ProtocolStack or None)
        playgroundEndpoint = GateClientEndpoint(reactor, self.__botAddress, port, networkSettings)
        
        #self.transport.write("Got Endpoint\n")
        reprogrammingProtocol = ReprogrammingClientProtocol()
        #self.transport.write("Got protocol. Trying to connect\n")
        d = connectProtocol(playgroundEndpoint, reprogrammingProtocol)
        #self.transport.write("Setting callback\n")
        d.addCallback(self.__botConnectionMade)
        d.addErrback(self.handleError)
        #self.transport.write("Waiting for callback\n")
    
    
    def handleResponse(self, data):
        #self.transport.write("Received response from server.\n")
        for serverString in data:
            if "uccessful" in serverString:
                self.transport.write("\t%s\n" % serverString)
                self.success = True
                print("Address: %s" % self.finalAddr)
                #self.protocol.transport.loseConnection()
        #self.refreshInterface()
            
    def handleError(self, failure):
        self.transport.write("Something went wrong: %s\n" % failure)
        self.refreshInterface()
        # swallow error

    def drownAddrRP(self, noiseSignalRatio = 200):
        minNSR = 25
        if noiseSignalRatio < minNSR:
            print("drownAddrRP(): Noise-to-signal ratio too low")
            return
        print("drownAddrRP() called with NSR = %s" % noiseSignalRatio)
        numBefore = randint(5, noiseSignalRatio-5)
        self.deferreds.append(deferLater(reactor, 0.010, self.noiseRP, numBefore, noiseSignalRatio))
        print("noiseRP() called (%s [] %s)" % (numBefore,noiseSignalRatio-numBefore))

    def noiseRP (self, numBefore, numTotal):
        #print("noiseRP() called (%s,%s)" % (numBefore,numTotal))
        if numBefore == 0:
            self.actualRPAddress()
            deferLater(reactor, 0.005, self.noiseRP, -1, numTotal-1)
        elif numTotal > 0:
            randPw = str(randint(0,999999))
            randPw = "0"*(6-len(randPw)) + randPw
            #print("initial rand pw")
            while randPw == self.password:
                randPw = str(randint(0,999999))
                randPw = "0"*(6-len(randPw)) + randPw
            #print("final rand pw")
            randAddr = "%s.%s.%s.%s" % (randint(374,99999),randint(374,99999),randint(374,99999),randint(374,999999))
            #print("rand address")
            d = self.protocol.reprogram(randPw, "ADDRESS", randAddr)
            d.addCallback(self.handleResponse)

            #print("calling deferLater")
            self.deferreds.append(deferLater(reactor, 0.005, self.noiseRP, numBefore - 1, numTotal - 1))
        elif self.success:
            print("Successful address reprogramming: %s" % (self.finalAddr))
        else:
            print("Address reprogramming not confirmed yet")

    def actualRPAddress(self):
        randAddr = "%s.66432.13056.%s" % ( randint(374,99999), randint(374,99999))
        print("actualRPAddress() called with actual address: %s" % randAddr)
        self.finalAddr = randAddr
        d = self.protocol.reprogram(self.password, "ADDRESS", randAddr)
        d.addCallback(self.handleResponse)

if __name__ == "__main__":
    gstarArgs = {}

    args = sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
            k,v = arg.split("=")
            gstarArgs[k]=v
        else:
            gstarArgs[i] = arg
            i+=1
    
    addr = gstarArgs[0]
    pswd = gstarArgs[1]
    
    protocol = ReprogrammingShellProtocol(addr)
    protocol.password = pswd
    stdio.StandardIO(protocol)

    reactor.run()