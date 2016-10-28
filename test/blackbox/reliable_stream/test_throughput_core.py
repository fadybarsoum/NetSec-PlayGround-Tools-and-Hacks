
from playground.network.message.StandardMessageSpecifiers import UINT4, STRING
from playground.network.common import PlaygroundAddress, Packet
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message import MessageData

import hashlib, random, time

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from playground.network.common.Protocol import MessageStorage
from playground.twisted.endpoints.GateEndpoint import GateServerEndpoint, GateClientEndpoint
from twisted.internet.endpoints import connectProtocol

class DataMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "test.blackbox.reliable_stream.throughput.DataMessage"

    MESSAGE_VERSION = "1.0"
    BODY = [
            ("sender_testid", STRING),
            ("txId", UINT4),
            ("hash", STRING),
            ("data", STRING)
            ]
    
class ThroughputTestControl(object):
    # transmission def = (ID, TYPE, TYPE_ARGS)
    # parameters: delay = (Constant, n), (Random, range)
    TX_TYPE_FIXED = "FIXED"
    TX_TYPE_RANDOM = "RANDOM"
    TX_TYPE_REPEATING = "REPEATING"
    
    DEFAULT_TX_DELAY = 1.0
    DEFAULT_TEST_NO_ACTIVITY_TIMEOUT = 45.0
    
    def __init__(self, testId, transmissions, **parameters):
        self.testId = testId
        self.transmissions = transmissions
        self.parameters = parameters
        self.testsReceived = {}
        self.testEnded = False
        self.protocol = None
        self.lastActivity = time.time()
        self.noActivityTimeout = parameters.get("noActivityTimeout", self.DEFAULT_TEST_NO_ACTIVITY_TIMEOUT)
        self.totalBytes = 0
        self.startTime = 0
        self.endTime = 0
    
    def startTest(self, protocol):
        print "start test", self.parameters.get("txDelay", self.DEFAULT_TX_DELAY)
        self.protocol = protocol
        txDelay = self.parameters.get("txDelay", self.DEFAULT_TX_DELAY)
        self.startTime = time.time()
        reactor.callLater(txDelay, self.processNextTransmission)
        self.lastActivity = time.time()
        reactor.callLater(self.noActivityTimeout, self.processActivityTimeout)
        cb = self.parameters.get("onConnect",None)
        if cb: cb(protocol)
        
    def endTest(self, protocol, reason):
        self.testEnded = True
        cb = self.parameters.get("onEnd",None)
        if cb: cb(reason)
        
    def started(self):
        self.startTime = time.time()
        return self.protocol != None
        
    def finished(self):
        return self.testEnded
    
    def totalReceived(self):
        return self.totalBytes
    
    def totalTime(self):
        return self.endTime - self.startTime
        
    def processNextTransmission(self):
        if not self.transmissions: 
            print self.testId,"out of transmissions. Let the protocol know"
            self.protocol.close()
            return
        if self.testEnded: return
        self.lastActivity = time.time()
        nextTransmissionDefinition = self.transmissions.pop(0)
        txId, txType, txArgs = nextTransmissionDefinition
        if txType == self.TX_TYPE_REPEATING:
            s, count = txArgs
            data = s * count
        elif txType == self.TX_TYPE_FIXED:
            data, = txArgs
        elif txType == self.TX_TYPE_RANDOM:
            count, = txArgs
            data = "".join([chr(random.getrandbits(8)) for _ in xrange(count)])#random._urandom(count)
        else:
            raise Exception("Unknown transmission type %s" % txType)
        self.protocol.send(data, txId)
        cb = self.parameters.get("onSend",None)
        if cb: cb(txId)
        txDelay = self.parameters.get("txDelay",self.DEFAULT_TX_DELAY)
        reactor.callLater(txDelay, self.processNextTransmission)
        
    def txReceived(self, senderTestid, txId, bytes, success):
        if not senderTestid:
            # intermediate update
            self.lastActivity = time.time()
            return
        self.totalBytes += bytes
        self.endTime = time.time()
        self.lastActivity = time.time()
        if not self.testsReceived.has_key(senderTestid):
            self.testsReceived[senderTestid] = {}
        if not self.testsReceived.has_key(txId):
            self.testsReceived[senderTestid][txId] = []
        self.testsReceived[senderTestid][txId].append(success)
        cb = self.parameters.get("onRecv",None)
        if cb: cb(txId, success)
        
    def iterResults(self):
        for senderTestId in self.testsReceived.keys():
            txIds = self.testsReceived[senderTestId].keys()
            txIds.sort()
            for txId in txIds:
                result = self.testsReceived[senderTestId][txId]
                yield (senderTestId, txId, result)
                
    def processActivityTimeout(self):
        if self.lastActivity and self.lastActivity + self.noActivityTimeout < time.time():
            print "Activity timeout"
            self.endTest(self.protocol, "timeout")
            if self.protocol and self.protocol.transport:
                self.protocol.transport.loseConnection()
        elif self.lastActivity:
            reactor.callLater(self.noActivityTimeout, self.processActivityTimeout)
            
    def disableActivityTimeout(self):
        self.lastActivity = None

class TestThroughputProtocol(Protocol):
    def __init__(self, factory, testControl):
        self.factory = factory
        self.control = testControl
        self.sendDone = False
        self.recvDone = False
        self.messageStorage = MessageStorage()
        
    def dataReceived(self, data):
        self.control.txReceived(None, None, len(data), False)
        self.messageStorage.update(data)
        for msg in self.messageStorage.iterateMessages():
            self.handleData(msg)
        
    def connectionMade(self):
        print "connection made"
        Protocol.connectionMade(self)
        self.control.startTest(self)
        
    def connectionLost(self, reason=None):
        print "Connection lost", reason
        Protocol.connectionLost(self, reason=reason)
        self.control.endTest(self, reason)
        
    def send(self, data, txId):
        dataMessage = DataMessage(sender_testid=self.control.testId,
                                     txId=txId, 
                                     hash=hashlib.sha1(data).hexdigest(),
                                     data=data)
        serialized = dataMessage.__serialize__()
        #print "test deserialize"
        #DataMessage.Deserialize(serialized)
        self.transport.write(dataMessage.__serialize__())
        
    def close(self):
        if self.sendDone:
            return
        self.sendDone = True
        print "sending empty hash message"
        dataMessage = DataMessage(sender_testid="",
                                  txId = 0,
                                  hash = "",
                                  data="")
        self.transport.write(dataMessage.__serialize__())
        if self.recvDone:
            print "receive already done, close transport"
            self.transport.loseConnection()
        
    def handleData(self, msg):
        msgObj = msg
        if self.recvDone or msgObj.hash == "":
            print self.control.testId,"received shutdown message"
            self.recvDone = True
            self.control.disableActivityTimeout()
            if self.sendDone:
                self.transport.loseConnection()
            return
        trueHash = hashlib.sha1(msgObj.data).hexdigest()
        print "Received data", msgObj.txId, trueHash, msgObj.hash
        self.control.txReceived(msgObj.sender_testid, msgObj.txId, 
                                len(msgObj.data),
                                (trueHash==msgObj.hash))
        
class TestThroughputFactory(Factory):
    def __init__(self, control):
        self.control = control
        
    def buildProtocol(self, addr):
        return TestThroughputProtocol(self, self.control)

class TestLauncher(object):
    def __init__(self, gateAddr, gatePort):
        self.gateAddr = gateAddr
        self.gatePort = gatePort
        
    def shutdown(self,delay=1):
        reactor.callLater(delay, reactor.stop)
    #    if self.client:
    #        reactor.callLater(delay, lambda: self.client.disconnectFromPlaygroundServer(stopReactor=True))
        
    def startTest(self, testControl, serverAddr, serverPort, stack=None):
    
        #logctx = playgroundlog.LoggingContext()
        #logctx.nodeId = myAddress.toString()
    
        #logctx.doPacketTracing = True
        #playgroundlog.startLogging(logctx)
        
        throughputFactory = TestThroughputFactory(testControl)
        
        if serverAddr == None:
            print "Starting server on port", serverPort
            serverEP = GateServerEndpoint(reactor, serverPort, self.gateAddr, self.gatePort, networkStack=stack)
            serverEP.listen(throughputFactory)
            #self.client.listen(throughputFactory, serverPort, connectionType)
        else:
            serverAddr = PlaygroundAddress.FromString(serverAddr)
            print "connecting client to", serverAddr, serverPort
            clientEP = GateClientEndpoint(reactor, serverAddr, serverPort, self.gateAddr, self.gatePort, networkStack=stack)
            testProtocol = throughputFactory.buildProtocol(None)
            connectProtocol(clientEP, testProtocol)
        
        reactor.run()
