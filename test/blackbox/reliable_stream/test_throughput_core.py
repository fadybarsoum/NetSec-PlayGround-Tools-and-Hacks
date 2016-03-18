
from playground.network.message.StandardMessageSpecifiers import UINT4, STRING
from playground.network.common import PlaygroundAddress, Packet
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message import MessageData
from playground.network.client.ClientApplicationServer import ClientApplicationServer, ClientApplicationClient
from playground.network.client import ClientBase

import hashlib, random, time

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
        self.protocol.callLater(txDelay, self.processNextTransmission)
        self.lastActivity = time.time()
        self.protocol.callLater(self.noActivityTimeout, self.processActivityTimeout)
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
            data = random._urandom(count)
        else:
            raise Exception("Unknown transmission type %s" % txType)
        self.protocol.send(data, txId)
        cb = self.parameters.get("onSend",None)
        if cb: cb(txId)
        txDelay = self.parameters.get("txDelay",self.DEFAULT_TX_DELAY)
        self.protocol.callLater(txDelay, self.processNextTransmission)
        
    def txReceived(self, senderTestid, txId, bytes, success):
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
        if self.lastActivity + self.noActivityTimeout < time.time():
            self.endTest(self.protocol, "timeout")
            if self.protocol and self.protocol.transport:
                self.protocol.transport.loseConnection()
        else:
            self.protocol.callLater(self.noActivityTimeout, self.processActivityTimeout)

class TestThroughputProtocol(SimpleMessageHandlingProtocol):
    def __init__(self, factory, addr, testControl):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.registerMessageHandler(DataMessage, self.handleData)
        self.control = testControl
        self.sendDone = False
        self.recvDone = False
        
    def connectionMade(self):
        print "connection made"
        SimpleMessageHandlingProtocol.connectionMade(self)
        self.control.startTest(self)
        
    def connectionLost(self, reason=None):
        SimpleMessageHandlingProtocol.connectionLost(self, reason=reason)
        self.control.endTest(self, reason)
        
    def send(self, data, txId):
        messageBuilder = MessageData.GetMessageBuilder(DataMessage)
        messageBuilder["sender_testid"].setData(self.control.testId)
        messageBuilder["txId"].setData(txId)
        messageBuilder["hash"].setData(hashlib.sha1(data).hexdigest())
        messageBuilder["data"].setData(data)
        self.transport.writeMessage(messageBuilder)
        
    def close(self):
        if self.sendDone:
            return
        self.sendDone = True
        messageBuilder = MessageData.GetMessageBuilder(DataMessage)
        messageBuilder["sender_testid"].setData("")
        messageBuilder["txId"].setData(0)
        messageBuilder["hash"].setData("")
        messageBuilder["data"].setData("")
        self.transport.writeMessage(messageBuilder)
        if self.recvDone:
            self.transport.loseConnection()
        
    def handleData(self, protocol, msg):
        msgObj = msg.data()
        if self.recvDone or msgObj.hash == "":
            print self.control.testId,"received shutdown message"
            self.recvDone = True
            if self.sendDone:
                self.transport.loseConnection()
            return
        trueHash = hashlib.sha1(msgObj.data).hexdigest()
        print "Received data", msgObj.txId, trueHash, msgObj.hash
        self.control.txReceived(msgObj.sender_testid, msgObj.txId, 
                                len(msgObj.data),
                                (trueHash==msgObj.hash))
        
class TestThroughputFactory(ClientApplicationServer):
    def __init__(self, control):
        self.control = control
        
    def buildProtocol(self, addr):
        return TestThroughputProtocol(self, addr, self.control)

class TestLauncher(object):
    def __init__(self, chaperoneAddr, chaperonePort):
        self.chaperoneData = (chaperoneAddr, chaperonePort)
        self.client = None
        
    def shutdownPlayground(self):
        if self.client:
            self.client.disconnectFromPlaygroundServer(stopReactor=True)
        
    def startTest(self, testControl, addr, serverAddr, serverPort):
    
        #logctx = playgroundlog.LoggingContext()
        #logctx.nodeId = myAddress.toString()
    
        #logctx.doPacketTracing = True
        #playgroundlog.startLogging(logctx)
    

        self.client = ClientBase(PlaygroundAddress.FromString(addr))
        chaperoneAddr, chaperonePort = self.chaperoneData
        
        throughputFactory = TestThroughputFactory(testControl)
        
        if serverAddr == None or serverAddr == addr:
            print "Starting server on", addr, serverPort, serverAddr
            self.client.listen(throughputFactory, serverPort, connectionType="RELIABLE_STREAM")
        else:
            serverAddr = PlaygroundAddress.FromString(serverAddr)
            print "connecting client to", serverAddr, serverPort
            self.client.runWhenConnected(lambda: self.client.connect(throughputFactory, 
                                                                serverAddr, 
                                                                serverPort,
                                                                connectionType="RELIABLE_STREAM"))
        
        self.client.connectToChaperone(chaperoneAddr, chaperonePort)
