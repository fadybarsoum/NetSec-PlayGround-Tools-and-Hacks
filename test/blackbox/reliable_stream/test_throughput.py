import framework, sys, time

class ThroughputTestPeer(framework.TestPeer):
    def __init__(self, testId):
        framework.TestPeer.__init__(self, testId)
        self.chaperoneAddr = None
        self.chaperonePort = None
        self.addr = None
        self.serverAddr = None
        self.serverPort = None
        self.playgroundPath = None
        
    def _realStart(self, transmissions, **parameters):
        sys.path.insert(0, self.playgroundPath)
        import playground
        print "Starting test for", playground
        import test_throughput_core as core
        from playground import playgroundlog
        #playgroundlog.g_Ctx = ForcePacketTrace()
        self.control = core.ThroughputTestControl(self.testId(), transmissions, 
                                                  onEnd=self.onTestEnd,
                                                  onConnect=self.onTestConnect,
                                                  txDelay=.1)
        self.testLauncher = core.TestLauncher(self.chaperoneAddr, self.chaperonePort)
        self.setSharedData("STARTED",True)
        self.testLauncher.startTest(self.control, self.addr, self.serverAddr, self.serverPort)
        
    def onTestEnd(self, reason):
        print self.testId(), "Test completed. Shutting down", reason
        print "received", self.control.totalReceived()
        print "time", self.control.totalTime()
        print "Throughput: %f bytes/sec" % (self.control.totalReceived()/self.control.totalTime())
        self.setSharedData("THROUGHPUT", (self.control.totalReceived()/self.control.totalTime()))
        self.setSharedData("FINISHED",True)
        results = list(self.control.iterResults())
        self.setSharedData("RESULTS",results)
        self.testLauncher.shutdownPlayground()
        
    def onTestConnect(self, protocol):
        print self.testId(), "Connected"
        if self.sharedData("CONNECTED", False):
            print "Already Connected! Exiting!"
            self.onTestEnd("Connected more than once!")
        self.setSharedData("CONNECTED",True)
        
    def connected(self):
        return self.sharedData("CONNECTED",False)
    
    def started(self):
        return self.sharedData("STARTED",False)
    
    def finished(self):
        return self.sharedData("FINISHED",False)
    
    def results(self):
        return self.sharedData("RESULTS",[])
    
    def throughput(self):
        return self.sharedData("THROUGHPUT",0.0)

class NetSecSpring2016_ReliableTest(object):
    SERVER_ADDRESS = "20161.0.1000.1"
    CLIENT_ADDRESS = "20161.0.1000.2"
    SERVER_PORT = 1000
    def __init__(self):
        pass
    
    def _getTransmissionTemplates(self):
        return [
                 (1100, "FIXED", ("Hello World",)),
                 (1200, "REPEATING", ("1",1) ),
                 (1201, "REPEATING", ("100",100) ),
                 (1202, "REPEATING", ("100,000",100000) ),
                 (1300, "RANDOM", (1,)),
                 (1301, "RANDOM", (1000,)),
                 (1302, "RANDOM", (10000,)),
                 (1303, "RANDOM", (100000,)),
                 (1304, "RANDOM", (1000000,))
                 ]
        
    def _configureTestPeer(self, testPeer, isServer):
        testPeer.chaperoneAddr = "127.0.0.1"
        testPeer.chaperonePort = 9090
        if isServer:
            testPeer.addr = self.SERVER_ADDRESS
        else:
            testPeer.addr = self.CLIENT_ADDRESS
            testPeer.serverAddr = self.SERVER_ADDRESS
        testPeer.serverPort = self.SERVER_PORT
        
    def syncWait(self, condition, wait, gran=1.0):
        count = 0
        while count < wait:
            if not condition():
                time.sleep(gran)
                count += gran
            else: break
        return condition()
        
    def runTest(self, clientPlaygroundPath, serverPlaygroundPath, **chaperoneArgs):
        framework.g_Mailbox["RESULTS"] = framework.g_Manager.list()
        chaperone = framework.ChaperoneControl()
        chaperone.start(**chaperoneArgs)
        print "waiting for chaperone"
        result = self.syncWait(chaperone.running, 10)
        if not result:
            print "Could not start chaperone. Exiting"
            chaperone.stop()
            return
        
        client = ThroughputTestPeer("ThroughputClient")
        server = ThroughputTestPeer("ThroughputServer")
        self._configureTestPeer(client, isServer=False)
        self._configureTestPeer(server, isServer=True)
        client.playgroundPath = clientPlaygroundPath
        server.playgroundPath = serverPlaygroundPath
        server.start(self._getTransmissionTemplates())
        print "waiting for server"
        result = self.syncWait(server.started, 10)
        if not result:
            print "Could not start server. Exiting"
            chaperone.stop()
            server.stop()
            return
        
        templates = self._getTransmissionTemplates()
        client.start(templates)
        result = self.syncWait(client.connected, 20)
        if result:
            result = self.syncWait(server.connected, 20)
        if not result:
            print "Could not connect client and/or server. Exiting"
            chaperone.stop()
            server.stop()
            client.stop()
            chaperone.join(), server.join(), client.join()
            return
        client.join()
        server.join()
        chaperone.stop()
        chaperone.join()
        testFinished = True
        print "TEST COMPLETE. DATA:"
        stats = chaperone.statistics()
        if stats:
            for k,v in stats.items():
                print "\t%s: %s" % (k,v)
        else:
            print "No chaperone stats"
        if not client.finished():
            print "Client did not finish. TestFailed"
        else:
            results = client.results()
            testsPassed = []
            testsFailed = []
            for template in templates:
                testNumber = template[0]
                if (server.testId(), testNumber, [True]) not in results:
                    testsFailed.append(testNumber)
                else: testsPassed.append(testNumber)
            print "Client successfully received server-sent tests %s" % testsPassed
            if testsFailed:
                print "Client did not receive/pass server-sent tests %s" % testsFailed
            print "Client throughput: ", client.throughput()    
        if not server.finished():
            print "Server did not finish. Test Failed"
        else:
            results = server.results()
            testsPassed = []
            testsFailed = []
            for template in templates:
                testNumber = template[0]
                if (client.testId(), testNumber, [True]) not in results:
                    testsFailed.append(testNumber)
                else: testsPassed.append(testNumber)
            print "Server successfully received server-sent tests %s" % testsPassed
            if testsFailed:
                print "Server did not receive/pass server-sent tests %s" % testsFailed
            print "Server throughput: ", server.throughput()  
    
class ForcePacketTrace(object):
    def __init__(self):
        self.doPacketTracing=True
if __name__=="__main__":
    import logging
    logging.getLogger("").setLevel("ERROR")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setFormatter(formatter)
    logging.getLogger("").addHandler(stdoutHandler)
    test = NetSecSpring2016_ReliableTest()
    
    print "RUN TEST WITHOUT ERRORS"
    test.runTest(sys.argv[1], sys.argv[2])
    
    for i in [10,30,50,70,90]:
        errorRate = (0,i,1000000)
        lossRate = (0,int(i/10),1000)
        print "\n\nRUN TEST WITH ERROR RATE = %s, LOSS = %s" % (errorRate, lossRate)
        test.runTest(sys.argv[1], sys.argv[2], errorRate=errorRate, lossRate=lossRate)