import framework, sys, time

class ThroughputTestPeer(framework.TestPeer):
    def __init__(self, testId, connectionType):
        framework.TestPeer.__init__(self, testId)
        self.chaperoneAddr = None
        self.chaperonePort = None
        self.addr = None
        self.serverAddr = None
        self.serverPort = None
        self.playgroundPath = None
        self.connectionType = connectionType
        
    def _realStart(self, transmissions, **parameters):
        sys.path.insert(0, self.playgroundPath)
        import playground
        print "Starting test for", self.playgroundPath, playground
        import test_throughput_core as core
        from playground import playgroundlog
        #playgroundlog.g_Ctx = ForcePacketTrace()
        self.control = core.ThroughputTestControl(self.testId(), transmissions, 
                                                  onEnd=self.onTestEnd,
                                                  onConnect=self.onTestConnect,
                                                  txDelay=.1)
        self.testLauncher = core.TestLauncher(self.chaperoneAddr, self.chaperonePort)
        self.setSharedData("STARTED",True)
        self.testLauncher.startTest(self.control, self.addr, self.serverAddr, 
                                    self.serverPort, self.connectionType)
        
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
    
    class Result(object):
        def __init__(self):
            self.client = ""
            self.server = ""
            self.clientPassCount = 0
            self.clientFailCount = 0
            self.serverPassCount = 0
            self.serverFailCount = 0
            self.bytesRouted = 0
            self.bytesDamaged = 0
            self.packSent = 0
            self.packDamaged = 0
            self.clientThroughput = 0.0
            self.serverThroughput = 0.0
            
        def toTuple(self):
            return (self.client, self.server,
                    self.clientPassCount, self.clientFailCount, 
                    self.serverPassCount, self.serverFailCount,
                    self.bytesRouted, self.bytesDamaged, self.packSent, self.packDamaged,
                    self.clientThroughput, self.serverThroughput)
    
    def __init__(self):
        self.allResults = []
        
    def __storeResult(self, res):
        self.allResults.append(res.toTuple())
        
    def saveResults(self, csvFilename):
        with open(csvFilename, "a") as f:
            for resTuple in self.allResults:
                f.write("%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%f,%f\n" % resTuple)
            
    
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
        
        storeResultData = self.Result()
        storeResultData.client = clientPlaygroundPath
        storeResultData.server = serverPlaygroundPath
        
        chaperone = framework.ChaperoneControl()
        chaperone.start(**chaperoneArgs)
        print "waiting for chaperone"
        result = self.syncWait(chaperone.running, 30)
        if not result:
            print "Could not start chaperone. Exiting"
            chaperone.stop()
            chaperone.join()
            return self.__storeResult(storeResultData)
        
        client = ThroughputTestPeer("ThroughputClient", "RELIABLE_STREAM")
        server = ThroughputTestPeer("ThroughputServer", "RELIABLE_STREAM")
        self._configureTestPeer(client, isServer=False)
        self._configureTestPeer(server, isServer=True)
        client.playgroundPath = clientPlaygroundPath
        server.playgroundPath = serverPlaygroundPath
        server.start(self._getTransmissionTemplates())
        print "waiting for server"
        result = self.syncWait(server.started, 15)
        if not result:
            print "Could not start server. Exiting"
            chaperone.stop()
            server.stop()
            chaperone.join(), server.join()
            return self.__storeResult(storeResultData)
        
        templates = self._getTransmissionTemplates()
        client.start(templates)
        result = self.syncWait(client.connected, 30)
        storeResultData.clientFailCount = len(templates)
        storeResultData.serverFailCount = len(templates)
        if result:
            result = self.syncWait(server.connected, 20)
        if not result:
            print "Could not connect client and/or server. Full stop on test"
            chaperone.stop()
            server.stop()
            client.stop()
            chaperone.join(), server.join(), client.join()
            return self.__storeResult(storeResultData)
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
                if k == "packetsRouted": 
                    storeResultData.packSent = int(v)
                elif k == "packetsDropped" or k == "packetsCorrupted":
                    storeResultData.packDamaged += int(v)
                elif k == "bytesRouted":
                    storeResultData.bytesRouted = int(v)
                elif k == "bytesCorrupted":
                    storeResultData.bytesDamaged += int(v)
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
            storeResultData.clientPassCount = len(testsPassed)
            storeResultData.clientFailCount = len(testsFailed)
            print "Client successfully received server-sent tests %s" % testsPassed
            if testsFailed:
                print "Client did not receive/pass server-sent tests %s" % testsFailed
            print "Client throughput: ", client.throughput()  
            storeResultData.clientThroughput = client.throughput()
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
            storeResultData.serverPassCount = len(testsPassed)
            storeResultData.serverFailCount = len(testsFailed)
            print "Server successfully received server-sent tests %s" % testsPassed
            if testsFailed:
                print "Server did not receive/pass server-sent tests %s" % testsFailed
            print "Server throughput: ", server.throughput()
            storeResultData.serverThroughput = server.throughput()
        return self.__storeResult(storeResultData)
    
def multiErrorRateTest(impl1, impl2, resultsFileName, errorRates=None):
    if not errorRates:
        errorRates = [0,10,20,30,40,50,60,70,80,90]
    print "Testing %s v %s" % (impl1, impl2)
    test = NetSecSpring2016_ReliableTest()
    
    for i in errorRates:
        errorRate = (0,i,1000000)
        lossRate = (0,int(i/10),1000)
        print "\n\nRUN TEST WITH ERROR RATE = %s, LOSS = %s" % (errorRate, lossRate)
        test.runTest(impl1, impl2, errorRate=errorRate, lossRate=lossRate)
    test.saveResults(resultsFileName)  
    
class ForcePacketTrace(object):
    def __init__(self):
        self.doPacketTracing=True
if __name__=="__main__":
    import logging, random, os
    
    args = sys.argv[1:]
    entries = None
    loglevel = "ERROR"
    selfTest = True
    while args and args[0][0] == '-':
        print args[0]
        flag = args.pop(0)
        if flag == "-f":
            bakeOffEntriesFile = args.pop(0)
            with open(bakeOffEntriesFile) as f:
                entries = f.readlines()
        elif flag == "--loglevel":
            loglevel = args.pop(0)
            print "loglevel", loglevel
        elif flag == "--noselftest":
            selfTest = False
    resultsFileName = args.pop(0)
    if not entries:
        entries = args
    
    
    random.seed(0)
    logging.getLogger("").setLevel(loglevel)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setFormatter(formatter)
    #logging.getLogger("").addHandler(stdoutHandler)
    logfile = open("debuglog.log","w+")
    fileHandler = logging.StreamHandler(logfile)
    fileHandler.setFormatter(formatter)
    logging.getLogger("").addHandler(fileHandler)
    print  entries

    # run every entry against every other entry including itself
    for entry1 in entries:
        entry1 = entry1.strip()
        if not entry1: continue
        entry1 = os.path.expanduser(entry1)
        for entry2 in entries:
            entry2 = entry2.strip()
            if not entry2: continue
            if not selfTest and entry1 == entry2: continue
            entry2 = os.path.expanduser(entry2)
            multiErrorRateTest(entry1, entry2, resultsFileName)
    print "BAKE OFF COMPLETE"
    logfile.close()
    