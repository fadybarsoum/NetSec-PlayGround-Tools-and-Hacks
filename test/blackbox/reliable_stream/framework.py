from multiprocessing import Process, Manager
# DO NOT IMPORT PLAYGROUND OR TWISTED HERE. Only Import in process to be run.

g_Manager = Manager()
g_Mailbox = g_Manager.dict()

class ChaperoneControl(object):
    def __init__(self, addr="127.0.0.1", port=9090):
        self.addr = addr
        self.port = port
        self.process = None
        self.sharedData = g_Manager.dict()
        self.sharedData["RUNNING"] = False
    
    def running(self):
        return self.process and self.process.is_alive() and self.sharedData["RUNNING"]
    
    def start(self, errorRate=None, lossRate=None):
        self.process = Process(target=self._realStart, args=(errorRate,lossRate))
        self.process.start()
        
    def _realStart(self, errorRate, lossRate):
        from playground.network.chaperone import Chaperone
        server = Chaperone(self.addr, self.port)
        if errorRate:
            server.setNetworkErrorRate(*errorRate)
        if lossRate:
            server.setNetworkLossRate(*lossRate)
        self.sharedData["RUNNING"] = True
        server.callLater(1.0,lambda: self.__monitorServer(server))
        server.run()
        print "setting stats"
        # we can't copy server back to the other side. If it takes
        # the reactor with it, it causes all kinds of havoc
        
        self.sharedData["STATISTICS"] = server.statistics().__dict__
    
    def __monitorServer(self, server):
        if not self.sharedData.get("RUNNING",False):
            server.stop()
        server.callLater(1.0, lambda: self.__monitorServer(server))
    
    def stop(self):
        self.sharedData["RUNNING"] = False
        #self.process.terminate()
        
    def join(self):
        #pass
        self.process.join()
        #self.process.terminate()
        
    def statistics(self):
        s = self.sharedData.get("STATISTICS",None)
        return s
    
class GateControl(object):
    def __init__(self, gateConfig):
        self.gateConfig = gateConfig
        self.process = None
        
    def running(self):
        return self.process and self.process.is_alive()
        
    def start(self):
        self.process = Process(target=self._realStart, args=(self.gateConfig,))
        self.process.start()
        
    def _realStart(self, gateConfig):
        import sys
        modkeys = sys.modules.keys()
        i = 1

        from playground import playgroundlog
        from playground.network.gate import Service
        #from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler
        from twisted.internet import reactor
        from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler
        #logctx = playgroundlog.LoggingContext("GATE_%s" % gateConfig.playgroundAddr)
    
        # Uncomment the next line to turn on "packet tracing"
        #logctx.doPacketTracing = True
    
        #playgroundlog.startLogging(logctx)
        #playgroundlog.UseStdErrHandler(True)

        TwistedShutdownErrorHandler.HandleRootFatalErrors()
        Service.Create(reactor, gateConfig)
        print "start gate", gateConfig.playgroundAddr
        reactor.run()
        print 'stop gate'
        
    def stop(self):
        self.process.terminate()
        
    def join(self):
        self.process.join()
    
class TestPeer(object):
    BROADCAST_TEST_ID = "__broadcast__"
    def __init__(self, testId):
        self.__testId = testId
        self.__mailbox = g_Mailbox
        self.__mailbox[testId] = g_Manager.list()
        self.process = None
        self.__sharedData = g_Manager.dict()
        
    def _realStart(self, *args):
        raise Exception("Re-implement in subclass")
    
    def start(self, *args):
        self.process = Process(target=self._realStart, args=args)
        self.process.start()
        
    def stop(self):
        self.process.terminate()
        
    def join(self):
        self.process.join()
        
    def testId(self):
        return self.__testId
    
    def sendTestData(self, dstTestId, data):
        if dstTestId == self.BROADCAST_TEST_ID:
            txIds = self.__mailbox.keys()
        else:
            txIds = [dstTestId]
        for testId in txIds:
            if not self.__mailbox.has_key(testId):
                self.__mailbox[testId] = g_Manager.list()
            l = self.__mailbox[testId]
            l.append((self.__testId, data))
            self.__mailbox[testId] = l
    
    def getTestData(self):
        if not self.__mailbox[self.__testId]:
            return None
        return self.__mailbox[self.__testId].pop()
    
    def setSharedData(self, k, v):
        self.__sharedData[k] = v
        
    def sharedData(self, k, default=None):
        return self.__sharedData.get(k, default)