'''
Created on Dec 4, 2013

@author: sethjn
'''
from PlaygroundNode import PlaygroundNode, StandaloneTask
import playground
from playground.network.common import Timer
import sys

def getRemotePiCodeString(nPoint):
    """Derived from the Python Code Found at https://gist.github.com/amitsaha/2036026 on 2013-12-04"""

    template = """
import random
count = 0
for i in range(%d):
    x=random.random()
    y=random.random()

    # if it is within the unit circle
    if x*x + y*y <= 1:
        count=count+1
result = count
"""
    return template % nPoint

class ComputePi(playground.network.client.sampleservers.MobileCodeClient.CodeCallback):
    '''
    classdocs
    '''


    def __init__(self, client, mobileCodeClient):
        '''
        Constructor
        '''
        self.mobileCodeClient = mobileCodeClient
        self.client = client
        self.protsToClose = []
    
    def stop(self):
        for prot in self.protsToClose:
            prot.transport.loseConnection()
        self.protsToClose = []
        
    def __reportResultsIfComplete(self):
        if self.successes + self.responses == self.mcount:
            print "All responses accounted for. Computing result"
            pi = (self.total/(self.n*1.0))*4  
            print "Pi estimated to be", pi
            print "Closing connection"
            self.stop()
            print "All connections closed"
        
    def handleCodeResult(self, resultStr, resultObj):
        self.successes += 1
        print "Got result!", resultObj,
        print "successful mobile results now", self.successes
        self.total += resultObj
        self.__reportResultsIfComplete()
    
    def handleCodeException(self, exceptionStr, exceptionObj):
        print "Got exception", exceptionStr
        self.responses += 1
        self.__reportResultsIfComplete()
        
    def handleDroppedCodeResult(self):
        print "Code result dropped"
        self.responses += 1
        self.__reportResultsIfComplete()
        
    def peersReceived(self, peerList):
        print "got addresses", peerList
        self.mcount = len(peerList)
        codeString = getRemotePiCodeString(self.n/(1.0*self.mcount))
        for peerString in peerList:
            print "Sending to peer", peerString
            peer = playground.network.common.PlaygroundAddress.FromString(peerString)
            # hardcoded port for now
            srcPort, prot = self.client.connect(self.mobileCodeClient, peer, 100)
            prot.sendPythonCode(codeString, self)
            self.protsToClose.append(prot)
        
    def startState(self):
        self.client.getPeers(self.peersReceived)
        
    def start(self, nPoints):
        print "Starting computation of pi with %d points" % nPoints
        self.n = nPoints
        self.successes = 0
        self.responses = 0
        self.total = 0
        self.startState()
        
### 
# For use with PlaygroundNode.py on import
####################################
class PlaygroundNodeControl(object):
    Name = "compute_pi"
    def __init__(self):
        self.serving = False
        self.client = None
    def start(self, clientBase, args):
        self.clientBase = clientBase
        result, msg = True, ""
        if "start_server" in args:
            mobileCodeServer = playground.network.client.sampleservers.ClientMobileCodeServer()
            result = clientBase.listen(mobileCodeServer, 100)
            if result == True:
                self.serving = True
            else: msg = "Could not start server"
        if "start_client" in args:
            print "start client"
            computePi = ComputePi(clientBase, playground.network.client.sampleservers.MobileCodeClient())
            Timer.callLater(0, lambda: computePi.start(10000000))
            self.client = computePi
        if not self.serving and not self.client:
            result, msg = False, "computePi requires either 'start_server', 'start_client', or both"
        return result, msg
    
    def stop(self):
        if self.serving:
            self.clientBase.close(100)
        if self.client:
            self.client.stop()
        return True, ""
control = PlaygroundNodeControl()

Name = control.Name
start = control.start
stop = control.stop
########
        
        
if __name__ == "__main__":
    playgroundAddrStr, mode, chaperoneAddr = sys.argv[1:]
    playgroundAddr = playground.network.common.PlaygroundAddress.FromString(playgroundAddrStr)
    runner = PlaygroundNode(playgroundAddr, chaperoneAddr, 9090)
    computePiModule = PlaygroundNodeControl()
    
    if mode == "server": startArgs = ["start_server"]
    elif mode == "client": startArgs = ["start_client"]
    elif mode == "client_server": startArgs = ["start_server", "start_client"]
    else: raise Exception("Unknown mode [%s]" % mode)
    
    task = StandaloneTask(runner.startScript, [computePiModule, startArgs])
    runner.startLoop(task)
