'''
Created on Apr 2, 2014

@author: sethjn
'''

from BasicMobileCodeClient import BasicMobileCodeFactory
import sys, os, getpass, math, time, shutil, subprocess
from playground.crypto import X509Certificate
from apps.bank.OnlineBank import PlaygroundOnlineBankClient
from twisted.internet import reactor
from playground.network.common.Timer import OneshotTimer

import playground
from playground.playgroundlog import logging, LoggingContext
from playground.network.common import MIBAddressMixin
from playground.config import LoadOptions
logger = logging.getLogger(__file__)

from PTSPVerify import VERIFY_PICKLE_LOAD_FAILURE, NOT_DIST_PATH_TUPLE_FAILURE
from PTSPVerify import DIST_NOT_AN_INT, PATH_NOT_A_LIST, ERROR_NOT_AN_EXCEPTION, EVIL_DETECTED

from utils.ui import CLIShell, stdio

LOCATION_OF_PLAYGROUND = os.path.dirname(playground.__file__)

#For now, just assume PYPY is in src/
"""AUX_DIR = os.path.abspath(os.path.join(LOCATION_OF_PLAYGROUND, "..","aux"))
if not os.path.exists(AUX_DIR):
    raise Exception("Playground installation missing required directory %s" % AUX_DIR)

PYPY = os.path.join(AUX_DIR, "pypy")
if not os.path.exists(PYPY):
    raise Exception("Playground installation missing required auxiliary file 'pypy'")

MODE_FILE = os.path.join(AUX_DIR,"location_hack")
if not os.path.exists(MODE_FILE):
    raise Exception("Mode file missing. Unknown installation type.")

with open(MODE_FILE) as f:
    install_mode = f.read()
    
if install_mode == "personal":
    PYPY_SANDBOXED = os.path.join(AUX_DIR, "pypy_sandboxed")
    if not os.path.exists(PYPY_SANDBOXED):
        raise Exception("Playground installation missing required auxiliary file 'pypy_sandboxed' for personal mode.")
elif install_mode == "py_vm":
    pass
else:
    raise Exception("Unknown installation target %s" % install_mode)"""
        
TSPCodeTemplate = """
import math

cities = %s
start_num = %d
end_num = %d

def maxPaths(n):
    return math.factorial(n)

def numToPath(n, num):
    if num >= maxPaths(n):
        return None
    ordered_cities = range(n)
    path = []
    for index in range(n-1):
        perDigit = maxPaths(n-(index+1))
        digitsThisIndex = num/perDigit
        num = num - (perDigit*digitsThisIndex)
        path.append(ordered_cities[digitsThisIndex])
        ordered_cities = ordered_cities[:digitsThisIndex] + ordered_cities[digitsThisIndex+1:]
    path.append(ordered_cities[0])
    path.append(path[0])
    return path

shortest = None
path = None
for i in range(start_num, end_num+1):
  p = numToPath(len(cities), i)
  if not p: break
  prev = p[0]
  dist = 0
  for cit in p[1:]:
    dist += cities[prev][cit]
    prev = cit
  if not shortest or dist < shortest:
    shortest = dist
    path = p
result = (shortest, path)
"""

import random, pickle, playground

import __builtin__
import io

def generateDistanceMatrix(n, min=1, max=9):
    matrix = []
    for i in range(n):
        matrix.append(['']*n)
    for i in range(n):
        for j in range(n):
            if i > j:
                matrix[i][j] = matrix[j][i]
            elif i == j: continue
            else: matrix[i][j] = random.randint(min, max)
    return matrix

def maxPaths(n):
    return math.factorial(n)

def numToPath(n, num):
    if num >= maxPaths(n):
        return None
    # the first path is 1,2,3,4... n
    ordered_cities = range(n)
    path = []
    for index in range(n-1):
        perDigit = maxPaths(n-(index+1))
        digitsThisIndex = num/perDigit
        num = num - (perDigit*digitsThisIndex)
        path.append(ordered_cities[digitsThisIndex])
        ordered_cities = ordered_cities[:digitsThisIndex] + ordered_cities[digitsThisIndex+1:]
    path.append(ordered_cities[0])
    path.append(path[0])
    return path
        

class AddrPod(object):
    def __init__(self, addr):
        self.addr = addr
        self.jobsSent = 0
        self.jobsCompleted = 0
        self.pathsCompleted = 0
        self.jobErrors = 0
        self.paid = 0

class ParallelTSP(CLIShell, MIBAddressMixin):
    PATHS_PER_PARALLEL = 150000
    VERIFY_ODDS = .1
    #SANDBOX_CONTROLLER = os.path.join(LOCATION_OF_PLAYGROUND, "extras", "sandbox", "DefaultSandbox.py")
    #SANDBOX_CMD = PYPY + " " + SANDBOX_CONTROLLER
    
    MIB_DISTANCE_MATRIX = "TSPDistanceMatrix"
    MIB_CURRENT_BEST_PATH = "CurrentBestTSPPath"
    MIB_CURRENT_BEST_PATH_DISTANCE = "CurrentBestTSPPathDistance"
    MIB_CURRENT_CODE = "CurrentCode"
    
    def getCodeString(self, startPath, endPath):
        return TSPCodeTemplate % (self.__citiesStr, startPath, endPath)
    
    def __init__(self, n=40, pathsPerParallel=None, maxRate=20):

        self.__matrix = generateDistanceMatrix(n)
        self.__parallelCodes = {}
        self.__citiesStr = "[\n"
        for row in self.__matrix:
            self.__citiesStr += str(row) + ",\n"
        self.__citiesStr += "]"
        self.__maxPaths = maxPaths(n)
        self.__curPath = 0
        self.__pathsPerParallel = pathsPerParallel and pathsPerParallel or self.PATHS_PER_PARALLEL

        self.__shortest = None
        self.__bestPath = None
        self.__resubmit = []
        self.__finished = False
        self.__checkIds = {}
        self.__idsToPaths = {}
        self.__completedPaths = 0
        self.__addrData = {}
        self.__maxRate = maxRate
        
    def configureMIBAddress(self, *args, **kargs):
        MIBAddressMixin.configureMIBAddress(self, *args, **kargs)
        self.__loadMibs()
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_DISTANCE_MATRIX, self.__handleMib)
            self.registerLocalMIB(self.MIB_CURRENT_BEST_PATH, self.__handleMib)
            self.registerLocalMIB(self.MIB_CURRENT_BEST_PATH_DISTANCE, self.__handleMib)
            self.registerLocalMIB(self.MIB_CURRENT_CODE, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_DISTANCE_MATRIX):
            return [self.__citiesStr]
        elif mib.endswith(self.MIB_CURRENT_BEST_PATH):
            return [str(self.__bestPath)]
        elif mib.endswith(self.MIB_CURRENT_BEST_PATH_DISTANCE):
            return [str(self.__shortest)]
        elif mib.endswith(self.MIB_CURRENT_CODE):
            responses = []
            for k in self.__parallelCodes.keys():
                code, addr = self.__parallelCodes[k]
                responses.append("Code for %s\n%s" % (str(addr), code))
            return responses
        return []
        
    def __computeInternal(self, start_num, end_num):
        shortest = None
        path = None
        for i in range(start_num, end_num+1):
            p = numToPath(len(self.__matrix), i)
            if not p: break
            prev = p[0]
            dist = 0
            for cit in p[1:]:
                dist += self.__matrix[prev][cit]
                prev = cit
            if not shortest or dist < shortest:
                shortest = dist
                path = p
        return (shortest, path)
        
    def finished(self): 
        return self.__finished
    
    def citiesMatrix(self): return self.__matrix
    
    def finalResult(self): return self.__shortest, self.__bestPath
        
    def hasNext(self):
        return (self.__curPath < self.__maxPaths)
    
    def mobileCodeId(self):
        return "Parallel TSP"
    
    def maxRate(self):
        return self.__maxRate
    
    def maxRuntime(self):
        return 1*60*60
    
    def maxPaths(self):
        return self.__maxPaths
    
    def currentBestPath(self):
        return (self.__bestPath, self.__shortest)
    
    def iterAddrStats(self):
        for addr in self.__addrData.values():
            yield addr
    
    def currentExecutions(self):
        executions = []
        for codeId in self.__parallelCodes.keys():
            paths, computingAddr, finished = self.__idsToPaths[codeId]
            executions.append((codeId, paths, computingAddr, finished))
        return executions
    
    def completedPathCount(self):
        return self.__completedPaths
        
    def getNextCodeUnit(self, addr):
        if not self.__addrData.has_key(addr):
            self.__addrData[addr] = AddrPod(addr)
        while self.__resubmit:
            codeStr, codeId = self.__resubmit.pop()
            if not self.__parallelCodes.has_key(codeId): continue
            self.__parallelCodes[codeId][1] = addr
            self.__idsToPaths[codeId][1] = addr
            self.__addrData[addr].jobsSent += 1
            return codeStr, codeId
        
        if not self.hasNext():
            return None, None
        start = self.__curPath
        end = self.__curPath + (self.__pathsPerParallel-1)
        if end > self.__maxPaths:
            end = self.__maxPaths
        instructionStr = self.getCodeString(self.__curPath, end)
        #instruction = playground.network.common.DefaultPlaygroundMobileCodeUnit(codeStr)
        id = random.randint(0,(2**64)-1)
        self.__parallelCodes[id] = [instructionStr, addr]
        self.__idsToPaths[id] = [(start,end), addr, False]
        logger.info("CodeStr Len: %d" % len(instructionStr))
        if random.random() < self.VERIFY_ODDS:
            self.__checkIds[id] = (start, end)
        self.__curPath = end+1
        self.__addrData[addr].jobsSent += 1
        return instructionStr, id
    
    def pickleBack(self, id, success, pickledResult):
        logger.info("Received a result pickle with id %s" % (str(id),))
        if not self.__parallelCodes.has_key(id):
            logger.info("No such ID %s" % (str(id),))
            return False, "No such ID"
        addr = self.__parallelCodes[id][1]
        logger.info("Now verifying result pickle from %s" % (str(addr),))
        resultObj = pickle.loads(pickledResult) # pickledStr
        if success:
            return self.codeCallback(id, resultObj)
        else:
            return self.codeErrback(id, resultObj)
    
    def codeCallback(self, id, resultObj):
        logger.info("callback: %s" % str(resultObj))
        try:
            dist, path = resultObj
        except:
            return False, "Invalid result. Expected distance, path"
        if type(dist) != int or type(path) != list:
            return False, "Invalid result, Expected int, list"
        verifiedOK = True
        addr = self.__parallelCodes[id][1]
        
        if self.__checkIds.has_key(id):
            logger.info("Validating ID %d" % id)
            start, end = self.__checkIds[id]
            del self.__checkIds[id]
            expectedDist, expectedPath = self.__computeInternal(start, end)
            if expectedDist != dist or expectedPath != path:
                logger.info("Verification failure. Expected %s (%d) but got %s (%d)" % (str(expectedPath), expectedDist,
                                                                                        str(path), dist))
                verifiedOK = False
                dist = expectedDist
                path = expectedPath
        if verifiedOK: 
            self.__idsToPaths[id][2] = True
            start, end = self.__idsToPaths[id][0]
            self.__completedPaths += (end-start)+1
            self.__addrData[addr].jobsCompleted += 1
            self.__addrData[addr].pathsCompleted += (end-start)+1
        else:
            self.__addrData[addr].jobErrors += 1
        del self.__parallelCodes[id]
        if self.__shortest == None or dist < self.__shortest:
            self.__shortest = dist
            self.__bestPath = path
        if (not self.hasNext()) and len(self.__parallelCodes) == 0 and len(self.__resubmit) == 0:
            self.__finished = True
            logger.info("==FINISHED==")
        if verifiedOK:
            return True, ""
        else:
            return False, "Failed verification."
            
    def codeErrback(self, id, exceptionObj):
        logger.info("exception back: %s" % str(exceptionObj))
        if not self.__parallelCodes.has_key(id):
            return False, "Unknown id %d" % id
        addr = self.__parallelCodes[id][1]
        self.__addrData[addr].jobErrors += 1
        self.__resubmit.append((self.__parallelCodes[id][0], id))
        self.__idsToPaths[1] = "<Needs Reassignment>"
        return False, "There shouldn't be exceptions"
    
def validateConfigFile(options):
    bankData = options.getSection("ptsp.bankdata")
    bankData["bank_addr"]
    bankData["account"]
    bankData["user"]
    bankData["bank_cert_path"]
    #parameter = options.getSection("ptsp.parameters")
    #loggingData = options.getSection("ptsp.logging")
    #loggingData["packet_tracing"]
    #loggingData[""]

class ParallelTSPCLI(CLIShell):
    BANNER = """
Parallel Traveling Salesman. Sends out paths to be computed
by remote hosts. Results are collected until the best path
is known. Execute 'start' to begin the computation. 
Execute 'status' to see how things are going.
"""
    def __init__(self, options, parallelMaster):
        CLIShell.__init__(self, banner = self.BANNER)   
        self.parallelMaster = parallelMaster
        self.options = options
        self.__poll = None
        self.__pollingCallback = None
        self.__started = False
        startHandler = CLIShell.CommandHandler("start",helpTxt="Start the parallelTsp",
                                               defaultCb=self.start,
                                               mode=CLIShell.CommandHandler.STANDARD_MODE)
        self.registerCommand(startHandler)
        configHandler = CLIShell.CommandHandler("config",helpTxt="Show current config (can't change yet)",
                                                defaultCb=self.config,
                                                mode=CLIShell.CommandHandler.STANDARD_MODE)
        self.registerCommand(configHandler)
        statusHandler = CLIShell.CommandHandler("status",helpTxt="Show current status",
                                                defaultCb=self.status,
                                                mode=CLIShell.CommandHandler.STANDARD_MODE)
        statusHandler.configure(1, self.status, helpTxt="Show status and set to poll the status",
                                usage="[polling time]")
        self.registerCommand(statusHandler)
        checkbalanceHandler = CLIShell.CommandHandler("balance", helpTxt="Check the current account balance",
                                                      defaultCb=self.checkBalance,
                                                      mode=CLIShell.CommandHandler.STANDARD_MODE)
        self.registerCommand(checkbalanceHandler)
        sampleCodeString = CLIShell.CommandHandler("sample", helpTxt="Generate A sample remote code string",
                                                   mode=CLIShell.CommandHandler.STANDARD_MODE)
        sampleCodeString.configure(3, self.getSampleCodeString, 
                                   helpTxt="Get a sample code string for the given parameters", 
                                   usage="[startpath] [endpath] [filename]")
        self.registerCommand(sampleCodeString)
        
        blacklistCommand = CLIShell.CommandHandler("blacklist", helpTxt="Get the list of blacklisted nodes",
                                                   mode=CLIShell.CommandHandler.STANDARD_MODE,
                                                   defaultCb=self.blacklistedAddrs)
        self.registerCommand(blacklistCommand)
        
    def __checkBalanceResponse(self, msgObj):
        self.transport.write("Current balance in account: %d\n" % msgObj.Balance)
        
    def __checkBalanceFailed(self, failure):
        self.transport.write("Balance check failed: %s\n" % failure)
        
    def checkBalance(self, writer):
        d = self.parallelMaster.checkBalance()
        d.addCallback(self.__checkBalanceResponse)
        d.addErrback(self.__checkBalanceFailed)
        
    def config(self, writer):
        for k, v in self.options.items():
            self.transport.write("%s: %s\n" % (k,v))
            
    def getSampleCodeString(self, writer, startPath, endPath, filename):
        try:
            startPath = int(startPath)
        except:
            writer("Invalid start path\n")
            return
        try:
            endPath = int(endPath)
        except:
            writer("Invalid end path\n")
            return
        codeStr = self.ptsp.getCodeString(startPath, endPath)
        with open(filename, "w+") as f:
            f.write(codeStr)
        writer("Wrote file %s\n" % filename)
        
    def blacklistedAddrs(self, writer):
        if not self.__started:
            self.transport.write("Can't get blacklist Not yet started\n")
            return
        bl = self.parallelMaster.getBlacklist()
        writer("Blacklisted Addresses:\n")
        for addr in bl:
            writer("  %s\n" % addr)
        writer("\n")
            
    def status(self, writer, poll=None):
        if not self.__started:
            self.transport.write("Can't get status. Not yet started\n")
            return
        if poll != None:
            # We're changing the polling time. Cancel the current, then
            # set the new polling time
            try:
                poll = int(poll)
            except:
                self.transport.write("Polling time must be an integer. Got %s" % poll)
                return
            if poll < 0:
                self.transport.write("Polling time must be a positive integer. Got %d" % poll)
                return
            if self.__pollingCallback:
                self.__pollingCallback.cancel()
                if poll == 0:
                    self.__pollingCallback = None
            self.__poll = poll
        template = """
    Max Paths: %(Max_Path_Count)s
    Completed Paths: %(Completed_Path_Count)s
    Currently Executing Paths: %(Current_Path_Count)s
%(Current_Execution_Details)s
    Address Data:
%(Addr_Stats)s"""
        if self.ptsp.finished():
            template = ("FINISHED: %s\n" % str(self.ptsp.finalResult())) + template
        templateData = {}
        templateData["Max_Path_Count"] = self.ptsp.maxPaths()
        templateData["Completed_Path_Count"] = self.ptsp.completedPathCount()
        
        currStr = ''
        currentExecutions = self.ptsp.currentExecutions()
        currentPathCount = 0
        for execId, paths, addr, finished in currentExecutions:
            currStr += "\t\t%s:\t%s\t%s\n" % (addr, execId, paths)
            start, end = paths
            currentPathCount += (end-start)+1
        templateData["Current_Path_Count"] = currentPathCount
        addrStr =  "\t\t%-15s\t%-10s\t%-10s\t%-10s\t%s\n" % ("Address", "Jobs Sent", "Completed Jobs", "Errors", "Paid")
        for addrData in self.ptsp.iterAddrStats():
            addrStr += "\t\t%-15s\t%-10s\t%-10s\t%s\t(Not Yet Implemented)\n" % (addrData.addr, addrData.jobsSent, addrData.jobsCompleted, addrData.jobErrors)  
        
        templateData["Current_Execution_Details"] = currStr
        templateData["Addr_Stats"] = addrStr
        
        self.transport.write((template % templateData)+"\n")
        if self.__poll:
            # if we have a polling time set, fire.
            self.__pollingCallback = OneshotTimer(lambda: self.status(writer))
            self.__pollingCallback.run(self.__poll)
        
    def start(self, writer):
        if self.__started:
            self.transport("Program already started.\n")
            return
        self.__started=True
        kargs = {}
        parameters = self.options.getSection("ptsp.parameters")
        if parameters.has_key("n"):
            kargs["n"] = int(parameters["n"])
        if parameters.has_key("paths_per_parallel_execution"):
            kargs["pathsPerParallel"] = int(parameters["paths_per_parallel_execution"])
        self.ptsp = ParallelTSP(**kargs)
        self.parallelMaster.runParallel(self.ptsp, self.finish)
        
    def finish(self):
        #resultsFile = "tsp_results."+str(time.time())+".txt"
        self.transport.write("Finished computation\n")
        self.transport.write("\tResult: %s\n" % str(self.ptsp.finalResult()))
        if self.__pollingCallback:
            self.__pollingCallback.cancel()
            self.__pollingCallback = None
        #with open(resultsFile,"w") as f:
        #    f.write(str(ptsp.citiesMatrix())+"\n\n")
        #    f.write(str(ptsp.finalResult()))
        #ptsp.disableMIBAddress()
        #reactor.stop()

USAGE = """
ParallelTSP <playground_addr> <chaperone_addr> <config_file>
"""
#<bank cert> <login name> <account name> <playground server> <playground port>
#"""
def main():
    if len(sys.argv) != 4:
        sys.exit(USAGE)
    myAddr, chaperoneAddr, configFile = sys.argv[1:4]
    configOptions = LoadOptions(configFile)
    validateConfigFile(configOptions)
    #cert, loginName, accountName, ipServer, ipPort = sys.argv[1:6] 
    #ipPort = int(ipPort)
    bankOptions = configOptions.getSection("ptsp.bankdata")
    if not os.path.exists(bankOptions["bank_cert_path"]):
        sys.exit("Could not locate cert file " + bankOptions["bank_cert_path"])
    with open(bankOptions["bank_cert_path"]) as f:
        cert = X509Certificate.loadPEM(f.read())
    pw = getpass.getpass("Account %s password:" % bankOptions["account"])
    bankFactory = PlaygroundOnlineBankClient(cert, bankOptions["user"], pw)
    myAddr = playground.network.common.PlaygroundAddress.FromString(myAddr)
    bankAddr = bankOptions["bank_addr"]
    client = playground.network.client.ClientBase(myAddr)
    
    logctx = LoggingContext()
    logctx.nodeId = "parallelTSP_"+myAddr.toString()
    # set this up as a configuration option
    #logctx.doPacketTracing = True
    playground.playgroundlog.startLogging(logctx)
    
    parallelMaster = BasicMobileCodeFactory(client, bankOptions["account"], bankFactory, bankAddr,
                                            mcConnType=configOptions.get("ptsp.networkdata.connectionType","RAW"),
                                            bankConnType=bankOptions.get("connectionType","RAW"))
    
    #client.runWhenConnected(lambda: ptsp.configureMIBAddress("ParallelTSP", client, client.MIBRegistrar()))
    #client.runWhenConnected(lambda: )
    client.runWhenConnected(lambda: stdio.StandardIO(ParallelTSPCLI(configOptions, parallelMaster)))
    client.connectToChaperone(chaperoneAddr, 9090)
    
if __name__ == "__main__":
    main()