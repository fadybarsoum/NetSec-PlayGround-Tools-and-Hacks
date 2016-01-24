'''
Created on Apr 2, 2014

@author: sethjn
'''

from BasicMobileCodeClient import BasicMobileCodeFactory
import sys, os, getpass, math, time, shutil, subprocess
from playground.crypto import X509Certificate
from apps.bank.OnlineBank import PlaygroundOnlineBankClient
from twisted.internet import reactor

import playground
from playground.playgroundlog import logging, LoggingContext
from playground.network.common import MIBAddressMixin
logger = logging.getLogger(__file__)

from PTSPVerify import VERIFY_PICKLE_LOAD_FAILURE, NOT_DIST_PATH_TUPLE_FAILURE
from PTSPVerify import DIST_NOT_AN_INT, PATH_NOT_A_LIST, ERROR_NOT_AN_EXCEPTION, EVIL_DETECTED

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

safe_builtins = {
    'list',
    'Exception',
    'int'
}

class RestrictedUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if True: #(module == "exceptions" and name == "Exception") or (module == "__builtin__" and name in safe_builtins):
            return getattr(__builtin__, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" %
                                     (module, name))

def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()

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
        

class ParallelTSP(MIBAddressMixin):
    PATHS_PER_PARALLEL = 150000
    VERIFY_ODDS = .1
    #SANDBOX_CONTROLLER = os.path.join(LOCATION_OF_PLAYGROUND, "extras", "sandbox", "DefaultSandbox.py")
    #SANDBOX_CMD = PYPY + " " + SANDBOX_CONTROLLER
    
    MIB_DISTANCE_MATRIX = "TSPDistanceMatrix"
    MIB_CURRENT_BEST_PATH = "CurrentBestTSPPath"
    MIB_CURRENT_BEST_PATH_DISTANCE = "CurrentBestTSPPathDistance"
    MIB_CURRENT_CODE = "CurrentCode"
    
    def __init__(self, n=40, pathsPerParallel=None):
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
        
    def getNextCodeUnit(self, addr):
        while self.__resubmit:
            codeStr, codeId = self.__resubmit.pop()
            if not self.__parallelCodes.has_key(codeId): continue
            self.__parallelCodes[codeId][1] = addr
            return codeStr, codeId
        
        if not self.hasNext():
            return None, None
        start = self.__curPath
        end = self.__curPath + self.__pathsPerParallel
        instructionStr = TSPCodeTemplate % (self.__citiesStr, self.__curPath, end)
        #instruction = playground.network.common.DefaultPlaygroundMobileCodeUnit(codeStr)
        id = random.randint(0,(2**64)-1)
        self.__parallelCodes[id] = [instructionStr, addr]
        logger.info("CodeStr Len: %d" % len(instructionStr))
        if random.random() < self.VERIFY_ODDS:
            self.__checkIds[id] = (start, end)
        self.__curPath = end+1
        return instructionStr, id
    
    def pickleBack(self, id, success, pickledResult):
        logger.info("Received a result pickle with id %s" % (str(id),))
        if not self.__parallelCodes.has_key(id):
            logger.info("No such ID %s" % (str(id),))
            return False, "No such ID"
        addr = self.__parallelCodes[id][1]
        logger.info("Now verifying result pickle from %s" % (str(addr),))
        """sandboxDir = "__ext_verify__tmp"
        if not os.path.exists(sandboxDir):
            os.mkdir(sandboxDir)
        if not os.path.exists(sandboxDir):
            logger.error("Could not create sandbox directory %s for pickle safety check" % (sandboxDir,))
            return False, "Could not create tmp dir for code execution"
        ptspDir = os.path.dirname(__file__)
        originalPTSP = os.path.join(ptspDir, "PTSPVerify.py")
        copiedPTSP = os.path.join(sandboxDir, "PTSPVerify.py")
        if not os.path.exists(originalPTSP):
            logger.error("PTSPVerify file missing.")
            return False, "Original PTSP does not exist"
        shutil.copy2(originalPTSP, copiedPTSP)
        execFileCmd = "/tmp/PTSPVerify.py"
        if install_mode == "personal":
            cmd = "%s --tmp=%s %s %s" % (self.SANDBOX_CMD, sandboxDir, PYPY_SANDBOXED, execFileCmd)
        elif install_mode == "py_vm":
            cmd = "%s --tmp=%s %s" % (self.SANDBOX_CMD, sandboxDir, execFileCmd)
        else:
            return False, "Unknown internal pypy mode"

        with open(os.path.join(sandboxDir, "__ext_verify__.txt"), "w+") as f:
            f.write(pickledResult)
        cmd += " __ext_verify__.txt " + (success and "1" or "0")
        iresult = 0
        logger.info("Executing pypy command to check pickle result from %s: %s" % (str(addr), cmd))
        try:
            output = subprocess.check_output([cmd], shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            iresult = e.returncode
        if iresult != 0:
            logger.error("Could not check the result of the pickle from %s. Reason: %s" % (str(addr), str(e)))
            return False, "Could not check pickle results"
        logger.info("Output from verification of pickle from %s:\n%s" % (str(addr), output))
        lines = output.split("\n")
        result = None
        msg = "No return message"
        pickledStr = None
        for line in lines:
            if pickledStr != None: # This means we've started loading the picked obj
                pickledStr += line + "\n"
            elif line.startswith("__VERIFY_RETURN_CODE__:"):
                try:
                    codeStr = line.split(":")[1].strip()
                    result = int(codeStr)
                except:
                    pass
            elif line.startswith("__VERIFY_MSG__:"):
                try:
                    msg = line.split(":")[1].strip()
                except:
                    logger.error("Output from verification of pickle from %s was corrupted." % (str(addr),))
                    msg = "Result message corrupted"
            elif line == "__VERIFY_PICKLED_OBJ__":
                pickledStr = ""
        if result == None:
            return False, "Could not get result from safe pickle execution"
        elif result == VERIFY_PICKLE_LOAD_FAILURE:
            return False, "Could not unpickle result: " + msg
        elif result == NOT_DIST_PATH_TUPLE_FAILURE:
            return False, "Not a distance,path tuple: " + msg
        elif result == DIST_NOT_AN_INT:
            return False, "Distance was not an int: " + msg
        elif result == PATH_NOT_A_LIST:
            return False, "Path was not a list: " + msg
        elif result == ERROR_NOT_AN_EXCEPTION:
            return False, "Exception was not an exception: " + msg
        elif result == EVIL_DETECTED:
            # Save the original pickle to disk
            evilFile = "evil."+str(addr)+"."+str(time.time())+".txt"
            logger.info("Detected possible attack from %s. Saving original pickle to %s" % (str(addr),
                                                                                            os.path.abspath(evilFile)))
            with open(evilFile, "w") as f:
                f.write(pickledResult)
            return False, "==DETECTION-OF-POSSIBLE-ATTACK==: " + msg
        elif result != 0:
            return False, "General error: " + msg"""
        resultObj = restricted_loads(pickledResult) # pickledStr
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
        self.__resubmit.append((self.__parallelCodes[id][0], id))
        return False, "There shouldn't be exceptions"
    
def finish(ptsp):
    resultsFile = "tsp_results."+str(time.time())+".txt"
    print "Finished computation"
    print ptsp.finalResult()
    with open(resultsFile,"w") as f:
        f.write(str(ptsp.citiesMatrix())+"\n\n")
        f.write(str(ptsp.finalResult()))
    ptsp.disableMIBAddress()
    reactor.stop()

USAGE = """
ParallelTSP <bank cert> <login name> <playground server> <playground port>
"""
def main():
    if len(sys.argv) < 5:
        sys.exit(USAGE)
    cert, loginName, ipServer, ipPort = sys.argv[1:5] 
    ipPort = int(ipPort)
    if not os.path.exists(cert):
        sys.exit("Could not locate cert file " + cert)
    with open(cert) as f:
        cert = X509Certificate.loadPEM(f.read())
    pw = getpass.getpass("Bank password:")
    bankFactory = PlaygroundOnlineBankClient(cert, loginName, pw)
    myAddr = playground.network.common.PlaygroundAddress(20151, 0, 2, 999)
    client = playground.network.client.ClientBase(myAddr)
    
    logctx = LoggingContext()
    logctx.nodeId = "parallelTSP_"+myAddr.toString()
    #logctx.doPacketTracing = True
    playground.playgroundlog.startLogging(logctx)
    
    parallelMaster = BasicMobileCodeFactory(client, bankFactory)
    ptsp = ParallelTSP(pathsPerParallel=3000000)
    #client.runWhenConnected(lambda: ptsp.configureMIBAddress("ParallelTSP", client, client.MIBRegistrar()))
    client.runWhenConnected(lambda: parallelMaster.runParallel(ptsp, lambda: finish(ptsp)))
    client.connectToChaperone(ipServer, ipPort)
    
if __name__ == "__main__":
    main()