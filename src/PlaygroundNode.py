'''
Created on Dec 4, 2013

@author: sethjn
'''
import playground
from playground.error import ErrorHandler
from playground.network.common import Timer

from utils.ui import CLIShell, stdio

import sys, os, logging, importlib, argparse, traceback

logger = logging.getLogger(__file__)


class ClientBaseFacade(object):
    def __init__(self, clientBase, script, node):
        self.__base  = clientBase
        self.__script = script
        self.__node = node
        
    def getAddress(self):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        return self.__base.getAddress()
    
    def listen(self, protFactory, port, connectionType=None):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        result = self.__base.listen(protFactory, port, connectionType)
        if result == True:
            self.__node.register(self.__script, port)
        return result
    
    def close(self, port):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        if not self.__node.isRegistered(self.__script, port):
            return False
        result = self.__base.close(port)
        self.__node.unregister(self.__script, port)
        return result
    
    def connect(self, protFactory, dstAddr, dstPort, connectionType=None, getFullStack=False):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        port, protocol = self.__base.connect(protFactory, dstAddr, dstPort, connectionType, getFullStack)
        if port != None:
            self.__node.register(self.__script, port)
        return port, protocol
    
    def getPeers(self, callback):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        return self.__base.getPeers(callback)
    
    def runWhenConnected(self, f):
        if not self.__node.isLive(self.__script):
            raise Exception("Not correctly connected to Node")
        return self.__base.runWhenConnected()
    
    def disconnectFromPlaygroundServer(self, *args, **kargs):
        # This call is ignored. Script is simply stopped.
        self.__node.stopScript(self.__script)

class StandaloneTask(object):
        
    def __init__(self, f, args, callback=None):
        self.f = f
        self.args = args
        self.callback = callback
        
    def __call__(self):
        result = self.f(*self.args)
        if self.callback:
            self.callback(result)
        else:
            print result    

class PlaygroundNode(object):
    def __init__(self, addr, chaperoneIp, chaperoneTcpPort, doLogging=True, standAlone=False):
        self.nodeAddress = addr
        self.chaperoneAddress = (chaperoneIp, chaperoneTcpPort)
        
        if doLogging:
            self.logctx = playground.playgroundlog.LoggingContext()
            self.logctx.nodeId = addr.toString()
            self.logctx.doPacketTracing = False
            playground.playgroundlog.startLogging(self.logctx)
            
        self.clientBase = playground.network.client.ClientBase(self.nodeAddress)
        self.runningScripts = {}
        self.standAlone = standAlone
        
    def isLive(self, scriptName):
        return self.runningScripts.has_key(scriptName)
    
    def getStdioUI(self, scriptName):
        if not self.isLive(scriptName):
            return (None, "Script not active")
        if not hasattr(self.runningScripts[scriptName][0], "getStdioProtocol"):
            return (None, "Script not interactive")
        return (self.runningScripts[scriptName][0].getStdioProtocol(), "")
        
    def register(self, scriptName, port):
        if not self.runningScripts.has_key(scriptName):
            raise Exception("Internal Error")
        self.runningScripts[scriptName][1].add(port)
        
    def unregister(self, scriptName, port):
        if not self.runningScripts.has_key(scriptName):
            raise Exception("Internal Error")
        if port in self.runningScripts[scriptName][1]:
            self.runningScripts[scriptName][1].remove(port)
            
    def isRegistered(self, scriptName, port):
        if not self.runningScripts.has_key(scriptName):
            raise Exception("Internal Error")
        return port in self.runningScripts[scriptName][1]
        
    def forceUnloadScript(self, scriptName):
        if self.runningScripts.has_key(scriptName):
            for port in self.runningScripts[scriptName][1]:
                self.clientBase.close(port)
            del self.runningScripts[scriptName]
        
    def startLoop(self, *runWhenConnected):
        for f in runWhenConnected:
            self.clientBase.runWhenConnected(f)
        self.clientBase.connectToChaperone(*self.chaperoneAddress)
    
    def startScript(self, script, scriptArgs):
        if not hasattr(script, "Name"):
            return (False, "PlaygroundNode Scripts require attribute Name")
        if self.runningScripts.has_key(script.Name):
            return (False, "Script named %s already running or starting" % script.Name)
        self.runningScripts[script.Name] = [script,set([])]
        clientBaseForScript = ClientBaseFacade(self.clientBase, script.Name, self)
        try:
            result, msg = script.start(clientBaseForScript, scriptArgs)
        except Exception, e:
            errMsg = traceback.format_exc()
            result, msg = (False, "Script launch failed: %s" % errMsg)
        if result == False:
            self.forceUnloadScript(script.Name)
        return (result, msg)
    
    def stopScript(self, scriptName):
        if not self.runningScripts.has_key(scriptName):
            return (False, "No such script")
        try:
            result, msg = self.runningScripts[scriptName][0].stop()
        except Exception, e:
            errMsg = traceback.format_exc()
            result, msg = False, "Could not stop script normally (will be forced close). Reason: %s" % errMsg
        self.forceUnloadScript(scriptName)
        if self.standAlone:
            self.shutdown()
        return (result, msg)
    
    def shutdown(self):
        for script in self.runningScripts.values():
            try:
                script.stop()
            except:
                pass
        self.clientBase.disconnectFromPlaygroundServer(stopReactor=True)

class ScriptTransport(object):
    def __init__(self, protocol, transport, loseConnectionCB):
        self.__protocol = protocol
        self.__transport = transport
        self.__loseConnectionCB = loseConnectionCB
        
    def write(self, msg):
        self.__transport.write(msg)  
        
    def loseConnection(self, *args, **kargs):
        self.__protocol.connectionLost()
        self.__loseConnectionCB()
        
        
def PythonModuleCompleter(s, state):
    try:
        sParts = s.split(".")
        pathFirstPart = os.sep.join(sParts[:-1])
        moduleFirstPart = ".".join(sParts[:-1])
        if moduleFirstPart: moduleFirstPart +="."

        pathIncomplete = sParts[-1]
        fullFirstPath = None
        for baseDir in [os.getcwd()]+sys.path:
            if os.path.exists(os.path.join(baseDir,pathFirstPart)):
                fullFirstPath = os.path.join(baseDir, pathFirstPart)
                break

        if fullFirstPath:
            fIndex = 0
            for fileName in os.listdir(fullFirstPath):
                if fileName.startswith(pathIncomplete):
                    fullPath = os.path.join(fullFirstPath, fileName)
                    canTab = False
                    trimSize = 0
                    if os.path.isdir(fullPath):
                        canTab = True
                    elif fullPath.endswith(".py"):
                        canTab = True
                        trimSize = -3
                    elif fullPath.endswith(".pyc") or fullPath.endswith(".pyo"):
                        canTab = True
                        trimSize = -4
        
                    if canTab and fIndex == state:
                        if trimSize != 0:
                            fileName = fileName[:trimSize]
                        return moduleFirstPart+fileName
                    fIndex += 1
        return None 
    except Exception, e:
        print e, traceback.format_exc()
        return None  

class PlaygroundNodeCLI(CLIShell, ErrorHandler):
    delimiter = os.linesep
    
    def __init__(self, node):
        CLIShell.__init__(self)
        self.__node = node
        self.__backlog = ""
        launchHandler = CLIShell.CommandHandler("launch", "Launch a script in this playground node",
                                                defaultCb=self.__loadScript,
                                                defaultArgHandler=self.__loadScriptArguments,)
        listHandler = CLIShell.CommandHandler("list", "List all running scripts",
                                              defaultCb=self.__listRunningScripts)
        stopHandler = CLIShell.CommandHandler("stop", "Stop a running script",
                                              defaultCb=self.__stopScript,
                                              defaultArgHandler=self.__stopScriptArguments)  
        interactHandler = CLIShell.CommandHandler("interact", "Launch an interactive process's UI",
                                                  defaultCb=self.__interact,
                                                  defaultArgHandler=self.__interactArgs)
        launchHandler.argCompleters["py://"] =PythonModuleCompleter
        self.registerCommand(launchHandler)
        self.registerCommand(listHandler)
        self.registerCommand(stopHandler)
        self.registerCommand(interactHandler)
        self.__loadedModules = {}
        self.__interactiveProtocol = None
        self.__generatePrompt()

    def __generatePrompt(self):
        self.prompt = "%s" % self.__node.nodeAddress
        if self.__interactiveProtocol and isinstance(self.__interactiveProtocol,CLIShell):
            self.prompt += " " + self.__interactiveProtocol.prompt
        else:
            self.prompt += " > "
    
    def __loadScriptArguments(self, writer, *args):
        if len(args) < 1:
            writer("\tExpected at least 1 argument (module name)\n")
            return None
        moduleName = args[0]
        return (moduleName, args[1:])
            
    def __loadScript(self, writer, moduleName, scriptArgs):
        #scriptModuleName = scriptModuleName[:-3] # remove ".py"
        curInvocation = self.__loadedModules.get(moduleName,0)
        self.__loadedModules[moduleName] = curInvocation + 1
        #scriptModuleName += "_%d" % curInvocation
        
        if sys.modules.has_key(moduleName):
            # We're going to force a reload of this module
            del sys.modules[moduleName]
        try:
            module = importlib.import_module(moduleName)
        except ImportError, e:
            errorMessage="\tCannot load script %s. Import Error: " % moduleName
            errorMessage+=str(e)+"\n"
            writer(errorMessage)
            self.handleException(e)
            return
        """
        with open(filename) as f:
            try:
                if scriptDir not in sys.path:
                    sys.path = [scriptDir] + sys.path
                module = imp.load_module(scriptModuleName, f, filename, (".py", "r", imp.PY_SOURCE))
                #if sys.path[0] == scriptDir: sys.path.pop(0)
                #del sys.modules[scriptModuleName]
            except Exception, e:
                self.transport.write("\tCould not load script: %s\n" % str(e))
                self.handleException(e)
                return
        """
        module.Name += "_%d" % curInvocation
        result, msg = self.__node.startScript(module, scriptArgs)
        if result == False:
            writer("\t"+msg + "\n")
        else:
            writer("\tScript loaded\n")
            #uiProtocol.makeConnection()
    
    def __interactArgs(self, writer, *args):
        if len(args) != 1:
            writer("\tExpected at least 1 argument (ScriptName)")
            return None
        scriptName = args[0]
        if self.__node.getStdioUI(scriptName)[0] == None:
            writer("\tNo interactive script %s\n" % scriptName)
        return (scriptName,)
    
    def __interact(self, writer, scriptName):
        uiProtocol, msg = self.__node.getStdioUI(scriptName)
        if uiProtocol == None:
            writer("\tCan't interact with %s. Reason=%s\n" % (scriptName, msg))
            return
        writer("\tEntering interactive mode with script %s.\n" % scriptName)
        writer("\tAll input will be sent to that script. To return,\n")
        writer("\tenter '_HOME_' at the prompt.\n")
        if uiProtocol.transport == None:
            scriptTransport = ScriptTransport(uiProtocol, self.transport, self.__interactiveQuit)
            uiProtocol.makeConnection(scriptTransport)
        self.__interactiveProtocol = uiProtocol
        self.__generatePrompt()    
        
    def __interactiveQuit(self):       
        self.transport.write("Interactive script exiting\n")
        self.reset(resetInteractivity=True)
    
    def __listRunningScripts(self, writer):
        for scriptName in self.__node.runningScripts.keys():
            interactiveText = ""
            if self.__node.getStdioUI(scriptName)[0] != None:
                interactiveText += " (interactive)"
            writer("  %s%s\n" % (scriptName, interactiveText))
            for port in self.__node.runningScripts[scriptName][1]:
                writer("    %d in use\n" % port)
    
    def __stopScriptArguments(self, writer, *args):
        if len(args) != 1:
            writer("  Expected 1 argument (script name)")
            return None
        scriptname, = args
        return (scriptname,)   
    
    def __stopScript(self, writer, scriptName):
        result, msg = self.__node.stopScript(scriptName)
        writer("\t"+msg+"\n")
        
    
    def lineReceived(self, line):
        if self.__interactiveProtocol:
            return self.__interactiveLineReceived(line)
            
        try:
            return self.lineReceivedImpl(line)
        except Exception, e:
            self.handleException(e)
            return (False, None)
            
    """def __lineReceivedImpl(self, commandline):
        commandline = commandline.strip()
        if not commandline: return
        
        if self.__d:
            self.__backlog.append(commandline)
            return
        commandParts = commandline.split(' ')
        command, args = commandParts[0], [arg for arg in commandParts[1:] if arg]
        commandHandler, argHandler = self.__commandHandler.get(command,(None, None))
        if commandHandler == None:
            self.transport.write("Unknown command [%s]\n" % command)
            return
        if argHandler != None:
            convertedArgs, message = argHandler(args)
        else:
            convertedArgs, message = args, ""
        if convertedArgs == None:
            self.transport.write(message + "\n")
            return
        
        commandHandler(*convertedArgs)"""
        
    def __interactiveLineReceived(self, line):
        line = line.strip()
        if line == '_HOME_':
            self.transport.write("Exiting interactive mode.\n")
            self.reset(resetInteractivity=True)
            return (False, None)
        else:
            try:
                return self.__interactiveProtocol.lineReceived(line)
            except Exception, e:
                self.handleException(e)
                self.transport.write("Exiting interactive mode.\n")
                self.reset(resetInteractivity=True)
                return (False, None)
        
    def reset(self, resetInteractivity=False):
        if resetInteractivity:
            self.__interactiveProtocol = None
            self.__generatePrompt()
        if self.__backlog:
            nextBackLog = self.__backlog.pop(0)
            self.lineReceived(nextBackLog)

        
    def handleError(self, message, reporter=None, stackHack=0):
        self.transport.write("Error: %s\n" % message)
        self.transport.write("Attempting to keep node operational\n")
    
    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        errMsg = traceback.format_exc()
        if not fatal:
            self.handleError(errMsg)
        else:
            self.transport.write("Fatal error: " + errMsg + "\n")
            self.__quit()
    
if __name__ == "__main__":
    cliHandler = argparse.ArgumentParser(description="""
A PlaygroundNode in which your Playground scripts can be launched
and connect to the Playground substrate. 
    """)
    cliHandler.add_argument("playground_addr",
                            type=playground.network.common.PlaygroundAddress.FromString)
    cliHandler.add_argument("chaperone_addr")
    cliHandler.add_argument("-p","--port",type=int,default=9090)
    config = cliHandler.parse_args()
    
    node = PlaygroundNode(config.playground_addr, config.chaperone_addr, config.port)
    delayedCLI = lambda: stdio.StandardIO(PlaygroundNodeCLI(node))
    node.startLoop(delayedCLI)