'''
Created on Feb 16, 2016

@author: sethjn
'''

import os, threading, sys, textwrap, traceback
from twisted.internet import reactor
from twisted.protocols import basic


class AdvancedStdio(object):
    def __init__(self, protocol):
        self.__protocol = protocol
        self.__getLine = False
        self.__getLineLock = threading.Lock()
        self.__getLineCV = threading.Condition(self.__getLineLock)
        self.__quit = False
        self.__quitLock = threading.Lock()
        reactor.callInThread(self.loop)
        
    def write(self, buf):
        sys.stdout.write(buf)
        if not buf[-1] == "\n":
            sys.stdout.flush()
        
    def loseConnection(self):
        with self.__quitLock:
            self.__quit = True
            
    def incompleteShutdown(self):
        with self.__getLineLock:
            if not self.__getLine:
                print "\nIncomplete shutdown (probably ctrl-c). Press enter (ctrl-d exits immediately)"
            
    def shouldQuit(self):
        if not reactor.running: return True
        with self.__quitLock:
            return self.__quit
        
    def __waitUntilReadyForInput(self):
        with self.__getLineCV:
            while not self.__getLine and not self.shouldQuit():
                self.__getLineCV.wait(1.0)
                
    def __protocolProcessLine(self, line):
        self.__protocol.lineReceived(line)
        with self.__getLineLock:
            self.__getLine = True
            self.__getLineCV.notify()

    def loop(self):
        reactor.addSystemEventTrigger('before', 'shutdown', self.incompleteShutdown)
        import readline
        readline.set_completer_delims("")
        if isinstance(self.__protocol, CompleterInterface):
            readline.set_completer(self.__protocol.complete)
        readline.parse_and_bind("tab: complete")
        self.__protocol.makeConnection(self)
        while not self.shouldQuit():
            try:
                line = raw_input(self.__protocol.prompt)
            except:
                print
                reactor.callFromThread(reactor.stop)
                return
            with self.__getLineLock:
                self.__getLine = False
            reactor.callFromThread(self.__protocolProcessLine, line)
            self.__waitUntilReadyForInput()

    
def FileArgCompleter(s, state):
    pathParts = os.path.split(s)
    pathFirstPart = os.sep.join(pathParts[:-1])
    pathFirstPart = os.path.expanduser(pathFirstPart)
    pathIncomplete = pathParts[-1]
    if os.path.exists(pathFirstPart):
        fIndex = 0
        for fileName in os.listdir(pathFirstPart):
            if fileName.startswith(pathIncomplete):
                if fIndex == state:
                    return os.path.join(pathFirstPart, fileName)
                fIndex += 1
    return None

class CompleterInterface(object):
    def complete(self, s, state):
        return None
    
def completeKeys(d, s, state, recursive=True):
    keyIndex = 0
    for k in d.keys():
        if recursive and s.startswith(k+" ") and isinstance(d[k], CompleterInterface):
            # in this case, the command is already fully formed.
            # allow the command's completer to take over
            remainderOfS = s[len(k)+1:]
            return k+" "+d[k].complete(remainderOfS, state)
        elif k.startswith(s):
            if keyIndex == state:
                return k
            keyIndex += 1
    return None

def formatText(line, width=120):
    return textwrap.TextWrapper(replace_whitespace=False, drop_whitespace=False, width=width).fill(line)

class TwistedStdioReplacement(object):
    StandardIO = AdvancedStdio
    formatText = formatText

class CLICommand(CompleterInterface):
    SINGLETON_MODE = "Singletone Mode: Single callback no matter the args"
    STANDARD_MODE = "Standard Mode: Arguments Only"
    SUBCMD_MODE = "SubCommand Mode: Requires a sub command"
    
    class ArgPod(object):
        def __init__(self):
            self.argHandler = lambda writer, *args: args
            self.cmdHandler = None
            self.help = None
            self.usage = None

    def __init__(self, cmdTxt, helpTxt, defaultCb = None, defaultArgHandler = None, mode=SINGLETON_MODE):
        self.cmdTxt = cmdTxt
        self.cb = {}
        self.argCompleters = {"_f:":FileArgCompleter}
        self.helpTxt = helpTxt
        self.defaultIndent = "  " # two spaces
        self.__mode = mode
        self.__defaultCb = defaultCb
        if defaultArgHandler: 
            self.__defaultArgHandler = defaultArgHandler
        else:
            self.__defaultArgHandler = lambda writer, *args: args
        if self.__mode == CLICommand.SINGLETON_MODE and not defaultCb:
            raise Exception("Singleton mode requires a one and only default callback")
        
    def usageHelp(self):
        usageStrings = []
        if self.__defaultCb:
            if self.__mode ==CLICommand.SINGLETON_MODE:
                usageStrings.append("%s/*"% self.cmdTxt)
            else: usageStrings.append("%s/0"%self.cmdTxt)
        if self.__mode == CLICommand.STANDARD_MODE:
            for argCount, argPod in self.cb.items():
                if argPod.usage:
                    usageStrings.append("%s %s" % (self.cmdTxt, argPod.usage))
                else:
                    usageStrings.append("%s/%d" % (self.cmdTxt, argCount))
        elif self.__mode == CLICommand.SUBCMD_MODE:
            for subCmdObj in self.cb.values():
                for subUsage in subCmdObj.usageHelp():
                    usageStrings.append("%s %s" % (self.cmdTxt, subUsage))
        return usageStrings
    
    def help(self):
        helpStrings = []
        if self.__defaultCb:
            if self.__mode==CLICommand.SINGLETON_MODE:
                helpStrings.append("%s/*\n  %s" % (self.cmdTxt, self.helpTxt))
            else:
                helpStrings.append("%s/0\n  %s" % (self.cmdTxt, self.helpTxt))
        if self.__mode == CLICommand.STANDARD_MODE:
            for argCount, argPod in self.cb.items():
                if argPod.usage:
                    helpStrings.append("%s %s\n  %s" % (self.cmdTxt, argPod.usage, formatText(argPod.helpTxt)))
                else:
                    helpStrings.append("%s/%d\n  %s" % (self.cmdTxt, argCount, formatText(argPod.helpTxt)))
        elif self.__mode == CLICommand.SUBCMD_MODE:
            for subCmdObj in self.cb.values():
                for helpLine in subCmdObj.help():
                    helpStrings.append("%s %s" % (self.cmdTxt, helpLine))
        return helpStrings
            
        
        """
        helpTxt = [prefix + "%s:" % self.cmdTxt]
        if maxDepth <= 1:
            return helpTxt
        if self.__noArgsCb:
            helpTxt.append(prefix+ "%s/0" % self.cmdTxt)
        helpTxt.append(prefix + self.defaultIndent + self.helpTxt)
        if self.__mode == CLICommand.STANDARD_MODE:
            for argCount, argPod in self.cb.items():
                if argPod.usage:
                    helpTxt.append(prefix + "%s %s" % (self.cmdTxt, argPod.usage))
                else:
                    helpTxt.append(prefix + "%s/%d" % (self.cmdTxt, argCount))
                helpTxt.append(prefix + self.defaultIndent +argPod.helpTxt)
        elif self.__mode == CLICommand.SUBCMD_MODE:
            for subCmdObj in self.cb.values():
                for subUsage in subCmdObj.usageHelp():
                    helpTxt.append(prefix + "%s %s" % (self.cmdTxt, subUsage))
                    subCmdPrefix = prefix + self.cmdTxt
                    for subHelpLine in subCmdObj.help(prefix = subCmdPrefix, maxDepth=maxDepth-1):
                        helpTxt.append(subHelpLine)
        return helpTxt"""
        
    def stripCompleterKeys(self, arg):
        if arg.startswith("_"):
            for key, pod in self.argCompleters.items():
                if arg.startswith(key):
                    return arg[len(key):]
        return arg
        
    def configureSubcommand(self, subCmd):
        if self.__mode != CLICommand.SUBCMD_MODE:
            raise Exception("Cannot configure sub commands except in sub command mode")
        if self.cb.has_key(subCmd.cmdTxt):
            raise Exception("Cannot add duplicate subcommand for %s" % subCmd.cmdTxt)
        self.cb[subCmd.cmdTxt] = subCmd
        
    def configure(self, numArgs, cmdHandler, helpTxt, argHandler = None, usage=None):
        if self.__mode != CLICommand.STANDARD_MODE:
            raise Exception("Cannot configure standard arguments except in standard mode")
        if self.cb.has_key(numArgs):
            raise Exception("CLI command %s already configured for %d args" % (self.cmdTxt, numArgs))
        if numArgs < 1:
            raise Exception("CLI command cannot take a negative number of arguments")
        self.cb[numArgs] = self.ArgPod()
        self.cb[numArgs].cmdHandler = cmdHandler
        self.cb[numArgs].helpTxt = helpTxt
        self.cb[numArgs].usage = usage
        if argHandler: self.cb[numArgs].argHandler = argHandler
        
    def process(self, args, writer):
        if self.__mode == CLICommand.SINGLETON_MODE:
            args = map(self.stripCompleterKeys, args)
            args = self.__defaultArgHandler(writer, *args)
            if args == None:
                writer("Command failed.\n")
            else: 
                self.__defaultCb(writer, *args)
            return
        if len(args)==0:
            if not self.__defaultCb:
                writer("Command requires arguments\n")
            else:
                args = self.__defaultArgHandler(writer, *args)
                if args == None:
                    writer("Command failed.\n")
                else:
                    self.__defaultCb(writer, *args)
            return
        if self.__mode == CLICommand.SUBCMD_MODE:
            subCmd = args[0]
            subCmdArgs = args[1:]
            subCmdHandler = self.cb.get(subCmd, None)
            if not subCmdHandler:
                writer("No such command %s\n" % subCmd)
                return
            subCmdHandler.process(subCmdArgs, writer)
        else:
            args = map(self.stripCompleterKeys, args)
            argsPod = self.cb.get(len(args), None)
            if not argsPod:
                writer("Wrong number of arguments\n")
                return
            args = argsPod.argHandler(writer, *args)
            if args == None:
                writer("Command failed\n")
            else:
                argsPod.cmdHandler(writer, *args)
        
    def complete(self, s, state):
        if self.__mode == CLICommand.SUBCMD_MODE:
            return completeKeys(self.cb, s, state)
        elif self.__mode in [CLICommand.STANDARD_MODE, CLICommand.SINGLETON_MODE]:
            args = s.split(" ")
            tabArg = args[-1]
            for key in self.argCompleters.keys():
                if tabArg.startswith(key):
                    tabArgWithoutKey=tabArg[len(key):]
                    return key+self.argCompleters[key](tabArgWithoutKey, state)
        return None


class CLIShell(basic.LineReceiver, CompleterInterface):
    delimiter = os.linesep
    
    CommandHandler = CLICommand
    
    def __init__(self, prompt=">>> ", banner=None):
        self.prompt = prompt
        self.banner = banner
        self.__helpCmdHandler = CLICommand("help", "Get information on commands", self.__help,
                                           mode = CLICommand.SUBCMD_MODE)
        self.__commands = {}
        self.__registerCommand(self.__helpCmdHandler)
        self.__registerCommand(CLICommand("quit", "Terminate the shell", self.__quit))
        
    def __help(self, writer, cmd=None):
        if cmd:
            if not self.__commands.has_key(cmd):
                writer("No such command %s\n" % cmd)
            else:
                writer("\n\n".join(self.__commands[cmd].help()))
                writer("\n")
            return
        for cmdObj in self.__commands.values():
            if cmdObj == self.__helpCmdHandler:
                writer("  help [cmd]\n")
                continue
            for cmdUsageString in  cmdObj.usageHelp():
                writer("  "+cmdUsageString+"\n")
            
    def __quit(self, writer, *args):
        self.transport.loseConnection()
        reactor.callLater(0, reactor.stop)
        
    def registerCommand(self, cmdHandler):
        if cmdHandler.cmdTxt.startswith("_"):
            raise Exception("Cannot register commands with leading underscores")
        self.__registerCommand(cmdHandler)
        
    def __registerCommand(self, cmdHandler):
        if self.__commands.has_key(cmdHandler.cmdTxt):
            raise Exception("Duplicate command handler")
        self.__commands[cmdHandler.cmdTxt] = cmdHandler
        subCommandHelp = CLICommand(cmdHandler.cmdTxt, "Get information about %s" % cmdHandler.cmdTxt,
                                    lambda writer: self.__help(writer, cmdHandler.cmdTxt))
        self.__helpCmdHandler.configureSubcommand(subCommandHelp)
        
    def complete(self, s, state):
        return completeKeys(self.__commands, s, state)
        
    def connectionMade(self):
        if self.banner:
            self.transport.write(formatText(self.banner)+"\n")
    
    def lineReceived(self, line):
        try:
            self.lineReceivedImpl(line)
        except Exception, e:
            errMsg = traceback.format_exc()
            self.transport.write(errMsg+"\n")
        #self.transport.write("\n"+self.prompt)
        
    def lineReceivedImpl(self, line):
        line = line.strip()
        if not line:
            return
        args = line.split(" ")
        while '' in args: args.remove('')
        cmd = args[0]
        cmdArgs = args[1:]
        callbackHandler = self.__commands.get(cmd, None)
        if callbackHandler == None:
            self.transport.write("Unknown command %s\n" % cmd)
            return
        
        callbackHandler.process(cmdArgs, self.transport.write)
        
if __name__=="__main__":
    printFilename = lambda writer, fname: writer("Got filename: %s\n" % fname)
    shell = CLIShell()
    fnameCommand = CLICommand("print_file", "Print a filename", mode=CLICommand.STANDARD_MODE)
    fnameCommand.configure(1, printFilename, usage="[filename]", 
                           helpTxt="Print out 'filename' to the screen.")
    shell.registerCommand(fnameCommand)
    a = AdvancedStdio(shell)
    reactor.run()