'''
Created on Feb 16, 2016

@author: sethjn
'''

import os, threading, sys, textwrap, traceback, shlex
from twisted.internet import reactor, defer
from twisted.protocols import basic


class AdvancedStdio(object):
    ReadlineModule = None
    def __init__(self, protocol):
        # don't import readline unless we're instantiating. Help with 
        # platform handling
        if not AdvancedStdio.ReadlineModule:
            import readline
            AdvancedStdio.ReadlineModule = readline
        self.__protocol = protocol
        self.__getLine = False
        self.__getLineLock = threading.Lock()
        self.__getLineCV = threading.Condition(self.__getLineLock)
        self.__quit = False
        self.__quitLock = threading.Lock()
        self.__inputLock = threading.Lock()
        reactor.callInThread(self.loop)
        
    def write(self, buf):
        if self.__inputLock.locked():
            sys.stdout.write("\n")
        sys.stdout.write(buf)
        if not buf[-1] == "\n":
            sys.stdout.flush()
        #else:
        #    if not self.shouldQuit() and self.__inputLock.locked():
        #        sys.stdout.write(self.__protocol.prompt + self.ReadlineModule.get_line_buffer())
        #        sys.stdout.flush()
        
    def refreshDisplay(self):
        if not self.shouldQuit() and self.__inputLock.locked():
            sys.stdout.write(self.__protocol.prompt + self.ReadlineModule.get_line_buffer())
            sys.stdout.flush()
            
    def getNextInput(self):
        with self.__getLineLock:
            self.__getLine = True
            self.__getLineCV.notify()
        
    def loseConnection(self):
        reactor.callLater(0,reactor.stop)
        with self.__quitLock:
            self.__quit = True
            
    def incompleteShutdown(self):
        with self.__getLineLock:
            # I don't understand twisted shutdown handling well yet.
            # why does ctr-c start shutdown, but not call reactor.stop?
            if (self.__getLine and not self.__quit) or self.__inputLock.locked():
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
        result, d = self.__protocol.lineReceived(line)
        if d:
            d.addCallback(lambda result: self.getNextInput())
        else:
            self.getNextInput()

    def loop(self):
        readline = self.ReadlineModule
        reactor.addSystemEventTrigger('before', 'shutdown', self.incompleteShutdown)
        readline.set_completer_delims("")
        if isinstance(self.__protocol, CompleterInterface):
            readline.set_completer(self.__protocol.complete)
        readline.parse_and_bind("tab: complete")
        self.__protocol.makeConnection(self)
        with self.__getLineLock:
            self.__getLine=True
        while not self.shouldQuit():
            try:
                with self.__inputLock:
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
        self.argCompleters = {"f://":FileArgCompleter}
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
        for key in self.argCompleters.keys():
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
                return (False, None)
            else: 
                d = self.__defaultCb(writer, *args)
                return (True, d)
        if len(args)==0:
            if not self.__defaultCb:
                writer("Command requires arguments\n")
            else:
                args = self.__defaultArgHandler(writer, *args)
                if args == None:
                    writer("Command failed.\n")
                    return (False, None)
                else:
                    d = self.__defaultCb(writer, *args)
                    return (True, d)
        if self.__mode == CLICommand.SUBCMD_MODE:
            subCmd = args[0]
            subCmdArgs = args[1:]
            subCmdHandler = self.cb.get(subCmd, None)
            if not subCmdHandler:
                writer("No such command %s\n" % subCmd)
                return (False, None)
            return subCmdHandler.process(subCmdArgs, writer)
        else:
            args = map(self.stripCompleterKeys, args)
            argsPod = self.cb.get(len(args), None)
            if not argsPod:
                writer("Wrong number of arguments\n")
                return (False, None)
            args = argsPod.argHandler(writer, *args)
            if args == None:
                writer("Command failed\n")
                return (False, None)
            else:
                d = argsPod.cmdHandler(writer, *args)
                return (True, None)
        
    def complete(self, s, state):
        if self.__mode == CLICommand.SUBCMD_MODE:
            return completeKeys(self.cb, s, state)
        elif self.__mode in [CLICommand.STANDARD_MODE, CLICommand.SINGLETON_MODE]:
            args = s.split(" ")
            tabArg = args[-1]
            finishedArgs = args[:-1]
            for key in self.argCompleters.keys():
                if tabArg.startswith(key):
                    tabArgWithoutKey=tabArg[len(key):]
                    completeString = ""
                    if finishedArgs: completeString += " ".join(finishedArgs) + " "
                    completeString += key + self.argCompleters[key](tabArgWithoutKey, state)
                    return completeString
        return None


class CLIShell(basic.LineReceiver, CompleterInterface):
    delimiter = os.linesep
    
    CommandHandler = CLICommand
    
    def __init__(self, prompt=">>> ", banner=None):
        self.prompt = prompt
        self.banner = banner
        self.__helpCmdHandler = CLICommand("help", "Get information on commands", self.help,
                                           mode = CLICommand.SUBCMD_MODE)
        self.__batchCmdHandler = CLICommand("batch", "Execute a file with a batch of instructions",
                                            mode = CLICommand.STANDARD_MODE)
        self.__batchCmdHandler.configure(1, self.__batch, "Launch [batch_file]", 
                                         usage = "[batch_file]")
        self.__commands = {}
        self.__registerCommand(self.__helpCmdHandler)
        self.__registerCommand(self.__batchCmdHandler)
        self.__registerCommand(CLICommand("quit", "Terminate the shell", self.quit,
                                          mode=CLICommand.STANDARD_MODE))
        
    def help(self, writer, cmd=None):
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
                
    def __runBatchLines(self, writer, batchLines, batchDeferred):
        while batchLines:
            line = batchLines.pop(0)
            writer("[Batch] > %s\n" % line)
            result, d = self.lineReceived(line)
            if not result:
                writer("  Batch failed\n")
                # even though this failed, we have a successful callback
                # to the I/O system
                batchDeferred.callback(True)
                return
            if d:
                d.addCallback(lambda result: self.__runBatchLines(writer, batchLines, batchDeferred))
                # we need to wait. So return the batch deferred for the 
                # i/o system to wait on.
                return batchDeferred
        writer("Batch Complete\n")
        batchDeferred.callback(True)
        # all done. No batch deferred required (return none)
                
    def __batch(self, writer, batchFile):
        if not os.path.exists(batchFile):
            writer("No such file %s\n"%batchFile)
            return
        d = defer.Deferred()
        with open(batchFile) as f:
            batchLines = f.readlines()
            d = self.__runBatchLines(writer, batchLines, d)
        # d is either the same d as above, or None
        # if it's d, the I/O system will wait until batch is complete
        # otherwise, will return immediately
        return d
            
    def quit(self, writer, *args):
        self.transport.loseConnection()
        
    def registerCommand(self, cmdHandler):
        if cmdHandler.cmdTxt.startswith("_"):
            raise Exception("Cannot register commands with leading underscores")
        self.__registerCommand(cmdHandler)
        
    def __registerCommand(self, cmdHandler):
        if self.__commands.has_key(cmdHandler.cmdTxt):
            raise Exception("Duplicate command handler")
        self.__commands[cmdHandler.cmdTxt] = cmdHandler
        subCommandHelp = CLICommand(cmdHandler.cmdTxt, "Get information about %s" % cmdHandler.cmdTxt,
                                    lambda writer, *args: self.help(writer, cmdHandler.cmdTxt))
        self.__helpCmdHandler.configureSubcommand(subCommandHelp)
        
    def complete(self, s, state):
        return completeKeys(self.__commands, s, state)
        
    def connectionMade(self):
        if self.banner:
            self.transport.write(formatText(self.banner)+"\n")
    
    def lineReceived(self, line):
        try:
            return self.lineReceivedImpl(line)
        except Exception, e:
            errMsg = traceback.format_exc()
            self.transport.write(errMsg+"\n")
            return False, None
        #self.transport.write("\n"+self.prompt)
        
    def lineReceivedImpl(self, line):
        line = line.strip()
        if not line:
            return (False, None)
        args = shlex.split(line)
        while '' in args: args.remove('')
        cmd = args[0]
        cmdArgs = args[1:]
        callbackHandler = self.__commands.get(cmd, None)
        if callbackHandler == None:
            self.transport.write("Unknown command %s\n" % cmd)
            return (False, None)
        
        return callbackHandler.process(cmdArgs, self.transport.write)
        
if __name__=="__main__":
    printFilename = lambda writer, fname: writer("Got filename: %s\n" % fname)
    shell = CLIShell()
    fnameCommand = CLICommand("print_file", "Print a filename", mode=CLICommand.STANDARD_MODE)
    fnameCommand.configure(1, printFilename, usage="[filename]", 
                           helpTxt="Print out 'filename' to the screen.")
    shell.registerCommand(fnameCommand)
    a = AdvancedStdio(shell)
    reactor.run()