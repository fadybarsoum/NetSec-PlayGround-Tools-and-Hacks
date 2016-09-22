'''
Created on Dec 5, 2013

@author: sethjn
'''

import logging
import json
import logging.config
import random, os
from playground.config import GlobalPlaygroundConfigData, extractList

configData = GlobalPlaygroundConfigData.getConfig(__name__)

g_StdErrHandler = logging.StreamHandler()

def UseStdErrHandler(enable, loggerName=""):
    logger = logging.getLogger(loggerName)
    if enable and g_StdErrHandler not in logger.handlers:
        logger.addHandler(g_StdErrHandler)
    if not enable and g_StdErrHandler in logger.handlers:
        logger.removeHandler(g_StdErrHandler)

class LoggingContext(object):
    def __init__(self, name=None):
        self.logDirectory = os.path.join( os.getcwd(), "logs" )
        self.nodeId = name and name or "unknown_"+str(random.randint(0,1024))
        self.doPacketTracing = False
        self.logConfig = None

"""
g_Ctx is the Playground Global Logging context. It is set by 
whatever logging context is passed to startLogging(). This is
a poor solution and we should definitely do something better...
"""
g_Ctx = None

def protocolLog(protocol, logmethod, msg):
    pmsg = "[%s (%d) connected to " % (str(protocol.__class__), id(protocol))
    if protocol.transport:
        pmsg += str(protocol.transport.getPeer())
    else: pmsg += "<UNCONNECTED>"
    pmsg += "] " + msg
    logmethod(pmsg) 

def packetTrace(logger, packet, msg):
    """
    A special logging function that is independent of logging 
    levels. When packet tracing is enabled, it is always logged
    no matter the log level. When it is disabled, it is always
    off.
    
    TODO: Consider making PacketTrace level specific...
    """
    if not g_Ctx or not g_Ctx.doPacketTracing:
        return
    
    msgType, msgVrs = packet.topLevelData()
    msgString = "<<PACKET_TRACE>> ["
    msgString += msgType + " v"
    msgString += msgVrs + " ID:"
    msgString += str(packet["playground_msgID"].data()) +"] "
    msgString += "\n\t" + msg
    
    """ 
    Log to the logger's effective level +1. If packet 
    tracing is disabled this is all ignored anyway. 
    """
    logger.log(logger.getEffectiveLevel()+1, msgString)
    
def convertPlaygroundConfigToLoggerConfig(configObj):
    """ Convert version to int"""
    result = configObj.get("version", None)
    if not result: return None
    configObj["version"] = int(configObj["version"])
    
    """ Convert disable_Existing_loggers to boolean """
    disableExistingLoggers = configObj.get("disable_existing_loggers", "False")
    if disableExistingLoggers.lower() == "true":
        disableExistingLoggers = True
    elif disableExistingLoggers.lower() == "false":
        disableExistingLoggers = False
    else:
        raise Exception("Malformed config. disable_existing_loggers must be 'true' or 'false'")
    configObj["disable_existing_loggers"] = disableExistingLoggers
    
    """ Convert elements to lists """
    listKeys = extractList(configObj, "list_keys", "")
    
    for keyToConvertToList in listKeys:
        if configObj.has_key(keyToConvertToList):
            configObj[keyToConvertToList] = extractList(configObj, keyToConvertToList, "")
    return configObj.toDictionaries()

def startLogging(logCtx):
    """
    Start up logging. We wait for a logging context so that we
    can get information about the Playground Address of the
    running application.
    
    Obviously this is limited to a single address per application.
    But this is the common case and in the rare cases where someone
    wants to have two addresses at once, they can customize the nodeid
    to reflect this
    """
    global g_Ctx
    
    g_Ctx = logCtx
    
    """ Create the log directory if necessary """
    if not os.path.exists(logCtx.logDirectory):
        os.mkdir(logCtx.logDirectory)
        
    """ Configure the root logger """
    
    """ Set these options to fill in some of the blanks """
    configData["logdir"] = logCtx.logDirectory.replace("\\","\\\\")
    configData["nodeid"] = logCtx.nodeId
    
    """ get the default options dictionary """
    defaultOpts = configData.get("default_config",{})
    loggerConfig = convertPlaygroundConfigToLoggerConfig(defaultOpts)
    if loggerConfig:
        logging.config.dictConfig(loggerConfig)
