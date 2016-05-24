'''
Created on Nov 26, 2013

@author: sethjn
'''

from playground.error import Common, PlaygroundError
from playground.network.message import definitions
from playground.network.message import MessageData
from playground.network.common import Packet, PlaygroundAddress, PlaygroundAddressPair
from ClientApplicationTransport import ClientApplicationTransport

from twisted.internet.threads import deferToThread
from twisted.internet import reactor, defer

import logging, pickle

from playground.playgroundlog import packetTrace
logger = logging.getLogger(__name__)
from playground.config import GlobalPlaygroundConfigData
configData = GlobalPlaygroundConfigData.getConfig(__name__)

class ClientRegisteredHandler(object):
    def __init__(self, clientConnectCallback, clientConnectFailCallback):
        self.__connectCb = clientConnectCallback
        self.__connectFailCb = clientConnectFailCallback
        
    def __call__(self, protocol, msg):
        packetTrace(logger, msg, "Start clientRegistered processing")
        
        msgObj = msg.data()
        if msgObj.success:
            packetTrace(logger, msg, "registration successful.")
            self.__connectCb(msgObj)
        else:
            packetTrace(logger, msg, "registration failed.")
            self.__connectFailCb()
            
class RunMobileCodeHandler(object):
    def __init__(self, server, **executionHandlers):
        self.__server = server
        self.__executionHandlers = executionHandlers.copy()
        if not self.__executionHandlers.has_key("serialized"):
            self.__executionHandlers["serialized"] = self.__serializedCodeHandler
        logger.info("Registering mobile code handler with execution handlers for %s" % self.__executionHandlers.keys())
        self.__peer = "<UNNOWN PEER>"
            
    def __defaultCodeHandler(self, codeString):
        try:
            logger.info("executing codestring (default handler)")
            logger.info(codeString)
            d = {}
            exec(codeString, d, d)
            result = d["result"] # force an error if the codeString did not produce a result
            logger.info("result: " + str(result))
        except Exception, e:
            logger.info("Exception " + str(e))
            return (str(e), pickle.dumps(e), "", "")
        return ("", "", str(result), pickle.dumps(result))
    
    def __serializedCodeHandler(self, codeString):
        try:
            logger.info("executing codestring (serialized handler)")
            logger.info(codeString)
            obj = pickle.loads(codeString)
            result = obj()
            logger.info("result: " + str(result))
        except Exception, e:
            logger.info("Exception " + str(e))
            return (str(e), pickle.dumps(e), "", "")
        return ("", "", str(result), pickle.dumps(result))
        
    def __runCodeThrowExceptions(self, codeString, mechanism, strict):
        handler = self.__executionHandlers.get(mechanism, None)
        if handler == None:
            if strict:
                d = defer.Deferred()
                e = Exception("No handler for strict mechanism %s" % mechanism)
                reactor.callLater(.1, d.callback, (str(e), pickle.dumps(e), "", ""))
                return d
            else:
                handler = self.__executionHandlers.get("__default__", self.__defaultCodeHandler)
        
        """ Run the remote code. Wait for deferred result """
        deferredResult = deferToThread(handler, codeString)
        
        return deferredResult
    
    def __sendResultBack(self, protocol, toClientMsg, result):
        exceptionStr, exceptionPickle, resultStr, resultPickle = result
        toClientMsg["success"].setData(exceptionStr == "" and exceptionPickle == "")
        toClientMsg["result"].setData(resultStr)
        toClientMsg["resultPickled"].setData(resultPickle)
        toClientMsg["exception"].setData(exceptionStr)
        toClientMsg["exceptionPickled"].setData(exceptionPickle)
        protocol.transport.writeMessage(toClientMsg)
        
    def __call__(self, protocol, msg):
        """
        Run the Python Code and return the result
        """
        
        self.__peer = str(protocol.transport.getPeer())
        
        """ Get the client message definition first. Don't run anything unless this is going to work """
        toClientMsg = MessageData.GetMessageBuilder(definitions.playground.base.MobileCodeResult)
        if not toClientMsg:
            self.__server.reportError("Could not get message builder for MobileCodeResult")
            return
        
        msgObj = msg.data()
        codeString = msgObj.pythonCode
        mechanism = msgObj.mechanism
        strict = msgObj.strict
        logger.info("RunMobileCode with mechanism %s (strict=%s)" % (mechanism, strict))

        toClientMsg["ID"].setData(msgObj.ID)
        
        try:
            deferredResult = self.__runCodeThrowExceptions(codeString, mechanism, strict)
        except PlaygroundError, e:
            self.__server.reportException(e)
            return
        deferredResult.addCallback(lambda result: self.__sendResultBack(protocol, toClientMsg, result))
        deferredResult.addErrback(lambda failure: self.__server.reportException(failure))
        
class MobileCodeCallbackHandler(object):
    """
    This handler allows for callback registration and then triggers when a 
    mobile code results are returned. It looks up the ID associated with the
    completed code result and calls the appropriate callback.
    """
    def __init__(self):
        self.__callbacks = {}
        
    def registerCallback(self, codeId, callback):
        self.__callbacks[codeId] = callback
    
    def __call__(self, protocol, msg):
        msgObj = msg.data()
        codeId = msgObj.ID
        if not self.__callbacks.has_key(codeId):
            return # Fail silently for results with no matching ID
        cb = self.__callbacks[codeId]
        del self.__callbacks[codeId]

        if msgObj.success:
            try:
                resultObj = pickle.loads(msgObj.resultPickled)
            except:
                resultObj = None
            cb.handleCodeResult(msgObj.result, resultObj)
        else:
            try:
                exceptionObj = pickle.loads(msgObj.exceptionPickled)
            except:
                exceptionObj = None
            cb.handleCodeException(msgObj.exception, exceptionObj)
        
        
class Client2ClientHandler(object):
    """
    The Client2Client Message Handler decapsulates the real message
    and passes it to the appropriate receiver. If no receiver is found,
    the handler fails silently.
    """
    def __init__(self, portToProtocol, closer):
        self.__portToProtocol = portToProtocol
        self.__frags = {}
        self.__closer = closer
        
    def __safeClose(self, protocol):
        if protocol.transport == None: return
        try:
            protocol.transport.loseConnection()
        except:
            pass
        
    def __call__(self, protocol, msg):
        """
        Process a client-to-client message. Note that most failures are silent as
        any guarantees of delivery or connection state must be provided by higher
        layers.
        """
        msgObj = msg.data()
        dstAddress = msgObj.dstAddress
        dstPort = msgObj.dstPort
        logger.debug("%s received message for %s" % (protocol, (dstAddress, dstPort)))
        packetTrace(logger, msg, "Begin processing c2c message for %s" % ((dstAddress, dstPort),))
        if not self.__portToProtocol.has_key(dstPort):
            """ There is no service for the specified port. Fail silently (drop packet) """
            logger.debug("No service. DROP")
            packetTrace(logger, msg, "No service specified for port %d" % dstPort)
            return 
        
        """
        on any given port, there is a database of open connections and (optionally)
        a factory for opening new connections. The factory only exists if there is a server
        listening on this port
        """
        portData = self.__portToProtocol[dstPort]
        peerHost, peerPort = msgObj.srcAddress, msgObj.srcPort
        peerAddressPair = PlaygroundAddressPair(PlaygroundAddress.FromString(peerHost), peerPort)
        
        """ Check for an existing connection """
        connectionProtocol = portData.getConnectionProtocol(peerAddressPair)
        if not connectionProtocol:
            """ No existing connection. Try to spawn (only works if a listening port. """
            
            
            thisAddressPair = PlaygroundAddressPair(PlaygroundAddress.FromString(dstAddress), dstPort)
            connectionResult, resultArg = portData.spawnNewConnection(thisAddressPair, 
                                                                      peerAddressPair)
            
            if connectionResult == False:
                """ Either couldn't spawn because we're not a listening socket
                or there was another kind of error """
                protocol.reportError("Could not spawn connection for c2c from %s to port %d: %s" % 
                                     (peerAddressPair, dstPort, str(resultArg)))
                packetTrace(logger, msg, "Could not spawn connection on port %d. Packet dropped." % dstPort)
                return
            
            """ We have a new connection. Create transport """
            connectionProtocol = resultArg
            connectionProtocol.makeConnection(ClientApplicationTransport(protocol.transport, thisAddressPair, peerAddressPair, self.__closer, protocol.multiplexingProducer()))
            logger.debug("New Connection %s" % connectionProtocol._connectionId())
            packetTrace(logger, msg, "New connection created from %s:%d to %s:%d" % (peerHost, peerPort, dstAddress, dstPort))
        else:
            logger.debug("Existing Connection %s" % connectionProtocol._connectionId())
            packetTrace(logger, msg, "Existing connection identified.")
        
        """ Pass the encapsulated message up """
        if hasattr(msgObj, "ID"):
            logger.debug("FRAG")
            packetTrace(logger, msg, "Is a c2c fragment. Combining with %d" % msgObj.ID)
            if not self.__frags.has_key(msgObj.ID):
                self.__frags[msgObj.ID] = {"last":None}
            self.__frags[msgObj.ID][msgObj.index] = msgObj.clientPacket
            if msgObj.lastPacket:
                self.__frags[msgObj.ID]["last"] = msgObj.index
            if self.__frags[msgObj.ID]["last"] != None:
                # Check if we have all elements
                
                # The number of packets received is keys minus 1 (minus 1 for "last")
                packetsReceived = len(self.__frags[msgObj.ID].keys())-1
                expectedPackets = self.__frags[msgObj.ID]["last"] + 1
                if packetsReceived == expectedPackets:
                    reassembled = ""
                    del self.__frags[msgObj.ID]["last"]
                    packetIndexes = self.__frags[msgObj.ID].keys()
                    packetIndexes.sort()
                    for packetIndex in packetIndexes:
                        reassembled += self.__frags[msgObj.ID][packetIndex]
                    logger.debug("Last Frag. Passing up %d bytes" % len(reassembled))
                    packetTrace(logger, msg, "Pass reassembled message up to %s" % connectionProtocol)
                    try:
                        connectionProtocol.dataReceived(reassembled)
                    except Exception, e:
                        protocol.reportException(e)
                        protocol.callLater(1.0, lambda: self.__safeClose(connectionProtocol))
                    del self.__frags[msgObj.ID]
        else:
            packetTrace(logger, msg, "Pass message up to %s" % connectionProtocol)
            trueMessage = msgObj.clientPacket
            logger.deubg("Passing up encapsulated data %d bytes" % len(trueMessage))
            try:
                connectionProtocol.dataReceived(trueMessage)
            except Exception, e:
                protocol.reportException(e)
                protocol.callLater(1.0, lambda: self.__safeClose(connectionProtocol))
