'''
Created on Apr 22, 2014

@author: sethjn
'''
from ClientApplicationServer import ClientApplicationServer
from playground.network.common import SimpleMessageHandlingProtocol, Packet
from playground.network.common import MIBServerImpl, StandardMIBProtocolAuthenticationMixin
from playground.network.message import MessageData
from playground.network.message.definitions.playground.mgmt import MIBRequest, MIBResponse
import random

class SimpleMIBClientProtocol(SimpleMessageHandlingProtocol):
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.registerMessageHandler(MIBResponse, self.__MIBResponseHandler)
        self.__pendingRequests = {}
        self.__privKey = None
        self.__waitForConnection = []
        self.__alive = True
        
    def connectionMade(self):
        for wait in self.__waitForConnection:
            wait()
        #SimpleMessageHandlingProtocol.connectionMade(self)
        
    def connectionLost(self, reason=None):
        self.__waitForConnection = None
        self.__alive = False
        
    def alive(self):
        return self.__alive
            
    def setMIBServerAuthData(self, privateKey):
        self.__privKey = privateKey
    
    def clearPendingRequest(self, id):
        if self.__pendingRequests.has_key(id):
            hits, signed_nonce, cb = self.__pendingRequests[id]
            del self.__pendingRequests[id]
            if hits == 0: cb(False, ["Timeout"])
            
    def __MIBResponseHandler(self, prot, msg):
        msgObj = msg.data()
        if not self.__pendingRequests.has_key(msgObj.ID):
            return
        self.__pendingRequests[msgObj.ID][0] += 1
        signed_nonce, cb = self.__pendingRequests[msgObj.ID][1:]
        # Don't delete the callback. We may get responses
        # from multiple listeners. The timeout will
        # clear this in 30 seconds, so all listeners
        # have 30 seconds to respond
        cb(msgObj.success, StandardMIBProtocolAuthenticationMixin.GetSecuredResponses(msg, signed_nonce, self.__privKey))
        
    def sendMIB(self, mib, args, callback, timeout=30):
        if not self.alive():
            return None
        req = MessageData.GetMessageBuilder(MIBRequest)
        mibRequestId = random.random()
        req["ID"].setData(mibRequestId)
        req["authData"].init()
        if self.__privKey:
            nonce, signed_nonce = StandardMIBProtocolAuthenticationMixin.CreateAuthData(self.__privKey)
        else:
            nonce, signed_nonce = "", ""
        for d in [nonce, signed_nonce]:
            req["authData"].add()
            req["authData"][-1].setData(d)
        req["MIB"].setData(mib)
        req["args"].init()
        for arg in args:
            req["args"].add()
            req["args"][-1].setData(arg)
        self.__pendingRequests[req["ID"].data()] = [0, signed_nonce, callback]
        
        # Transport not guaranteed to have writeMessage...
        if self.transport:
            self.transport.write(Packet.SerializeMessage(req))
        else:
            self.__waitForConnection.append(lambda: self.transport.write(Packet.SerializeMessage(req)))
        if timeout:
            self.callLater(timeout, lambda: self.clearPendingRequest(req["ID"].data()))
        return mibRequestId
    
class SimpleMIBClientFactory(ClientApplicationServer):
    Protocol = SimpleMIBClientProtocol
            
class MIBServer(ClientApplicationServer, MIBServerImpl, StandardMIBProtocolAuthenticationMixin):
    SERVERS = {}
    
    @classmethod
    def GetMibServerForAddr(cls, addr, authCert=None, trustedPrefix=""):
        if not cls.SERVERS.has_key(addr):
            mibServer = MIBServer()
            if authCert:
                mibServer.loadAuthData(authCert)
            if trustedPrefix: 
                mibServer.setTrustedPrefix(trustedPrefix)
            cls.SERVERS[addr] = mibServer
        return cls.SERVERS[addr]
    
    def __init__(self):
        MIBServerImpl.__init__(self)