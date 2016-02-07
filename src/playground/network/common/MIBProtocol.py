'''
Created on Apr 18, 2014

@author: sethjn
'''
from playground.network.common import SimpleMessageHandlingProtocol
from Packet import Packet
from playground.network.message import MessageData
from playground.network.message.definitions.playground.mgmt import MIBRequest, MIBResponse
from playground.crypto import DefaultRSASigningAlgo, DefaultRSAEncryptionAlgo, RSA, SHA, AES, Pkcs7Padding

from playground.playgroundlog import packetTrace, logging

logger = logging.getLogger(__name__)

import os, time, struct

class MIBProtocolAuthenticationMixin(object):
    def authenticate(self, hostData, authData):
        return False
    
class StandardMIBProtocolAuthenticationMixin(MIBProtocolAuthenticationMixin):
    NO_AUTH = False
    PUBLIC_KEY = None
    TRUSTED_PREFIX = ""
    HASH_ALGO = SHA
    NONCE_SIZE = struct.calcsize(">d")
    TIME_RANGE = 5.0 # 5 seconds
    
    @classmethod
    def CreateAuthData(cls, privateKey):
        hasher = cls.HASH_ALGO.new()
        nonce = struct.pack(">d", time.time())
        hasher.update(nonce)
        signer = DefaultRSASigningAlgo.new(privateKey)
        return (nonce, signer.sign(hasher))
    
    def disableAuthentication(self):
        self.NO_AUTH = True
        
    def loadAuthData(self, certificateObj):
        publicKeyBlob = certificateObj.getPublicKeyBlob()
        self.PUBLIC_KEY = RSA.importKey(publicKeyBlob)
            
    def setTrustedPrefix(self, prefix):
        self.TRUSTED_PREFIX = prefix
        
    def authenticate(self, hostData, authData):
        if self.NO_AUTH:
            return True
        if not self.PUBLIC_KEY: 
            return False
        if not str(hostData.host).startswith(self.TRUSTED_PREFIX):
            return False
        curTime = time.time()
        nonce = authData[0]
        signed_nonce = authData[1]
        if len(nonce) != self.NONCE_SIZE: return False
        hasher = self.HASH_ALGO.new()
        hasher.update(nonce)
        verifier = DefaultRSASigningAlgo.new(self.PUBLIC_KEY)
        if not verifier.verify(hasher, signed_nonce):
            return False
        try:
            timestamp = struct.unpack(">d", nonce)[0]
        except:
            return False
        if (curTime - timestamp) > self.TIME_RANGE:
            return False
        return True
    
    def SecureResponse(self, request, response):
        authData = request["authData"].data()
        origResponses = response["responses"].data()
        response["responses"].add(2)
        response["responses"][0].setData(authData[1])
        encrypter = DefaultRSAEncryptionAlgo(self.PUBLIC_KEY, None, None, None)
        aeskey = os.urandom(16)
        iv = os.urandom(16)
        response["responses"][1].setData(encrypter.encrypt(aeskey+iv))
        aesEncrypter = AES.new(aeskey, IV=iv, mode=AES.MODE_CBC)
        padder = Pkcs7Padding(16)
        for i in range(len(origResponses)):
            encryptedResponse = aesEncrypter.encrypt(padder.padData(origResponses[i]))
            response["responses"][i+2].setData(encryptedResponse)
        return response
    
    @classmethod
    def GetSecuredResponses(cls, response, signedTimestamp, privateKey):
        responses = response["responses"].data()
        if len(responses) < 2 or responses[0] != signedTimestamp:
            return []
        decryptedResponses = []
        decrypter = DefaultRSAEncryptionAlgo(privateKey, None, None, None)
        keyAndIV = decrypter.decrypt(responses[1])
        key = keyAndIV[:16]
        iv = keyAndIV[16:]
        aesDecrypter = AES.new(key, IV=iv, mode=AES.MODE_CBC)
        padder = Pkcs7Padding(16)
        for encryptedResponse in responses[2:]:
            decryptedResponse = padder.unpadData(aesDecrypter.decrypt(encryptedResponse))
            decryptedResponses.append(decryptedResponse)
        return decryptedResponses

class MIBServerProtocol(SimpleMessageHandlingProtocol):
    
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.registerMessageHandler(MIBRequest, self.__MIBRequestHandler)
        
        self.__authenticate = False
        self.__factory = factory
        self.__addr = addr
        self.__pendingRequests = {}
        if isinstance(self.__factory, MIBProtocolAuthenticationMixin):
            self.__authenticate = True
        
    def __MIBRequestHandler(self, prot, msg):
        msgObj = msg.data()
        authData = msgObj.authData
        resp = MessageData.GetMessageBuilder(MIBResponse)
        resp["ID"].setData(msgObj.ID)
        resp["responses"].init()
        if self.__authenticate and not self.__factory.authenticate(prot.transport.getHost(), authData):
            resp["success"].setData(False)
            resp["responses"].add()
            resp["responses"][-1].setData("Authentication failed")
            prot.transport.write(resp.serialize())
            return
        resp["success"].setData(True)
        mib = msgObj.MIB
        args = msgObj.args
        callbacks = self.__factory.getCallbacksForKey(mib)
        responses = []
        for c in callbacks:
            try:
                responses += map(str, c(mib, args)) 
            except Exception, e:
                print e
        for r in responses:
            resp["responses"].add()
            resp["responses"][-1].setData(r)
        if self.__authenticate:
            resp = self.__factory.SecureResponse(msg, resp)
        prot.transport.write(resp.serialize())
        
class MIBServerImpl(object):
    Protocol = MIBServerProtocol
    CALLBACKS = object()
    REFCOUNT = object()
    SPECIAL_KEYS = [CALLBACKS, REFCOUNT]
    
    # Builtin mibs
    GET_LOADED_MIBS = ("__builtin__","GET_LOADED_MIBS")

    def registerMIB(self, prefix, listeningKey, callback):
        if not listeningKey:
            raise Exception("Listening Key cannot be empty")
        d = self.DEFINED_MIBS
        listen = False
        for parts in [prefix.split("."), listeningKey.split(".")]:
            for p in parts:
                if not d.has_key(p):
                    d[p] = {self.CALLBACKS:set([]), self.REFCOUNT:0}
                d = d[p]
                d[self.REFCOUNT] += 1
                if listen: d[self.CALLBACKS].add(callback)
            listen = True
            
    def deregisterMib(self, dottedKey):
        d = self.DEFINED_MIBS
        parts = dottedKey.split(".")
        erase = []
        for p in parts:
            elm = (d, p)
            d = d.get(p, None)
            if not d: break
            d[self.REFCOUNT] -= 1
            if d[self.REFCOUNT] <= 0:
                erase.append(elm)
        for d, key in erase:
            del(d[key])
            
    def getCallbacksForKey(self, dottedkey):
        d = self.DEFINED_MIBS
        parts = dottedkey.split(".")
        callbacks = set([])
        for p in parts:
            d = d.get(p, None)
            if not d: break
            callbacks.update(d[self.CALLBACKS])
        return callbacks
            
    def getLoadedMibs(self, mib, args):
        d = self.DEFINED_MIBS
        mibs = []
        stack = [("",d)]
        while stack:
            curKey, curD = stack.pop(-1)
            for sub in curD.keys():
                if sub in self.SPECIAL_KEYS: continue
                stack.append((curKey+"."+sub, curD[sub]))
            if curD.has_key(self.CALLBACKS) and curD[self.CALLBACKS]:
                mibs.append(curKey[1:])
        return mibs
    
    def __init__(self):
        self.DEFINED_MIBS = {}
        self.registerMIB(self.GET_LOADED_MIBS[0], self.GET_LOADED_MIBS[1], self.getLoadedMibs)