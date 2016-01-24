'''
Created on Apr 22, 2014

@author: sethjn
'''

import os
from playground.config import GlobalPlaygroundConfigData
from X509Certificate import X509Certificate
from Crypto.PublicKey import RSA
configData = GlobalPlaygroundConfigData.getConfig(__name__)

class CertificateDatabase(object):
    
    INSTANCE = None
    
    @classmethod
    def GetDatabase(cls):
        if not cls.INSTANCE:
            cls.INSTANCE = CertificateDatabase()
        return cls.INSTANCE
    
    def __init__(self):
        #if not os.path.exists("rls.conf"):
        #    raise Exception("No configuration file for rls certificate database. Please review src/rls.conf.sample")
        #config = loadConfigFile("rls.conf")
        
        self.CERT_DIR = configData.get("CERT_DIR", None)
        self.ROOT_CERT = configData.get("ROOT_CERT", None)
        self.CERT_CA = configData.get("CA_CERT", None)
        
        if None in [self.ROOT_CERT, self.CERT_CA, self.CERT_DIR]:
            raise Exception("Configuration file missing required value")
        
        self.CERT_DIR = os.path.expanduser(self.CERT_DIR)
        self.ROOT_CERT = os.path.join(self.CERT_DIR, self.ROOT_CERT)
        self.CERT_CA = os.path.join(self.CERT_DIR, self.CERT_CA)
    
        self.ROOT = None
        with open(self.ROOT_CERT) as f:
            self.ROOT = f.read()
        if not self.ROOT:
            raise Exception("No Root Cert")
        
    def getRawFile(self, filename):
        abspath = os.path.join(self.CERT_DIR, filename)
        if os.path.exists(abspath):
            with open(abspath) as f:
                data = f.read()
            return data
        return None
        
    def loadX509(self, filename):
        data = self.getRawFile(filename)
        if data:
            return X509Certificate.loadPEM(data)
        return None
        
    def loadPrivateKey(self, filename):
        data = self.getRawFile(filename)
        if data:
            return RSA.importKey(data)
        return None
        
    def loadCertsAndKey(self, playgroundAddr):
        addrStr = playgroundAddr.toString()
        certFileNames = [os.path.join(self.CERT_DIR, "%s_signed.cert" % addrStr)]
        certFileNames.append(self.CERT_CA)
        certFileNames.append(self.ROOT_CERT)
        chain = []
        for fileName in certFileNames:
            if not os.path.exists(fileName):
                raise Exception("No such cert file %s" % fileName)
            with open(fileName) as f:
                chain.append(f.read())
        privKeyName = os.path.join(self.CERT_DIR, "%s.key" % addrStr)
        if not os.path.exists(privKeyName):
            raise Exception("No such key for addr %s" % addrStr)
        privKeyData = None
        with open(privKeyName) as f:
            privKeyData = f.read()
        if not privKeyData:
            raise Exception("No private key data in key file!")
        return (chain, privKeyData)