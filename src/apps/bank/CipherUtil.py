'''
Created on Mar 29, 2014

@author: sethjn
'''
import sys
sys.path.append("../..")
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from playground.crypto import X509Certificate, Pkcs7Padding

class CIPHER_AES128_CBC(object):
    def __init__(self, key, iv):
        self.encrypter = AES.new(key, IV=iv, mode=AES.MODE_CBC)
        self.decrypter = AES.new(key, IV=iv, mode=AES.MODE_CBC)
        self.block_size = AES.block_size
        
    def encrypt(self, data):
        paddedData = Pkcs7Padding(self.block_size).padData(data)
        return self.encrypter.encrypt(paddedData)
    
    def decrypt(self, data):
        paddedData = self.decrypter.decrypt(data)
        return Pkcs7Padding(self.block_size).unpadData(paddedData)
    
class MAC_HMAC_SHA1(object):
    MAC_SIZE = 20
    def __init__(self, key):
        self.__key = key#self.mac = HMAC.new(key)
    
    def mac(self, data):
        mac = HMAC.new(self.__key, digestmod=SHA)
        mac.update(data)
        return mac.digest()
    
    def verifyMac(self, data, checkMac):
        mac = self.mac(data)
        return mac == checkMac

class RSA_SIGNATURE_MAC(object):
    MAC_SIZE = 128
    def __init__(self, key):
        self.signer = PKCS1_v1_5.new(key)
        self.verifier = PKCS1_v1_5.new(key.publicKey())
        
    def mac(self, data):
        digest = SHA.new(data).digest()
        return self.signer.sign(digest)
    
    def verifyMac(self, data, checkMac):
        digest = SHA.new(data).digest()
        return self.signer.verify(digest, checkMac)

class EncryptThenMac(object):
    @staticmethod
    def CreateMode(encMode, macMode):
        return lambda k_enc, iv, k_mac: EncryptThenMac(encMode, macMode, k_enc, iv, k_mac)
    
    def __init__(self, encMode, macMode, k_enc, iv, k_mac):
        self.encrypter = encMode(k_enc, iv)
        self.mac = macMode(k_mac)
    
    def encrypt(self, data):
        cipherText = self.encrypter.encrypt(data)
        return cipherText + self.mac.mac(cipherText)
    
    def decrypt(self, data):
        cipherText, storedMac = data[:-self.mac.MAC_SIZE], data[-self.mac.MAC_SIZE:]
        if not self.mac.verifyMac(cipherText, storedMac):
            return None
        return self.encrypter.decrypt(cipherText)
    
EncryptThenHmac = EncryptThenMac.CreateMode(CIPHER_AES128_CBC, MAC_HMAC_SHA1)
EncryptThenRsaSign = EncryptThenMac.CreateMode(CIPHER_AES128_CBC, RSA_SIGNATURE_MAC)

def DefaultSign(msg, rsaKey):
    return PKCS1_v1_5.new(rsaKey).sign(SHA.new(msg))