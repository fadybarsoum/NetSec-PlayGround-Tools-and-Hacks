'''
Created on Mar 27, 2014

@author: sethjn
'''
import pickle, sys
sys.path.append("../..")
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from playground.crypto import X509Certificate, Pkcs7Padding

import struct

class PermanentObjectMixin(object):
    PERM_CERT_KEY = "__PERM__CERT_KEY__"
    PERM_PRIVATE_KEY_KEY = "__PERM__PRIVATE_KEY_KEY__"
    RESERVED_KEYS = [PERM_CERT_KEY, PERM_PRIVATE_KEY_KEY]
    SIGNATURE_PACK = "<Q"
    AES_SIZE = 16
    
    @classmethod
    def getSalt(cls):
        return SHA.new("SALTSALTSALTSALT" + cls.__name__).digest()
    
    @classmethod
    def getIV(cls):
        return SHA.new("IVIVIVIVIVIVIVIV" + cls.__name__).digest()[:cls.AES_SIZE]
    
    @classmethod
    def secureSaveState(cls, filename, cert, privateKey, password, **state):
        for key in cls.RESERVED_KEYS:
            if key in state.keys():
                raise Exception("Reserved key %s used in save state" % key)
        state[cls.PERM_CERT_KEY] = cert.dumpPEM()
        state[cls.PERM_PRIVATE_KEY_KEY] = privateKey.exportKey()
        data = pickle.dumps(state)
        fileKey = PBKDF2(password, cls.getSalt())[:cls.AES_SIZE]
        
        encrypter = AES.new(key=fileKey, mode=AES.MODE_CBC, IV=cls.getIV())
        paddedData = Pkcs7Padding(AES.block_size).padData(data)
        encryptedData = encrypter.encrypt(paddedData)
        signer = PKCS1_v1_5.new(privateKey)
        signature = signer.sign(SHA.new(encryptedData))
        fileContents = encryptedData + signature + struct.pack(cls.SIGNATURE_PACK,len(signature))

        with open(filename, "wb+") as f:
            f.write(fileContents)
            
    @classmethod
    def secureLoadState(cls, filename, cert, password):
        with open(filename, "rb") as f:
            contents = f.read()
        packSize = struct.calcsize(cls.SIGNATURE_PACK)
        body, signatureSizeStructString = contents[:-packSize], contents[-packSize:]
        signatureSize = struct.unpack(cls.SIGNATURE_PACK, signatureSizeStructString)[0]
        encryptedData, signature = body[:-signatureSize], body[-signatureSize:]

        publicKey = RSA.importKey(cert.getPublicKeyBlob())
        verifier = PKCS1_v1_5.new(publicKey)
        if not verifier.verify(SHA.new(encryptedData), signature):
            raise Exception("Invalid cryptographic save state. Verification of signature failed.")
        fileKey = PBKDF2(password, cls.getSalt())[:cls.AES_SIZE]
        decrypter = AES.new(key=fileKey, mode=AES.MODE_CBC, IV=cls.getIV())
        paddedData = decrypter.decrypt(encryptedData)
        data = Pkcs7Padding(AES.block_size).unpadData(paddedData)
        state = pickle.loads(data)
        if state[cls.PERM_CERT_KEY] != cert.dumpPEM():
            raise Exception("Certificate mismatch")
        del state[cls.PERM_CERT_KEY]
        privateKey = RSA.importKey(state[cls.PERM_PRIVATE_KEY_KEY])
        del state[cls.PERM_PRIVATE_KEY_KEY]
        return privateKey, state