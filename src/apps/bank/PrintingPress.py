'''
Created on Mar 18, 2014

@author: sethjn
'''

import sys
sys.path.append("../..")

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from playground.crypto import X509Certificate, Pkcs7Padding

import time, struct, random, os, pickle
import getpass

from Exchange import BitPoint
from PermanentObject import PermanentObjectMixin

class BitPointVerifier(object):
    SIG_ALGO = PKCS1_v1_5
    HASH_ALGO = SHA
    
    def __init__(self, authorityCert):
        self.__issuer = authorityCert.getSubject()["commonName"]
        publicKey = RSA.importKey(authorityCert.getPublicKeyBlob())
        self.__verifier = self.SIG_ALGO.new(publicKey)
        
    def verify(self, bp):
        sigVerified = self.__verifier.verify(self.HASH_ALGO.new(bp.mainDataBlob()), bp.signatureBlob())
        if not sigVerified:
            return (False,"Invalid signature")
        if bp.issuer() != self.__issuer:
            return (False, "Invalid issuer %s (expected %s)" % (bp.issuer(),
                                                                self.__issuer))
        return (True,"Validated Correctly")

class PrintingPress(PermanentObjectMixin):
    INSTANCE = None
    #ISSUER = "PLAYGROUND PROJECT ROOT BANK - Q1 2014"
    
    SERIES_RANGE = 9999999999
    
    """PASSWORD_SALT = "PRINTING_PRESS"
    ENCRYPTION_IV = "PENNYSAVEDEARNED"
    SIGNATURE_SIZE = 128"""
    
    @classmethod
    def CreateBankVault(cls, filename, certificate, privateKey, password, startingSerialNumber=0):
        """seriesStringLength = len(str(cls.SERIES_RANGE))
        seriesTemplate = "P%" + ("%0d"%seriesStringLength) + "d"
        series = seriesTemplate % random.randint(0,cls.SERIES_RANGE)
        assert len(series) == (seriesStringLength+1)
        fileKey = PBKDF2(password, cls.PASSWORD_SALT)
        serialNumber = startingSerialNumber
        
        data = struct.pack("!Q%dsH" % len(series), serialNumber, series, len(certificate.dumpPEM()))
        data += struct.pack("!%dsH" % len(certificate.dumpPEM()), certificate.dumpPEM(), len(privateKey.exportKey()))
        data += struct.pack("!%ds" % len(privateKey.exportKey()), privateKey.exportKey())
        encrypter = AES.new(key=fileKey, mode=AES.MODE_CBC, IV=cls.ENCRYPTION_IV)
        paddedData = Pkcs7Padding(AES.block_size).padData(data)
        encryptedData = encrypter.encrypt(paddedData)
        signer = PKCS1_v1_5.new(privateKey)
        signature = signer.sign(SHA.new(encryptedData))
        fileContents = encryptedData + signature
        with open(filename, "wb+") as f:
            f.write(fileContents)"""
        seriesStringLength = len(str(cls.SERIES_RANGE))
        seriesTemplate = "P%" + ("%0d"%seriesStringLength) + "d"
        series = seriesTemplate % random.randint(0,cls.SERIES_RANGE)
        cls.secureSaveState(filename, certificate, privateKey, password, serialNumber=startingSerialNumber,
                                                                            series=series)
    
    def __init__(self, certificate, password, bankStateVaultFileName):
        if not os.path.exists(bankStateVaultFileName):
            raise Exception ("No Bank State Vault %s" % bankStateVaultFileName)
        if PrintingPress.INSTANCE:
            raise Exception("Duplicate Printing Press")
        PrintingPress.INSTANCE = self
        self.__cert = certificate
        self.ISSUER = self.__cert.getSubject()["commonName"]
        self.__password = password
        self.__stateFileName = bankStateVaultFileName
        self.__loadState()
        
    def __loadState(self):
        """with open(self.__stateFileName, "rb") as f:
            contents = f.read()
        encryptedData, signature = contents[:-self.SIGNATURE_SIZE], contents[-self.SIGNATURE_SIZE:]
        publicKey = RSA.importKey(self.__cert.getPublicKeyBlob())
        verifier = PKCS1_v1_5.new(publicKey)
        if not verifier.verify(SHA.new(encryptedData), signature):
            raise Exception("Invalid bank vault. Signature Failed")
        fileKey = PBKDF2(self.__password, self.PASSWORD_SALT)
        decrypter = AES.new(key=fileKey, mode=AES.MODE_CBC, IV=self.ENCRYPTION_IV)
        paddedData = decrypter.decrypt(encryptedData)
        data = Pkcs7Padding(AES.block_size).unpadData(paddedData)
        seriesStringLength = len(str(self.SERIES_RANGE))
        serialNumber, series, certLen = struct.unpack_from("!Q"+("%d"%(seriesStringLength+1))+"sH", data)
        offset = struct.calcsize("!Q"+("%d"%(seriesStringLength+1))+"sH")
        rawCertData, privKeyLen = struct.unpack_from("!"+("%d" % certLen) + "sH", data, offset)
        if self.__cert.dumpPEM() != rawCertData:
            raise Exception("Invalid bank vault. Certificate mismatch")
        offset += struct.calcsize("!"+("%d" % certLen) + "sH")
        rawPrivKeyData, = struct.unpack_from("!"+("%d" % privKeyLen) + "s", data, offset)
        self.__privateKey = RSA.importKey(rawPrivKeyData)
        self.__signaturePad = PKCS1_v1_5.new(self.__privateKey)
        self.__serialNumber = serialNumber
        self.__series = series"""
        self.__privateKey, state = self.secureLoadState(self.__stateFileName, self.__cert, self.__password)
        self.__signaturePad = PKCS1_v1_5.new(self.__privateKey)
        self.__serialNumber = state["serialNumber"]
        self.__series = state["series"]
        
    def __saveState(self):
        self.CreateBankVault(self.__stateFileName, self.__cert, self.__privateKey, self.__password, self.__serialNumber)
        
    def __getNewSerialNumbers(self, count=1):
        baseSerialNumber = self.__serialNumber
        self.__serialNumber += count
        self.__saveState()
        return [baseSerialNumber+i for i in range(count)]
    
    def mintBitPoints(self, count, depositor):
        newSerialNumbers = self.__getNewSerialNumbers(count)
        bitPoints = []
        for i in range(count):
            bitPoint = BitPoint.mintNew(issuer = self.ISSUER, 
                                serialNumber = "%020d" % newSerialNumbers[i], 
                                timestamp = time.ctime())
            bitPointBin = bitPoint.mainDataBlob()
            bitPoint.setSignature(self.__signaturePad.sign(SHA.new(bitPointBin)))
            bitPoints.append(bitPoint)
            
        depositor(bitPoints)
    
def test_start(filename, cert, key, passwd, depositor):
    PrintingPress.CreateBankVault(filename, cert, key, passwd)
    mint = PrintingPress(cert, passwd, filename)
    mint.mintBitPoints(10, depositor)
    mint.mintBitPoints(20, depositor)
    
def simulate_shutdown():
    PrintingPress.INSTANCE = None
    
def test_reload(filename, cert, passwd, depositor):
    mint = PrintingPress(cert, passwd, filename)
    mint.mintBitPoints(10, depositor)
    
def test_basic():
    
    def printPoints(p):
        for bp in p:
            print bp
    
    filename, cert, key = sys.argv[1:]
    with open(cert) as f:
        cert = X509Certificate.loadPEM(f.read())
    with open(key) as f:
        key = RSA.importKey(f.read())
    passwd = getpass.getpass()
    
    test_start(filename, cert, key, passwd, printPoints)
    simulate_shutdown()
    test_reload(filename, cert, passwd, printPoints)

class DefaultSerializer(object):
    def __init__(self, outputDir=None, filebase="bitpoints"):
        self.__outputDir = outputDir
        if outputDir and not os.path.exists(self.__outputDir):
            raise Exception("No such directory %s" % self.__outputDir)
        self.__base = filebase  
        
    def __call__(self, bps):
        filename = "%s.%d.%s" % (self.__base, len(bps), time.ctime().replace(" ","_"))
        if self.__outputDir:
            filename = os.path.join(self.__outputDir, filename)
        with open(filename, "wb+") as f:
            for s in bps:
                f.write(s.serialize())
    
def main(args):
    if args[0] == "create":
        cert, key, filename = args[1:4]
        with open(cert) as f:
            cert = X509Certificate.loadPEM(f.read())
        with open(key) as f:
            key = RSA.importKey(f.read())
        passwd = getpass.getpass("Create mint password: ")
        passwd2 = getpass.getpass("Re-enter mint password: ")
        if passwd != passwd2:
            sys.exit("Passwords do not match")
        PrintingPress.CreateBankVault(filename, cert, key, passwd)
    elif args[0] == "mint":
        if len(args) == 1 or args[1].lower() in ["--help", "-h", "help"]:
            sys.exit("mint <amount> <cert> <filename> [<output_dir>]\n"+
                     "  amount can be of the form <amount>:<denomination>")
        amount, cert, filename = args[1:4]
        if len(args) > 4:
            outputDir = args[4]
        else:
            outputDir = None
        with open(cert) as f:
            cert = X509Certificate.loadPEM(f.read())
        if ":" in amount:
            amount, denominations = amount.split(":")
        else:
            denominations = amount
        amount = int(amount)
        denominations = int(denominations)
        passwd = getpass.getpass("Mint password: ")
        total = 0
        serializer = DefaultSerializer(outputDir)
        mint = PrintingPress(cert, passwd, filename)
        while total < amount:
            print "Minting %d of %d bitpoints" % ((total+denominations),amount)
            mint.mintBitPoints(denominations, serializer)
            total += denominations
    elif args[0] == "info":
        filename = args[1]
        if len(args) > 2:
            sampleSize = args[2]
        else:
            sampleSize = None
        bitpoints = []
        with open(filename,"rb") as f:
            bitpoints = BitPoint.deserializeAll(f)
        print "Deserialized",len(bitpoints),"bitpoints"
        if sampleSize == None:
            sample = []
        elif sampleSize.lower() == "all":
            sample = bitpoints
        else:
            start,stop = sampleSize.split(":")
            start = int(start.strip())
            stop = int(stop.strip())
            sample = bitpoints[start:stop]
        for bp in sample:
            print bp
    elif args[0] == "validate":
        filename, issuingCert = args[1:3]
        bitpoints = []
        with open(filename,"rb") as f:
            bitpoints = BitPoint.deserializeAll(f)
        with open(issuingCert) as f:
            cert = X509Certificate.loadPEM(f.read())
        verifier = BitPointVerifier(cert)
        for bp in bitpoints:
            isValid, reason = verifier.verify(bp)
            if isValid:
                print bp.serialNumber(),"is valid"
            else:
                print bp.serialNumber(),"is NOT valid:", reason
        
if __name__ == "__main__":
    main(sys.argv[1:])