'''
Created on Mar 14, 2014

@author: sethjn
'''
from twisted.internet.ssl import Certificate
from OpenSSL.crypto import dump_privatekey, FILETYPE_PEM
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder, encoder
from StringIO import StringIO


class X509Certificate(object):
    """
    Unfortunately, there is not a single class that makes getting the 
    information from an X509 certificate easy. This class **attempts**
    to provide the necessary helpers
    """
    
    @classmethod
    def loadPEM(cls, pemData):
        cert = X509Certificate()
        cert.__internalTwistedCert = Certificate.loadPEM(pemData)
        
        asn1cert = decoder.decode(pem.readPemFromFile(StringIO(pemData)), asn1Spec=rfc2459.Certificate())[0]
        cert.__internalAsn1 = asn1cert 
        
        return cert
    
    def __init__(self):
        self.__internalTwistedCert = None
        self.__internalAsn1 = None
        
    def dumpPEM(self):
        if self.__internalTwistedCert:
            return self.__internalTwistedCert.dumpPEM()
        return ""
    
    def getSerialNumber(self):
        if self.__internalTwistedCert:
            return self.__internalTwistedCert.serialNumber()
        return None
    
    def getIssuer(self):
        if self.__internalTwistedCert:
            return self.__internalTwistedCert.getIssuer()
        return None
    
    def getSubject(self):
        if self.__internalTwistedCert:
            return self.__internalTwistedCert.getSubject()
        return None
    
    def getSignatureAlgorithm(self):
        if self.__internalTwistedCert:
            return self.__internalTwistedCert.original.get_signature_algorithm()
        return None
    
    def getPublicKeyBlob(self):
        if self.__internalTwistedCert:
            bitString = self.__internalAsn1[0][6][1]
            bitCount = len(bitString)
            byteCount = bitCount/8 # this should be an even multiple...
            bytes = encoder.encode(bitString)[-byteCount:]
            return bytes
        return None
    
    def getSignatureBlob(self):
        if self.__internalTwistedCert:
            bitString = self.__internalAsn1[2]
            bitCount = len(bitString)
            byteCount = bitCount/8 # this should be an even multiple...
            bytes = encoder.encode(bitString)[-byteCount:]
            return bytes
        return None
    
    def getPemEncodedCertWithoutSignatureBlob(self):
        if self.__internalTwistedCert:
            bitString = self.__internalAsn1[0]
            bitCount = len(bitString)
            byteCount = bitCount/8 # this should be an even multiple...
            bytes = encoder.encode(bitString)[-byteCount:]
            return bytes
        return None