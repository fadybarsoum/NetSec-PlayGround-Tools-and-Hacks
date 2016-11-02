'''
Created on Nov 2, 2016

@author: sethjn
'''
from playground.network.common.PlaygroundAddress import PlaygroundAddressPair

class PkiPlaygroundAddressPair(PlaygroundAddressPair):
    @classmethod
    def ConvertHostPair(cls, hostPair, certificateChain, privateKey):
        pkiPair = cls(hostPair.host, hostPair.port)
        pkiPair.certificateChain = certificateChain
        pkiPair.privateKey = privateKey
        return pkiPair
    
    @classmethod
    def ConvertPeerPair(cls, peerPair, certificateChain):
        pkiPair = cls(peerPair.host, peerPair.port)
        pkiPair.certificateChain = certificateChain
        return pkiPair
    
    def __init__(self, pAddress, port):
        PlaygroundAddressPair.__init__(self, pAddress, port)
        self.certificateChain = None
        self.privateKey = None