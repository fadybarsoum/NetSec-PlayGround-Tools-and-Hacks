'''
Created on Mar 24, 2014

@author: sethjn
'''


class Padding(object):
    def padData(self, s): return s
    def unpadData(self, s): return s
    
class Pkcs7Padding(Padding):
    def __init__(self, blockSize):
        self.blockSize = blockSize
        
    def padData(self, data):
        padSize = self.blockSize-(len(data)%self.blockSize)
        if padSize == 0: padSize = self.blockSize
        pad = chr(padSize) * padSize
        return data + pad
    
    def unpadData(self, data):
        padSize = ord(data[-1])
        return data[:-padSize]