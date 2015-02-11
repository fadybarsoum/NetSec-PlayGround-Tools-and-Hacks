'''
Created on Apr 22, 2014

@author: sethjn
'''

class MIBAddressMixin(object):
    __mibEnabled = False
    
    def MIBAddressEnabled(self):
        return self.__mibEnabled
    
    def MIBRegistrar(self):
        return self.__registrar
        
    def configureMIBAddress(self, localKey, parent, mibRegistration):
        self.__mibEnabled = True
        self.__parentNode = parent
        self.__registrar = mibRegistration
        self.__localKey = localKey
        self.__myLocalMibs = set([])
    
    def getKey(self):
        if self.__parentNode:
            return self.__parentNode.getKey() + "." + self.__localKey
        return self.__localKey
    
    def disableMIBAddress(self):
        if not self.__mibEnabled: return
        self.__mibEnabled = False
        for dottedKey in self.__myLocalMibs:
            self.__registrar.deregisterMib(dottedKey)
        self.__myLocalMibs = set([])
        
    def getMIBAddress(self):
        if not self.__mibEnabled: return "<NOT MIB ENABLED>"
        if self.__parentNode:
            return self.__parentNode.getMIBAddress() + "." + self.__localKey
        return self.__localKey
        
    def registerLocalMIB(self, listeningKey, callback):
        if not self.__mibEnabled:
            raise Exception("This object not MIB enabled")
        self.__registrar.registerMIB(self.getKey(), listeningKey, callback)
        self.__myLocalMibs.add(self.getKey()+"."+listeningKey)