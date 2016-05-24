'''
Created on Nov 27, 2013

@author: sethjn
'''

class ClientConnectionState(object):
    '''
    classdocs
    '''


    def __init__(self, code, codeString):
        self.__code = code
        self.__codeString = codeString
        
    def __eq__(self, otherState):
        if not isinstance(otherState, ClientConnectionState): return False
        return otherState.__code == self.__code
    
    def __int__(self):
        return self.__code
    
    def __str__(self):
        return self.__codeString