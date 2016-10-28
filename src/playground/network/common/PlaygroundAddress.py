'''
Created on Nov 25, 2013

@author: sethjn
'''

from Error import InvalidPlaygroundAddressString, InvalidPlaygroundFormat
from twisted.internet.interfaces import IAddress

class PlaygroundAddress(object):
    @staticmethod
    def FromString(addressString):
        if type(addressString) != str:
            raise InvalidPlaygroundAddressString("Address string not of type string")
        
        parts = addressString.split(".")
        if len(parts) != 4:
            raise InvalidPlaygroundAddressString("Address string not of form a.b.c.d")
        
        try:
            parts = map(int, parts)
        except:
            raise InvalidPlaygroundAddressString("Address parts must be integers")
        
        return PlaygroundAddress(parts[0], parts[1], parts[2], parts[3])
    
    def __init__(self, semester, group, individual, index):
        self.__validateAddressPart(semester, group, individual, index)
        self.__semester = semester
        self.__group = group
        self.__individual = individual
        self.__index = index
        self.__addressString = ".".join(map(str, [semester, group, individual, index]))
        
    def __validateAddressPart(self, *parts):
        for part in parts:
            if not type(part) == int or part < 0:
                raise InvalidPlaygroundFormat("Address parts must be positive integers")
    
    def __eq__(self, other):
        if isinstance(other, PlaygroundAddress):
            return (self.__semester == other.__semester and 
                    self.__group == other.__group and
                    self.__individual == other.__individual and
                    self.__index == other.__index)
        elif isinstance(other, str):
            return self.__addressString == other
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __hash__(self):
        return self.__addressString.__hash__()
    
    def __getitem__(self, i):
        if i < 0 or i > 3:
            raise IndexError("Playground Addresses have 4 parts")
        if i == 0: return self.__semester
        if i == 1: return self.__group
        if i == 2: return self.__individual
        if i == 3: return self.__index
    
    def semester(self): return self.__semester
    def group(self): return self.__group
    def individual(self): return self.__individual
    def index(self): return self.__index
        
    def getSemesterPair(self):
        year = int(self.__semester/10)
        semesterCode = int(self.__semester%10)
        return (year, semesterCode)
    
    def toString(self):
        return self.__addressString
    
    def __repr__(self):
        return self.toString()
    
    def __str__(self):
        return self.toString()
    
# figure out how IAddress works...
class PlaygroundAddressPair(object):
    def __init__(self, playgroundAddress, port):
        if not isinstance(playgroundAddress, PlaygroundAddress):
            playgroundAddress = PlaygroundAddress.FromString(playgroundAddress)
        if port < 0:
            raise Exception("Port must be positive")
        self.host = playgroundAddress
        self.port = port
        self.__stringValue = self.host.toString() + ": "+str(self.port)
        self.__hashValue = self.__stringValue.__hash__()

        
    def __eq__(self, other):
        if isinstance(other, PlaygroundAddressPair):
            return self.host == other.host and self.port == other.port
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __hash__(self):
        return self.__hashValue
        
    def toString(self):
        return self.__stringValue
    
    def __repr__(self):
        return self.toString()
    
    def __str__(self):
        return self.toString()