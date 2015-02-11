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
        self.semester = semester
        self.group = group
        self.individual = individual
        self.index = index
        
    def __validateAddressPart(self, *parts):
        for part in parts:
            if not type(part) == int or part < 0:
                raise InvalidPlaygroundFormat("Address parts must be positive integers")
        
    def getSemesterPair(self):
        year = int(self.semester/10)
        semesterCode = int(self.semester%10)
        return (year, semesterCode)
    
    def toString(self):
        return ".".join(map(str, [self.semester, self.group, self.individual, self.index]))
    
    def __repr__(self):
        return self.toString()
    
    def __str__(self):
        return self.toString()
    
# figure out how IAddress works...
class PlaygroundAddressPair(object):
    def __init__(self, playgroundAddress, port):
        self.host = playgroundAddress
        self.port = port
        
    def toString(self):
        return self.host.toString()+": "+str(self.port)
    
    def __repr__(self):
        return self.toString()
    
    def __str__(self):
        return self.toString()