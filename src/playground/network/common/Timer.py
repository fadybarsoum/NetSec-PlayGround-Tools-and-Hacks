'''
Created on Mar 12, 2014

@author: sethjn
'''
from twisted.internet import reactor

class ITimer(object):
    def run(self, inSeconds):
        pass
    
class ICancelableTimer(ITimer):
    def cancel(self):
        pass

class ReactorOneshotTimer(ICancelableTimer):
    def __init__(self, callback):
        self.__cb = callback
        self.__started = False
        
    def run(self, inSeconds):
        if self.__started:
            raise Exception("One shot timer only runs once")
        self.__started = True
        self.__reactorID = reactor.callLater(inSeconds, self.__cb)
        
    def cancel(self):
        if self.__started:
            self.__reactorID.cancel()
            
OneshotTimer = ReactorOneshotTimer