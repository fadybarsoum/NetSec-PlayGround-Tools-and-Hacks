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
    def __init__(self, callback, *cbArgs, **cbKargs):
        self.__cb = callback
        self.__cbArgs = cbArgs
        self.__cbKargs = cbKargs
        self.__started = False
        
    def run(self, inSeconds):
        if self.__started:
            raise Exception("One shot timer only runs once")
        self.__started = True
        self.__reactorID = reactor.callLater(inSeconds, self.__cb, *self.__cbArgs, **self.__cbKargs)
        
    def cancel(self):
        if self.__started:
            self.__reactorID.cancel()
            
OneshotTimer = ReactorOneshotTimer
callLater = lambda delay, f, *args, **kargs: reactor.callLater(delay, f, *args, **kargs)