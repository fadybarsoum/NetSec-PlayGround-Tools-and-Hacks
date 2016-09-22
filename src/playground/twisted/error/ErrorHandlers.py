'''
Created on Sep 10, 2016

@author: sethjn
'''

from twisted.internet import reactor

from playground.error import ErrorHandler, GetErrorReporter, ErrorLevel

class TwistedShutdownErrorHandler(ErrorHandler):
    @classmethod
    def HandleRootFatalErrors(cls, shutdownDelay=1.0):
        root = GetErrorReporter("")
        root.setHandler(ErrorLevel.LEVEL_FATAL, cls(shutdownDelay=shutdownDelay))
        
    def __init__(self, shutdownDelay=1.0):
        ErrorHandler.__init__(self, "Twisted Shutdown Error Handler")
        self.__shutdownDelay = shutdownDelay
        
    def handle(self, reporter, level, message, exception=None, stackFrame=None):
        try:
            print "Fatal Error. %s" % message
            print "Error reported from: %s" % reporter
            print "Error level: %s" % level
            
            if exception:
                print "Associated exception: " % exception
            if stackFrame:
                import traceback
                traceback.print_stack(stackFrame)
        except Exception, e:
            print "Shutdown report failed: ", e
            
        print "Attempting to shutdown Twisted Reactor."
        
        try:
            reactor.callLater(self.__shutdownDelay, reactor.stop)
        except:
            pass