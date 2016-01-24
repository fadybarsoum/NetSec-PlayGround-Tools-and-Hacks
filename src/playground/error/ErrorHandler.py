'''
Created on Nov 22, 2013

@author: sethjn
'''

import logging
import inspect
import sys

from twisted.internet import reactor

class ErrorHandler(object):
    '''
    Interface class for all error handling mechanisms. Any
    error handling mechanisms must have the capacity to handle
    error messages and error exceptions.
    
    Error handling can take many forms. The default mechanism
    simply logs to the global logger (LoggingErrorHandler). However,
    other mechanisms can be inserted that scan errors for specific
    problems and take appropriate action.
    '''

    def __init__(self):
        '''
        Constructor
        '''
        pass
    
    def handleError(self, message, reporter=None, stackHack=0):
        pass
    
    def handleException(self, e, reporter=None, stackHack=0, fatal=0):
        pass
    
class LoggingErrorHandler(ErrorHandler):
    """
    The LoggingErrorHandler is the default error handler for PLAYGROUND.
    When an error is logged (either as a message or an exception), it is 
    simply logged using the global python logger.
    
    If the logger has no handlers, error messages are simply dropped. Exceptions
    are re-raised if there are no handlers or the exceptions are marked as 
    fatal.
    """
    def __init__(self, logger):
        self.logger = logger
        
    def __loggerReady(self):
        if not self.logger: return False
        if not self.logger.handlers: return False
        return True
        
    def handleError(self, message, reporter=None, stackHack=0):
        callerframerecord = inspect.stack()[2+stackHack]    
                                            # 0 represents this function
                                            # 1 represents line at reporter
                                            # 2 represents the caller unless we were called from handleException
                                            # 3 represents the caller if there's an intermediate call from handleException
                                            # If other layers get inbetween the call to reportError, they should
                                            #   increase the stackHack
        frame = callerframerecord[0]
        info = inspect.getframeinfo(frame)
        objId = reporter and str(id(reporter)) or "(None)"
        errMsg = "[Error at %s::%s::%d (obj id: %s)] %s" % (info.filename, info.function, info.lineno, objId, message)
        if self.__loggerReady():
            self.logger.error(errMsg)
        
    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        if fatal:
            reactor.callLater(.1, reactor.stop)
        if self.__loggerReady():
            try:
                str(e).decode('ascii','strict')
            except UnicodeDecodeError, u_e:
                e = Exception("Could not report original error because it has encoding problems: %s" % str(str(e).decode("ascii","ignore")))
            if reporter: self.handleError("Exception: %s" % str(e), reporter=reporter, stackHack=(stackHack+1))
            self.logger.exception(e)
            if fatal:
                raise Exception, "Logging Error Handler received fatal exception, re-raising:\n%s"%e, sys.exc_info()[2]
        else:
            raise Exception, "Logging Error Handler not ready, re-raising exception:\n%s"%e, sys.exc_info()[2]
        
        
class ErrorHandlingMixin(object):
    """
    The ErrorHandlingMixin is a class that can be easily inherited
    by a Python class to allow simple in-class error handling for non-
    abortive problems. The error messages and/or exceptions are simply
    reported to the API and the API handles the details.
    
    A global error handler is set that is the default handler. However,
    Individual classes can have specific error handlers set if necessary.
    
    So, for example, a mobile-code handling class might want a more
    investigative error handler while the default logging handler is
    appropriate for everything else.
    
    The mixin only reports to one handler: the class handler if it exists,
    and the global handler otherwise. If the local object should report to
    both the local and global error handler, the object-specific handler
    should chain to the global handler.
    """
    g_ErrorHandler = LoggingErrorHandler(logging.getLogger(""))
    
    @staticmethod
    def SetGlobalErrorHandler(handler):
        ErrorHandlingMixin.g_ErrorHandler = handler
    
    def setLocalErrorHandler(self, handler):
        """
        Set the object to use a local handler rather than the global
        one. If handler is none, this object is reset to use the global
        handler.
        """
        if handler:
            self.g_ErrorHandler = handler
        else:
            self.g_ErrorHandler = ErrorHandlingMixin.g_ErrorHandler
        
    def reportError(self, message, explicitReporter=None, stackHack=0):
        reporter = explicitReporter and explicitReporter or self
        self.g_ErrorHandler.handleError(message, reporter=reporter, stackHack=stackHack)
        
    def reportException(self, e, explicitReporter=None, stackHack=0, fatal=False):
        reporter = explicitReporter and explicitReporter or self
        self.g_ErrorHandler.handleException(e, reporter=reporter, stackHack=stackHack, fatal=fatal)