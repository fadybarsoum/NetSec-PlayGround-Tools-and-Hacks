'''
Created on Nov 25, 2013

@author: sethjn

This element of the error module contains all "common" errors.
'''

class PlaygroundError(Exception): 
    """
    The PlaygroundError class is the base exception for all errors
    thrown from PLAYGROUND modules and classes.
    """
    pass

class InvalidArgumentException(PlaygroundError): 
    """
    Common error for an unexpected argument to a Playground routine.
    Python has no invalid argument exception.
    """
    pass

class UnimplementedException(PlaygroundError):
    """
    This error is for methods unimplemented in a subclass. However,
    Python already has a NotImplementedException. The future of this class
    is undecided.
    
    Possibility #1: Keep the class, but multiple inherit from NotImplemented
    Possibility #2: Keep this class just the way it is
    Possibility #3: Get rid of this class and replace with NotImplementedException
    
    I like this class better because it allows (requires) the user to specify the
    classObj and methodObj that have the problem. Nevertheless, it isn't good to
    provide a class when there is a builtin class that does the same thing.
    """
    def __init__(self, classObj, methodObj, additionalInfo=None):
        errorString = "Method %s not implemented in class %s." % (str(methodObj), str(classObj))
        if additionalInfo: errorString += " " + additionalInfo
        self.classObj = classObj
        self.methodObj = methodObj
        PlaygroundError.__init__(self, errorString)

class MobileCodeException(PlaygroundError):
    """
    This error is for wrapping all errors produced by mobile code into a
    common class. 
    
    TODO: Maybe the call stack should be included?
    """
    def __init__(self, exception):
        PlaygroundError.__init__(self)
        self.codeException = exception