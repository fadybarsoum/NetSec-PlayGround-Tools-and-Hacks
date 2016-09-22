'''
Created on Sep 12, 2016

@author: sethjn
'''

from playground.error import PlaygroundError
from twisted.python.failure import Failure

class SimpleFailureException(PlaygroundError): pass

class SimpleFailure(Failure):
    def __init__(self, msg):
        Failure.__init__(self, SimpleFailureException(msg))