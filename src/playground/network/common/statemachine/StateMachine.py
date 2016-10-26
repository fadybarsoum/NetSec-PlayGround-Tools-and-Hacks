'''
Created on Sep 8, 2016

@author: sethjn
'''

import logging

from playground.error.Common import PlaygroundError

logger = logging.getLogger(__name__)

class StateMachine(object):
    
    STATE_DEFAULT_ERROR_STATE = "STATE MACHINE DEFAULT ERROR STATE"
    
    SIGNAL_UNKNOWN_TRANSITION = "STATE MACHINE: Unknown Transition"
    SIGNAL_UNKNOWN_STATE      = "STATE MACHINE: Unknown State"
    SIGNAL_ERROR              = "STATE MACHINE: Error Reported"
    
    def __init__(self, name):
        self.__name = name
        self.__curState = None
        self.__errState = None
        self.__states = {}
        self.__stateHistory = []
        
    def defaultErrorHandler(self, signal, data):
        raise StateMachineError(signal, data)
        
    def addState(self, name, *transitions, **callbacks):
        if name in self.__states:
            raise DuplicateStateException()
        
        # prepare a transitions mapping for this state
        stateTransitions = {}
        for signal, state in transitions:
            if stateTransitions.has_key(signal):
                raise DuplicateSignalException(name, signal)
            stateTransitions[signal] = state
            
        # get enter and exit callbacks
        onEnterCallback = callbacks.get("onEnter",None)
        onExitCallback  = callbacks.get("onExit", None)
        
        # save the new state
        self.__states[name] = (onEnterCallback, onExitCallback, stateTransitions)
        
    def start(self, startingState, errorState=None):
        if self.__curState: raise StateMachineAlreadyStarted()
        
        logging.debug("Starting state machine %s in state %s" % (self.__name, startingState))
        
        self.__curState = startingState
        self.__errorState = errorState
        if not errorState:
            self.addState(self.STATE_DEFAULT_ERROR_STATE, onEnter=self.defaultErrorHandler)
            self.__errorState = self.STATE_DEFAULT_ERROR_STATE
        self.__stateHistory = [(None, startingState)]
        
    def signal(self, signal, data):
        if not self.__curState: raise StateMachineNotStarted()
        
        logging.debug("State machine %s in state %s received signal %s (%s)" % (self.__name, self.__curState, signal, data))
        
        _, onExit, transitions = self.__states[self.__curState]
        logging.debug("State machine %s existing current state %s" % (self.__name, self.__curState))
        onExit and onExit(signal, data)
            
        if signal == self.SIGNAL_ERROR or not transitions.has_key(signal):
            nextState = self.__errorState
            if signal != self.SIGNAL_ERROR:
                data = (self.__curState, signal, data)
                signal = self.SIGNAL_UNKNOWN_TRANSITION
                logging.debug("State machine %s has no such transition. Moving to error state %s" % (self.__name, nextState))
            #nextState.enter(self.SIGNAL_UNKNOWN_TRANSITION, (self.__curState, signal, data))
        else:
            nextState = transitions[signal]
            if not self.__states.has_key(nextState):
                data = (self.__curState, signal, nextState, data)
                nextState = self.__errorState
                signal = self.SIGNAL_UNKNOWN_STATE
                logging.debug("State machine %s has no such next state. Moving to error state %s" % (self.__name, nextState))
                #nextState.enter(self.SIGNAL_UNKNOWN_STATE, (self.__curState, signal, data))
            else:
                #onEnter, _, _ = self.__states[nextState]
                logging.debug("State machine %s entering state %s" % (self.__name, nextState))
        onEnter, _, _ = self.__states[nextState]
        self.__curState = nextState
        self.__stateHistory.append((signal, self.__curState))
        
        ### IMPORTANT ###
        # onEnter MUST be called last because it could change state.
        onEnter and onEnter(signal, data)
        
    def started(self): 
        return self.__curState != None
    
    def inErrorState(self): 
        return self.__curState == self.__errorState
    
    def previousSignalAndState(self, offset=1):
        if offset > len(self.__stateHistory):
            return (None, None)
        return self.__stateHistory[-offset]
    
    def inTerminalState(self): 
        if not self.started(): return False
        _, _, transitions = self.__states[self.__curState]
        for nextState in transitions.values():
            if nextState != self.__curState:
                return False
        return True
    
    def currentState(self):
        return self.__curState
        
class DuplicateStateException(PlaygroundError):pass
class DuplicateSignalException(PlaygroundError):
    def __init__(self, state, signal):
        PlaygroundError.__init__(self, "Duplicate signal %s for state %s" % (signal, state))
class StateMachineError(PlaygroundError):
    def __init__(self, signal, data):
        PlaygroundError.__init__(self, "State machine entered error state on signal %s (%s)." % (signal, str(data)))
        self.signal = signal
        self.data = data
class StateMachineNotStarted(PlaygroundError):pass
class StateMachineAlreadyStarted(PlaygroundError):pass