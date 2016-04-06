'''
Created on Mar 28, 2016

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition

class Register(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.Register"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING)
            ]

class Challenge(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.Challenge"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING),
            ("HashAlgorithm",STRING),
            ("TestMessage",STRING),
            ("ZerosRequired",UINT2)
            ]

class ChallengeResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.ChallengeResponse"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING),
            ("Response",STRING)
            ]

class RegistrationResult(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.RegistrationResult"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING),
            ("Result",BOOL1)
            ]
    
class EncapsulatedC2C(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.EncapsulatedC2C"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address", STRING),
            ("C2CMessage",STRING)
            ]

class Unregister(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.Unregister"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING)
            ]

class Terminated(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "chaperone.intercept.Terminated"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Address",STRING),
            ("Reason",STRING)
            ]