'''
Created on Apr 1, 2014

@author: sethjn
'''

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import INT8, UINT8, STRING, OPTIONAL

class OpenSession(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.OpenSession"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("Login",STRING),
            ("PasswordHash",STRING)
            ]
    
class SessionOpen(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.SessionOpen"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("Account",STRING)
            ]
    
class BalanceRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.BalanceRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8)
            ]
    
class BalanceResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.BalanceResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Balance",INT8)
            ]
    
class TransferRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.TransferRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("DstAccount",STRING),
            ("Amount",UINT8),
            ("Memo",STRING)
            ]
    
class Receipt(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.Receipt"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Receipt", STRING),
            ("ReceiptSignature", STRING)
            ]

class LoginFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.LoginFailure"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("ErrorMessage", STRING)
            ]
    
class RequestFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.RequestFailure"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("ServerNonce", UINT8),
            ("RequestId", UINT8),
            ("ErrorMessage", STRING)]
    
class Close(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.Close"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("ServerNonce", UINT8)]
