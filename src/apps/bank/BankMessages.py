'''
Created on Apr 1, 2014

@author: sethjn
'''

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import INT8, UINT8, STRING, LIST, OPTIONAL

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
    
class AdminBalanceRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.AdminBalanceRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8)
            ]
    
class AdminBalanceResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.AdminBalanceResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Accounts",LIST(STRING)),
            ("Balances",LIST(INT8))
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
    
class VaultDepositRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.VaultDepositRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("bpData",STRING)
            ]
    
class VaultDepositReceipt(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.VaultDepositReceipt"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Balance",UINT8)
            ]
    
class CreateAccountRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.CreateAccountRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("loginName",STRING),
            ("AccountName", STRING),
            ("pwHash",STRING)
            ]

class ChangePasswordRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.ChangePasswordRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("loginName", STRING),
            ("oldPwHash", STRING),
            ("newPwHash", STRING)
            ]
    
class RequestSucceeded(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.RequestSucceeded"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
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
