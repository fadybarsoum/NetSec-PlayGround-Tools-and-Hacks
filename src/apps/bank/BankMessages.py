'''
Created on Apr 1, 2014

@author: sethjn
'''

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import BOOL1, INT8, UINT8, STRING, LIST, OPTIONAL

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
    
class ListAccounts(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.ListAccounts"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("User",STRING,OPTIONAL)
            ]
    
class ListAccountsResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.ListAccountsResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Accounts",LIST(STRING))
            ]
    
class CurrentAccount(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.CurrentAccount"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8)
            ]
    
class CurrentAccountResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.CurrentAccountResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Account",STRING)
            ]
    
class SwitchAccount(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.bank.SwitchAccount"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
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
    
class DepositRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.DepositRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("bpData",STRING)
            ]
    
class WithdrawalRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.WithdrawlRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Amount",INT8)
            ]
    
class WithdrawalResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.WithdrawalResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("bpData",STRING)
            ]

class SetUserPasswordRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.SetUserPasswordRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("loginName", STRING),
            ("oldPwHash", STRING),
            ("newPwHash", STRING)
            ]
    
class CreateAccountRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.CreateAccountRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("AccountName", STRING),
            ]
    
class CurAccessRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.CurAccessRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("UserName", STRING, OPTIONAL),
            ("AccountName", STRING, OPTIONAL),
            ]
    
class CurAccessResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.CurAccessResponse"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("Accounts", LIST(STRING)),
            ("Access", LIST(STRING))
            ]
    
class ChangeAccessRequest(MessageDefinition):
    PLAYGROUND_IDENTIFIER= "apps.bank.ChangeAccessRequest"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ServerNonce",UINT8),
            ("RequestId",UINT8),
            ("UserName", STRING),
            ("Account", STRING, OPTIONAL),
            ("AccessString", STRING)
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
    
class PermissionDenied(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.PermissionDenied"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("ServerNonce", UINT8),
            ("RequestId", UINT8),
            ("ErrorMessage", STRING)]
    
class ServerError(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.ServerError"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ErrorMessage", STRING)]
    
class Close(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.bank.Close"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("ServerNonce", UINT8)]
