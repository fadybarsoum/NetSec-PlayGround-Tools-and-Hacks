'''
Created on Apr 2, 2014

@author: sethjn
'''

from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import BOOL1, LIST, UINT8, STRING, OPTIONAL, DEFAULT_VALUE

class OpenSession(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.OpenSession"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce", UINT8),
            ("MobileCodeId", STRING),
            ("Authenticated", BOOL1),
            ("Login",STRING, OPTIONAL),
            ("PasswordHash",STRING, OPTIONAL)
            ]
    
class SessionOpen(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.SessionOpen"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("Cookie",STRING),
            ("ServiceLevel",STRING),
            ("BillingRate",UINT8),
            ("Account",STRING),
            ("ServiceExtras",LIST(STRING))
            ]
    
class SessionOpenFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.SessionOpenFailure"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("ClientNonce",UINT8),
            ("ErrorMessage",STRING)]
    
class SessionRunMobileCode(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.SessionRunMobileCode"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING),
            ("MaxRuntime", UINT8),
            ("ID", UINT8),
            ("Mechanism", STRING),
            ("Strict", BOOL1, DEFAULT_VALUE(False)),
            ("PythonCode", STRING),
            ("ResultKey", STRING, OPTIONAL)]
    
class RunMobileCodeAck(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.RunMobileCodeAck"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING),
            ("MobileCodeAccepted", BOOL1),
            ("Message",STRING,OPTIONAL)]
    
class CheckMobileCodeResult(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.CheckMobileCodeResult"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING)]
    
class EncryptedMobileCodeResult(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.mobilecodeservice.EncryptedMobileCodeResult"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Cookie",STRING),
            ("RunTime",UINT8),
            ("RunMobileCodeHash",STRING),
            ("Success", BOOL1),
            ("EncryptedMobileCodeResultPacket",STRING)]
    
class PurchaseDecryptionKey(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.mobilecodeservice.PurchaseDecryptionKey"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Cookie",STRING),
            ("Receipt", STRING),
            ("ReceiptSignature", STRING)]
    
class ResultDecryptionKey(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.mobilecodeservice.ResultDecryptionKey"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Cookie",STRING),
            ("key",STRING),
            ("iv",STRING)]
    
class RerequestDecryptionKey(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.mobilecodeservice.RerequestDecryptionKey"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Cookie",STRING)]

class RunMobileCodeFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.RunMobileCodeFailure"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING),
            ("ErrorMessage",STRING)]
    
class AcquireDecryptionKeyFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.AcquireDecryptionKeyFailure"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING),
            ("ErrorMessage",STRING)]
    
class GeneralFailure(MessageDefinition):
    PLAYGROUND_IDENTIFIER="apps.mobilecodeservice.GeneralFailure"
    MESSAGE_VERSION="1.0"
    BODY = [
            ("Cookie",STRING),
            ("ErrorMessage",STRING)]