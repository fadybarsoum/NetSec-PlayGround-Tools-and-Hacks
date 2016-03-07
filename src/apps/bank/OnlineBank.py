'''
Created on Mar 27, 2014

@author: sethjn
'''

import playground, random, sys, os, getpass, pickle, shelve, base64, time, traceback
from BankMessages import OpenSession, SessionOpen, BalanceRequest, TransferRequest, Close
from BankMessages import BalanceResponse, Receipt, LoginFailure, RequestFailure
from BankMessages import DepositRequest, CreateAccountRequest, SetUserPasswordRequest, AdminBalanceRequest
from BankMessages import WithdrawalRequest, WithdrawalResponse, RequestSucceeded, AdminBalanceResponse
from BankMessages import ListAccounts, ListUsers, ListAccountsResponse, CurrentAccount, CurrentAccountResponse
from BankMessages import SwitchAccount, PermissionDenied, CreateAccountRequest
from BankMessages import ChangeAccessRequest, CurAccessRequest, CurAccessResponse
from BankMessages import ServerError, ListUsersResponse
from BankMessages import LedgerRequest, LedgerResponse
from playground.network.message import MessageData
from playground.network.common import Timer
from CipherUtil import SHA, X509Certificate, RSA, PKCS1_v1_5
from Exchange import BitPoint

from playground.playgroundlog import logging, LoggingContext
from playground.config import LoadOptions
from playground.error import ErrorHandler
from PlaygroundNode import PlaygroundNode, StandaloneTask
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol
logger = logging.getLogger(__file__)

from BankCore import Ledger, LedgerLine
from contextlib import closing

from twisted.internet import defer
from utils.ui import CLIShell, stdio

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

PasswordHash = lambda pw: SHA.new(pw).digest()

BANK_FIXED_PLAYGROUND_PORT = 700

"""
Protocol
[c] -> [ob (server)] :: C sends openSession(login_name, password)
[c] <- [ob (server)] :: ob either closes connection or sends "OK"
[c] -> [ob (server)] :: C sends request
[c] <- [ob (server)] :: ob sends response + receipt
"""

class DummyFile(object):
    def close(self): pass
InvalidPwFile = DummyFile()

class BankServerProtocol(playground.network.common.SimpleMessageHandlingProtocol,
                         ErrorHandler):
    MIB_CURRENT_STATE = "CurrentState"
    
    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    
    ADMIN_PW_ACCOUNT = "__admin__"
    ADMIN_ACCOUNTS = ["VAULT"]
    def __init__(self, factory, addr, pwDb, bank):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.setLocalErrorHandler(self)
        self.__pwDb = pwDb
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0,
                           "AccountName":None,
                           "LoginName":None}
        self.__state = self.STATE_UNINIT
        self.__bank = bank
        self.registerMessageHandler(OpenSession, self.__handleOpenSession)
        self.registerMessageHandler(ListAccounts, self.__handleListAccounts)
        self.registerMessageHandler(ListUsers, self.__handleListUsers)
        self.registerMessageHandler(CurrentAccount, self.__handleCurrentAccount)
        self.registerMessageHandler(SwitchAccount, self.__handleSwitchAccount)
        self.registerMessageHandler(BalanceRequest, self.__handleBalanceRequest)
        self.registerMessageHandler(TransferRequest, self.__handleTransferRequest)
        self.registerMessageHandler(DepositRequest, self.__handleDeposit)
        self.registerMessageHandler(WithdrawalRequest, self.__handleWithdrawal)
        self.registerMessageHandler(AdminBalanceRequest, self.__handleAdminBalanceRequest)
        self.registerMessageHandler(CreateAccountRequest, self.__handleCreateAccount)
        self.registerMessageHandler(SetUserPasswordRequest, self.__handleSetUserPassword)
        self.registerMessageHandler(ChangeAccessRequest, self.__handleChangeAccess)
        self.registerMessageHandler(CurAccessRequest, self.__handleCurAccess)
        self.registerMessageHandler(LedgerRequest, self.__handleLedgerRequest)
        self.registerMessageHandler(Close, self.__handleClose)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_CURRENT_STATE, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_CURRENT_STATE):
            resp = []
            resp.append("STATE: %s" % self.__state)
            for k in self.__connData.keys():
                resp.append("%s: %s" % (str(k), str(self.__connData[k])))
            return resp
        return []
    
    def handleError(self, message, reporter=None, stackHack=0):
        # handleError handles error messages reported in the framework
        # this is different from __error, which is designed to handle
        # errors in the protocol
        self.g_ErrorHandler.handleError(message, reporter, stackHack)
    
    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        # handle if it's reported by us, or by one of our methods
        localHandler = (reporter == self or (hasattr(reporter,"im_self") and reporter.im_self==self))
        if not localHandler:
            self.g_ErrorHandler.handleException(e, reporter, stackHack, fatal)
            return
        
        # this is an exception handler for exceptions raised by the framework
        errMsg = "Error reported in handler %s\n" % str(reporter)
        errMsg += traceback.format_exc()
        # we will treat exceptions as fatal. Try to shut down
        try:
            networkErrorMessage = MessageData.GetMessageBuilder(ServerError)
            networkErrorMessage["ErrorMessage"].setData(errMsg)
            self.transport.writeMessage(networkErrorMessage)
            self.handleError(errMsg)
        except Exception, e:
            self.handleError("Failed to transmit message: " + errMsg)
            self.handleError(traceback.format_exc())
        try:
            self.callLater(0, self.transport.loseConnection)
        except:
            pass
    
    def __error(self, errMsg, requestId = 0, fatal=True):
        if self.__state == self.STATE_ERROR:
            return None
        if self.__state == self.STATE_UNINIT:
            response = MessageData.GetMessageBuilder(LoginFailure)
            response["ClientNonce"].setData(self.__connData["ClientNonce"])
        else:
            response = MessageData.GetMessageBuilder(RequestFailure)
            response["ClientNonce"].setData(self.__connData["ClientNonce"])
            response["ServerNonce"].setData(self.__connData["ServerNonce"])
            response["RequestId"].setData(requestId)
        response["ErrorMessage"].setData(errMsg)
        self.transport.writeMessage(response)
        if fatal:
            self.__state = self.STATE_ERROR
            self.callLater(1,self.transport.loseConnection)
        return None
    
    def __sendPermissionDenied(self, errMsg, requestId=0):
        if self.__state == self.STATE_ERROR:
            return None
        response = MessageData.GetMessageBuilder(PermissionDenied)
        response["ClientNonce"].setData(self.__connData.get("ClientNonce",0))
        response["ServerNonce"].setData(self.__connData.get("ServerNonce",0))
        response["RequestId"].setData(requestId)
        response["ErrorMessage"].setData(errMsg)
        self.transport.writeMessage(response)
        return None
    
    def __getSessionAccount(self, msgObj):
        if self.__state != self.STATE_OPEN:
            self.__error("Session not logged-in", msgObj.RequestId)
            return None, None
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
        account = self.__connData["AccountName"]
        userName = self.__connData["LoginName"]
        if account and self.__pwDb.hasAccount(account):
            access = self.__pwDb.currentAccess(userName, account)
        else: access = ''
        return (account, access)
    
    def __validateAdminPeerConnection(self):
        peer = self.transport.getPeer()
        if not peer: return False
        return True
    
    def __getAdminPermissions(self, requestId=0, fatal=True):
        if not self.__validateAdminPeerConnection():
            if fatal: self.__error("Unauthorized connection location. Will be logged", requestId)
            return None
        userName = self.__connData.get("LoginName",None)
        if not userName:
            if fatal: self.__error("Attempt for admin without logging in. Will be logged", requestId)
            return None
        if not self.__pwDb.hasUser(userName):
            if fatal: self.__error("Attempt for admin from not user. Will be logged", requestId)
            return None
        access = self.__pwDb.currentAccess(userName, self.ADMIN_PW_ACCOUNT)
        if not access:
            if fatal: self.__error("Attempt for admin without any admin permissions. Will be logged", requestId)
            return None
        return access
    
    """def __getAdminAccount(self, msgObj):
        if not self.__validateAdminPeerConnection():
            self.__error("Unauthorized connection location. Will be logged", msgObj.RequestId)
            return None
        account = self.__getSessionAccount(msgObj)
        if account != self.ADMIN_PW_ACCOUNT:
            self.__error("Unauthorized account", msgObj.RequestId)
            return None
        return account"""
    
    def __createResponse(self, msgObj, responseType):
        response = MessageData.GetMessageBuilder(responseType)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(msgObj.ServerNonce)
        return response
    
    def __handleOpenSession(self, protocol, msg):
        # permissions: None
        if self.__state != self.STATE_UNINIT:
            return self.__error("Session not uninitialized. State %s" % self.__state)
        msgObj = msg.data()
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        passwordHash = self.__pwDb.currentUserPassword(msgObj.Login)
        if not passwordHash == msgObj.PasswordHash:
            return self.__error("Invalid Login")
        """if not  accountName in self.__bank.getAccounts():
            return self.__error("Invalid Login")"""
        self.__connData["ServerNonce"] = RANDOM_u64()
        self.__connData["AccountName"] = ""
        self.__connData["LoginName"] = msgObj.Login
        self.__state = self.STATE_OPEN
        response = MessageData.GetMessageBuilder(SessionOpen)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(self.__connData["ServerNonce"])
        response["Account"].setData("")
        self.transport.writeMessage(response)
        
    def __handleCurrentAccount(self, protocol, msg):
        # permissions: None
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if account == None: # require
            return 
        response = self.__createResponse(msgObj, CurrentAccountResponse)
        response["Account"].setData(account)
        response["RequestId"].setData(msgObj.RequestId)
        self.transport.writeMessage(response)
        
    def __handleListAccounts(self, protocol, msg):
        # permissions: regular - None, for a specific user, Admin(B)
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if account == None:
            return
        if hasattr(msgObj,"User"):
            adminAccessData = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccessData == None:
                # error already reported.
                return None
            if "B" not in adminAccessData:
                return self.__sendPermissionDenied("Requires 'B' access", msgObj.RequestId)
            userName = msgObj.User
        else:
            userName = self.__connData["LoginName"]
        accountAccessData = self.__pwDb.currentAccess(userName)
        accountNames = accountAccessData.keys()
        response = self.__createResponse(msgObj, ListAccountsResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Accounts"].setData(accountNames)
        self.transport.writeMessage(response)
        
    def __handleListUsers(self, protocol, msg):
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        users = []
        if account == None:
            return
        if not hasattr(msgObj,"Account"):
            # use current account, unless account is not set, in which case
            # it has to be administrator
            accountToList = account
        else:
            accountToList = msgObj.Account
            
        if accountToList == '':
            adminAccessData = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccessData == None:
                # error already reported
                return None
            accountToList = None
        else:
            accountToListAccess = self.__pwDb.currentAccess(self.__connData["LoginName"], accountToList)
            if 'a' not in accountToListAccess:
                return self.__sendPermissionDenied("Requires 'a' access", msgObj.RequestId)

        for name in self.__pwDb.iterateUsers(accountToList):
            users.append(name)
        response = self.__createResponse(msgObj, ListUsersResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Users"].setData(users)
        self.transport.writeMessage(response)    
        
    def __handleSwitchAccount(self, protocol, msg):
        # permissions: some permissions on account, if an admin account, 'S'
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if account == None:
            return
        desiredAccount = msgObj.Account
        
        result = True
        if desiredAccount.startswith("__"):
            result = False
        elif desiredAccount in self.ADMIN_ACCOUNTS:
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess == None:
                return
            if 'S' not in adminAccess:
                return self.__sendPermissionDenied("Requires 'S' permissions", msgObj.RequestId)
        elif desiredAccount:
            access = self.__pwDb.currentAccess(self.__connData["LoginName"], desiredAccount)
            if not access: result = False
        if result:
            self.__connData["AccountName"] = desiredAccount
        if result:
            response = self.__createResponse(msgObj, RequestSucceeded)
        else:
            response = self.__createResponse(msgObj, RequestFailure)
            response["ErrorMessage"].setData("Could not switch accounts")
        response["RequestId"].setData(msgObj.RequestId)
        self.transport.writeMessage(response)    
    
    def __handleBalanceRequest(self, protocol, msg):
        # permissions: regular(b)
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Account must be selected")
            self.transport.writeMessage(response)
            return None
        if 'b' not in access:
            return self.__sendPermissionDenied("No Permission to check Balances", 
                                               msgObj.RequestId)
        balance = self.__bank.getBalance(account)
        response = self.__createResponse(msgObj, BalanceResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Balance"].setData(balance)
        self.transport.writeMessage(response)
        
    def __handleAdminBalanceRequest(self, protocol, msg):
        # permissions: Admin(B)
        msgObj = msg.data()
        adminAccess = self.__getAdminPermissions(msgObj.RequestId)
        if adminAccess == None:
            return
        if "B" not in adminAccess:
            return self.__sendPermissionDenied("Requires 'B' access", msgObj.RequestId)
        accountList = self.__bank.getAccounts()
        balancesList = []
        for account in accountList:
            balancesList.append(self.__bank.getBalance(account))
        response = self.__createResponse(msgObj, AdminBalanceResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Accounts"].setData(accountList)
        response["Balances"].setData(balancesList)
        self.transport.writeMessage(response)
        
    def __handleTransferRequest(self, protocol, msg):
        # permissions: regular(t)
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Account must be selected")
            self.transport.writeMessage(response)
        if not 't' in access:
            return self.__sendPermissionDenied("Requires 't' access", msgObj.RequestId)
        dstAccount = msgObj.DstAccount
        if not dstAccount in self.__bank.getAccounts():
            return self.__error("Invalid destination account %s" % dstAccount, msgObj.RequestId,
                                fatal=False)
        amount = msgObj.Amount
        if amount < 0: 
            return self.__error("Invalid (negative) amount %d" % amount, msgObj.RequestId,
                                fatal=False)
        if amount > self.__bank.getBalance(account):
            return self.__error("Insufficient Funds to pay %d" % amount, msgObj.RequestId,
                                fatal=False)
        result = self.__bank.transfer(account,dstAccount, amount, msgObj.Memo)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        # Assume single threaded. The last transaction will still be the one we care about
        result = self.__bank.generateReceipt(dstAccount)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        receipt, signature = result.value()
        response = self.__createResponse(msgObj, Receipt)
        response["RequestId"].setData(msgObj.RequestId)
        response["Receipt"].setData(receipt)
        response["ReceiptSignature"].setData(signature)
        self.transport.writeMessage(response)
        
    def __handleDeposit(self, protocol, msg):
        # requires: regular(d)
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Account must be selected")
            self.transport.writeMessage(response)
        if 'd' not in access:
            return self.__sendPermissionDenied("Requires 'd' access", msgObj.RequestId)
        bps = []
        bpData = msgObj.bpData
        while bpData:
            newBitPoint, offset = BitPoint.deserialize(bpData)
            bpData = bpData[offset:]
            bps.append(newBitPoint)
        result = self.__bank.depositCash(account,bps)
        if not result.succeeded():
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData(result.msg())
        else:
            result = self.__bank.generateReceipt(account)
            if not result.succeeded():
                response = self.__createResponse(msgObj, RequestFailure)
                response["RequestId"].setData(msgObj.RequestId)
                response["ErrorMessage"].setData(result.msg())
            else:
                receipt, signature = result.value()
                response = self.__createResponse(msgObj, Receipt)
                response["RequestId"].setData(msgObj.RequestId)
                response["Receipt"].setData(receipt)
                response["ReceiptSignature"].setData(signature)
        self.transport.writeMessage(response)
        
    def __handleWithdrawal(self, protocol, msg):
        # requires: regular(d)
        msgObj = msg.data()
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Account must be selected")
            self.transport.writeMessage(response)
        if 'd' not in access:
            return self.__sendPermissionDenied("Requires 'd' access", msgObj.RequestId)
        result = self.__bank.withdrawCash(account,msgObj.Amount)
        if not result.succeeded():
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData(result.msg())
        else:
            bitPoints = result.value()
            bpData = ""
            for bitPoint in bitPoints:
                bpData += bitPoint.serialize()
            response = self.__createResponse(msgObj, WithdrawalResponse)
            response["RequestId"].setData(msgObj.RequestId)
            response["bpData"].setData(bpData)
        self.transport.writeMessage(response)
        
    def __isValidUsername(self, name):
        for letter in name:
            if not letter.isalnum() and not letter == "_":
                return False
        return True
        
    def __handleSetUserPassword(self, protocol, msg):
        # requires that the user is changing his own password, or Admin('A') access
        msgObj = msg.data()
        userName = msgObj.loginName
        newUser = msgObj.NewUser
        logger.info("Received change password request. Current user %s, user to change [%s]" % 
                    (self.__connData["LoginName"], userName))
        errorResponse = self.__createResponse(msgObj, RequestFailure)
        errorResponse["RequestId"].setData(msgObj.RequestId)
        okResponse = self.__createResponse(msgObj, RequestSucceeded)
        okResponse["RequestId"].setData(msgObj.RequestId)
        if not userName:
            userName = self.__connData["LoginName"]
        
        if (newUser or userName != self.__connData["LoginName"]):
            # if this is a new user, must be admin because couldn't login
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess == None:
                return
            if "A" not in adminAccess:
                return self.__sendPermissionDenied("Requires 'A' access", msgObj.RequestId)
            
            if newUser and self.__pwDb.hasUser(userName):
                errorResponse["ErrorMessage"].setData("User %s already exists" % userName)
                self.transport.writeMessage(errorResponse)
                return
            elif newUser and not self.__isValidUsername(userName):
                errorResponse["ErrorMessage"].setData("Username invalid. Only letters, numbers, and underscores.")
                self.transport.writeMessage(errorResponse)
                return
            elif not newUser and not self.__pwDb.hasUser(userName):
                errorResponse["ErrorMessage"].setData("User %s does not exist" % userName)
                self.transport.writeMessage(errorResponse)
                return
        elif msgObj.oldPwHash == '':
            # Cannot allow this.
            errorResponse["ErrorMessage"].setData("No password hash specified")
            self.transport.writeMessage(errorResponse)
            return
        elif self.__pwDb.currentUserPassword(userName) != msgObj.oldPwHash:
                errorResponse["ErrorMessage"].setData("Invalid Password")
                self.transport.writeMessage(errorResponse)
                return
            
        pwHash = msgObj.newPwHash
        self.__pwDb.createUser(userName, pwHash, modify=True)
        self.__pwDb.sync()
        self.transport.writeMessage(okResponse)
        
    def __handleCreateAccount(self, protocol, msg):
        # requires Admin(A)
        msgObj = msg.data()
        adminAccess = self.__getAdminPermissions(msgObj.RequestId)
        if adminAccess == None:
            return
        if "A" not in adminAccess:
            return self.__sendPermissionDenied("Requires 'A' access", msgObj.RequestId)
        
        response = self.__createResponse(msgObj, RequestSucceeded)
        newAccountName = msgObj.AccountName
        if self.__pwDb.hasAccount(newAccountName):
            response = self.__createResponse(msgObj, RequestFailure)
            response["ErrorMessage"].setData("That account already exists")
        result = self.__bank.createAccount(newAccountName)
        if result.succeeded():
            self.__pwDb.createAccount(newAccountName)
            self.__pwDb.sync()
        else:
            response = self.__createResponse(msgObj, RequestFailure)
            response["ErrorMessage"].setData("Could not create account. Internal error")
        response["RequestId"].setData(msgObj.RequestId)
        self.transport.writeMessage(response)
        
    def __handleCurAccess(self, protocol, msg):
        msgObj = msg.data()
        userName = self.__connData["LoginName"]
        if hasattr(msgObj, "UserName"):
            checkUserName = msgObj.UserName
        else:
            checkUserName = userName
        if hasattr(msgObj, "AccountName"):
            accountName = msgObj.AccountName
        else: accountName = None
        
        if userName != checkUserName and not accountName:
            # requires admin access to get general permissions for other user
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess == None:
                return
            if 'A' not in adminAccess:
                return self.__sendPermissionDenied("Requires admin access 'A'", 
                                                   msgObj.RequestId)
        elif userName != checkUserName:
            # requires 'a' to check other user's permissions on an account
            access = self.__pwDb.currentAccess(userName, accountName) 
            if 'a' not in access:
                return self.__sendPermissionDenied("Requires access 'a'", 
                                                   msgObj.RequestId)
        
        accounts = []
        accountsAccess = []
        if accountName:
            accounts.append(accountName)
            accountsAccess.append(self.__pwDb.currentAccess(checkUserName, accountName))
        else:
            accessMulti = self.__pwDb.currentAccess(checkUserName)
            for accountName, accountAccessString in accessMulti.items():
                accounts.append(accountName)
                accountsAccess.append(accountAccessString)
        response = self.__createResponse(msgObj, CurAccessResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Accounts"].setData(accounts)
        response["Access"].setData(accountsAccess)
        self.transport.writeMessage(response)
        
    def __handleChangeAccess(self, protocol, msg):
        # if no account is specified, it must be for the current account with 'a' access
        # if an account is specified, it must belong to the current user with 'a' access
        # if an account is specified that doesn't belong to the current user, Admin('A')
        msgObj = msg.data()
        userName = self.__connData["LoginName"]
        changeUserName = msgObj.UserName
        account, access = self.__getSessionAccount(msgObj)
        if account == None:
            return None # this was an actual error
        if not account and not hasattr(msgObj, "Account"):
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Account must be selected or specified")
            self.transport.writeMessage(response)
            return
        if hasattr(msgObj, "Account"):
            account = msgObj.Account
            access = self.__pwDb.currentAccess(userName, account)
        if not access:
            # doesn't own the account. Check admin 
            # 
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess == None:
                return
            if 'A' not in adminAccess:
                return self.__sendPermissionDenied("Requires admin access or regular 'a'", 
                                                   msgObj.RequestId)
        elif 'a' not in access:
            # do a non-fatal admin access check
            adminAccess = self.__getAdminPermissions(msgObj.RequestId, fatal=False)
            if not adminAccess or 'A' not in adminAccess:
                return self.__sendPermissionDenied("Requires 'a' access or admin", msgObj.RequestId)
        
        if not self.__pwDb.isValidAccessSpec(msgObj.AccessString, account):
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData("Invalid access string %s" % msgObj.AccessString)
            self.transport.writeMessage(response)
            return
        self.__pwDb.configureAccess(changeUserName, account, msgObj.AccessString)
        self.__pwDb.sync()
        response = self.__createResponse(msgObj, RequestSucceeded)
        response["RequestId"].setData(msgObj.RequestId)
        self.transport.writeMessage(response)

    def __handleLedgerRequest(self, protocol, msg):
        msgObj = msg.data()
        #account, access = self.__getSessionAccount(msgObj)
        userName = self.__connData["LoginName"]
        accountToGet = hasattr(msgObj,"Account") and msgObj.Account or None
        if not accountToGet:
            # No account specified. Get the entire bank ledger.
            # this is administrative access only.
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess == None:
                return
            if 'A' not in adminAccess:
                return self.__sendPermissionDenied("Requires admin access", 
                                                   msgObj.RequestId)
            # return all lines
            lFilter = lambda lline: True
        else:
            accountToGetAccess = self.__pwDb.currentAccess(userName, accountToGet) 
            if 'a' not in accountToGetAccess:
                # don't kill the connection if we don't have admin. Just tell them.
                adminAccess = self.__getAdminPermissions(msgObj.RequestId, fatal=False)
                if adminAccess == None or 'A' not in adminAccess:
                    return self.__sendPermissionDenied("Requires admin access or regular 'a'", 
                                                       msgObj.RequestId)
            lFilter = lambda lline: lline.partOfTransaction(accountToGet)
        lineNums = self.__bank.searchLedger(lFilter)
        lines = []
        for lineNum in lineNums:
            line = self.__bank.getLedgerLine(lineNum)
            lines.append(line.toHumanReadableString(accountToGet))
        response = self.__createResponse(msgObj, LedgerResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Lines"].setData(lines)
        self.transport.writeMessage(response)
            
    def __handleClose(self, protocol, msg):
        msgObj = msg.data()
        if self.__state != self.STATE_OPEN:
            return # silently ignore close messages on unopen connections
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            return # silently ignore close messages on wrong client nonce
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            return # silently ignore close messages on wrong server nonce
        self.__state = self.STATE_UNINIT
        if self.transport: self.transport.loseConnection()
        
        
class BankClientProtocol(playground.network.common.SimpleMessageHandlingProtocol, playground.network.common.StackingProtocolMixin):
    STATE_UNINIT = "Uninitialized"
    STATE_WAIT_FOR_LOGIN = "Waiting for login to server"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    def __init__(self, factory, addr, cert, loginName, password):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__loginName = loginName
        self.__passwordHash = PasswordHash(password)
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0}
        self.__deferred = {"CONNECTION":defer.Deferred(),
                           "TERMINATION":defer.Deferred()}
        self.__state = self.STATE_UNINIT
        self.__account = None
        rsaKey = RSA.importKey(cert.getPublicKeyBlob())
        self.__verifier = PKCS1_v1_5.new(rsaKey)
        self.registerMessageHandler(SessionOpen, self.__handleSessionOpen)
        self.registerMessageHandler(BalanceResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(Receipt, self.__handleStdSessionResponse)
        self.registerMessageHandler(CurrentAccountResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(CurAccessResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(WithdrawalResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(LoginFailure, self.__handleLoginFailure)
        self.registerMessageHandler(RequestFailure, self.__handleRequestFailure)
        self.registerMessageHandler(AdminBalanceResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(RequestSucceeded, self.__handleStdSessionResponse)
        self.registerMessageHandler(PermissionDenied, self.__handleRequestFailure)
        self.registerMessageHandler(ListAccountsResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(ListUsersResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(LedgerResponse, self.__handleStdSessionResponse)
        self.registerMessageHandler(ServerError, self.__handleServerError)
        
    def __errorCallbackWrapper(self, e, d):
        self.__error(e)
        d.errback(e)
        
    def __error(self, errMsg):
        if self.__state != self.STATE_ERROR:
            self.__state = self.STATE_ERROR
            self.reportError(errMsg)
            self.transport.loseConnection()
            
    def __reportExceptionAsDeferred(self, e):
        d = defer.Deferred()
        # we need a call later so the client code has enough time to set the errback handler
        self.callLater(.1,lambda: self.__errorCallbackWrapper(e, d))
        return d
    
    def __nextRequestData(self):
        rId = RANDOM_u64()
        d = defer.Deferred()
        self.__deferred[rId] = d
        return rId, d
    
    def verify(self, msg, sig):
        return self.__verifier.verify(SHA.new(msg), sig)
    
    def state(self): return self.__state
    
    def account(self): return self.__account
    
    def connectionMade(self):
        d = self.__deferred.get("CONNECTION", None)
        if d:
            del self.__deferred["CONNECTION"]
            d.callback(True)
        
    def connectionLost(self, reason):
        d = self.__deferred.get("CONNECTION", None)
        if d:
            del self.__deferred["CONNECTION"]
            d.errback(Exception("Connection lost before connection made: " + str(reason)))
        d = self.__deferred.get("TERMINATION", None)
        if d:
            del self.__deferred["TERMINATION"]
            d.callback(True)
            
    def waitForTermination(self):
        d = self.__deferred["TERMINATION"]
        return d
    
    def waitForConnection(self):
        d =  self.__deferred.get("CONNECTION",None)
        if not d:
            # we've already executed. For this to run nearly immediately
            d = defer.Deferred()
            self.callLater(.1, lambda: d.callback(True))
        return d
        
    def loginToServer(self):
        if self.__deferred.has_key("CONNECTION"):
            # we haven't connected yet!
            raise Exception("Can't login. Connection not yet made.")
        if self.__state != self.STATE_UNINIT:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        openMsg = MessageData.GetMessageBuilder(OpenSession)
        self.__connData["ClientNonce"] = RANDOM_u64()
        openMsg["ClientNonce"].setData(self.__connData["ClientNonce"])
        openMsg["Login"].setData(self.__loginName)
        openMsg["PasswordHash"].setData(self.__passwordHash)
        self.__state = self.STATE_WAIT_FOR_LOGIN
        d = defer.Deferred()
        self.__deferred["LOGIN"] = d
        self.transport.writeMessage(openMsg)
        return d
        
    def __handleSessionOpen(self, protocol, msg):
        if self.__state != self.STATE_WAIT_FOR_LOGIN:
            return self.__error("Unexpected Session Open Message. State is (%s)" % self.__state)
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error("Invalid internal state. No LOGIN deferred")
        del self.__deferred["LOGIN"]
        
        msgObj = msg.data()
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return d.errback("Invalid Connection Data")
        self.__connData["ServerNonce"] = msgObj.ServerNonce
        self.__account = msgObj.Account
        self.__state = self.STATE_OPEN
        d.callback(True)
        
    def __handleLoginFailure(self, protocol, msg):
        msgObj = msg.data()
        if self.__state != self.STATE_WAIT_FOR_LOGIN:
            return self.__error("Error logging in: %s" % msgObj.ErrorMessage)
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error("Invalid internal state. No LOGIN deferred")
        del self.__deferred["LOGIN"]
        
        msgObj = msg.data()
        d.errback(Exception(msgObj.ErrorMessage))
        
    def __createStdSessionRequest(self, requestType, noRequestId=False):
        
        msg = MessageData.GetMessageBuilder(requestType)
        msg["ClientNonce"].setData(self.__connData["ClientNonce"])
        msg["ServerNonce"].setData(self.__connData["ServerNonce"])
        if not noRequestId:
            requestId, d = self.__nextRequestData()
            msg["RequestId"].setData(requestId)
        else: d = None
        return msg, d
    
    def __validateStdSessionResponse(self, msgObj):
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            d.errback(Exception("Invalid internal state. No deferred for request %d" % msgObj.RequestId))
            return None
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            d.errback(Exception("Invalid Connection Data (ClientNonce)"))
            return None
        if msgObj.ServerNonce != self.__connData["ServerNonce"]:
            d.errback(Exception("Invalid Connection Data (ServerNonce"))
            return None
        del self.__deferred[msgObj.RequestId]
        return d
    
    # list response, swith account response, balance response
    # receipt response,  
    def __handleStdSessionResponse(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback(msgObj)
        
    def __handleServerError(self, protocol, msg):
        msgObj = msg.data()
        self.reportError("Server Error: " + msgObj.ErrorMessage + "\nWill terminate")
        self.callLater(1,self.transport.loseConnection)
    
    def listAccounts(self, userName=None):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        listMsg, d = self.__createStdSessionRequest(ListAccounts)
        if userName:
            listMsg["User"].setData(userName)
        self.transport.writeMessage(listMsg)
        return d
    
    def listUsers(self, account=None):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        listMsg, d = self.__createStdSessionRequest(ListUsers)
        if account:
            listMsg["Account"].setData(account)
        self.transport.writeMessage(listMsg)
        return d
    
    def switchAccount(self, accountName):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        switchMsg, d = self.__createStdSessionRequest(SwitchAccount)
        switchMsg["Account"].setData(accountName)
        self.transport.writeMessage(switchMsg)
        return d
    
    def currentAccount(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        currentMsg, d = self.__createStdSessionRequest(CurrentAccount)
        self.transport.writeMessage(currentMsg)
        return d
    
    def currentAccess(self, userName=None, accountName=None):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        curAccessMsg, d = self.__createStdSessionRequest(CurAccessRequest)
        if userName:
            curAccessMsg["UserName"].setData(userName)
        if accountName:
            curAccessMsg["AccountName"].setData(accountName)
        self.transport.writeMessage(curAccessMsg)
        return d
        
    def getBalance(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        balanceMsg, d = self.__createStdSessionRequest(BalanceRequest)
        self.transport.writeMessage(balanceMsg)
        return d
        
    def transfer(self, dstAccount, amount, memo):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        transferMsg, d = self.__createStdSessionRequest(TransferRequest)
        transferMsg["DstAccount"].setData(dstAccount)
        transferMsg["Amount"].setData(amount)
        transferMsg["Memo"].setData(memo)
        self.transport.writeMessage(transferMsg)
        return d
    
    def close(self):
        if self.__state != self.STATE_OPEN:
            return # silently ignore closing a non-open connection
        self.__state = self.STATE_UNINIT
        if self.transport:
            closeMsg, d = self.__createStdSessionRequest(Close, noRequestId=True)
            self.transport.writeMessage(closeMsg)
            self.callLater(.1, self.transport.loseConnection)
        
    def __handleRequestFailure(self, protocol, msg):
        msgObj = msg.data()
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Failure. Should be state %s but state %s. Failure Message: %s" % (self.STATE_OPEN, self.__state, msgObj.ErrorMessage))
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            return self.__error("Invalid internal state. No deferred for request %d. Error msg: %s" % (msgObj.RequestId, msgObj.ErrorMessage))
        del self.__deferred[msgObj.RequestId]
        
        d.errback(Exception(msgObj.ErrorMessage))
        
    def adminGetBalances(self):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        balanceMsg, d = self.__createStdSessionRequest(AdminBalanceRequest)
        self.transport.writeMessage(balanceMsg)
        return d
        
    def deposit(self, serializedBp):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        depositMsg, d = self.__createStdSessionRequest(DepositRequest)
        depositMsg["bpData"].setData(serializedBp)
        self.transport.writeMessage(depositMsg)
        return d
    
    def withdraw(self, amount):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        withdrawalMsg, d = self.__createStdSessionRequest(WithdrawalRequest)
        withdrawalMsg["Amount"].setData(amount)
        self.transport.writeMessage(withdrawalMsg)
        return d
        
    def adminCreateUser(self, loginName, password):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        createMsg, d = self.__createStdSessionRequest(SetUserPasswordRequest)
        createMsg["loginName"].setData(loginName)
        createMsg["oldPwHash"].setData('')
        createMsg["newPwHash"].setData(PasswordHash(password))
        createMsg["NewUser"].setData(True)
        self.transport.writeMessage(createMsg)
        return d
    
    def adminCreateAccount(self, accountName):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        createMsg, d = self.__createStdSessionRequest(CreateAccountRequest)
        createMsg["AccountName"].setData(accountName)
        self.transport.writeMessage(createMsg)
        return d
    
    def changePassword(self, newPassword, oldPassword=None, loginName=None):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        changeMsg, d = self.__createStdSessionRequest(SetUserPasswordRequest)
        if loginName:
            changeMsg["loginName"].setData(loginName)
        else: changeMsg["loginName"].setData("")
        if oldPassword:
            changeMsg["oldPwHash"].setData(PasswordHash(oldPassword))
        else: changeMsg["oldPwHash"].setData("")
        changeMsg["newPwHash"].setData(PasswordHash(newPassword))
        changeMsg["NewUser"].setData(False)
        self.transport.writeMessage(changeMsg)
        return d
    
    def changeAccess(self, username, access, account=None):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        changeMsg, d = self.__createStdSessionRequest(ChangeAccessRequest)
        changeMsg["UserName"].setData(username)
        changeMsg["AccessString"].setData(access)
        if account:
            changeMsg["Account"].setData(account)
        self.transport.writeMessage(changeMsg)
        return d
    
    def exportLedger(self, account):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        ledgerMsg, d = self.__createStdSessionRequest(LedgerRequest)
        if account:
            ledgerMsg["Account"].setData(account)
        self.transport.writeMessage(ledgerMsg)
        return d
    
class BankClientSimpleCommand(object):
    def __init__(self):
        pass
    
    def __failed(self, final_d, protocol, errMsg):
        protocol.close()
        final_d.errback(Exception(errMsg))
    
    def __cmdSucceeded(self, final_d, protocol, result ):
        protocol.close()
        final_d.callback(result)
    
    def __switchAccountSucceeded(self, cmdState):
        protocol, account, cmd, args, kargs, final_d = cmdState
        d = cmd(protocol, *args, **kargs)
        d.addCallback(lambda result: self.__cmdSucceeded(final_d, protocol, result))
        d.addErrback(lambda failure: self.__failed(final_d, protocol,
                                                   "Could not execute bank command. Reason: %s" % str(failure)))
    
    def __loginSucceeded(self, cmdState):
        protocol, account, cmd, args, kargs, final_d = cmdState
        if account:
            d = protocol.switchAccount(account)
            d.addCallback(lambda result: self.__switchAccountSucceeded(cmdState))
            d.addErrback(lambda failure: self.__failed(final_d, protocol,  
                                                       "Could not switch to account %s. Reason: %s" % (account, str(failure))))
        else:
            d = cmd(protocol, *args, **kargs)
            d.addCallback(lambda result: self.__cmdSucceeded(final_d, result))
            d.addErrback(lambda failure: self.__failed(final_d, protocol, 
                                                       "Could not execute bank command. Reason: %s" % str(failure)))
    
    def __call__(self, protocol, account, cmd, *args, **kargs):
        final_d = defer.Deferred()
        cmdState = [protocol, account, cmd, args, kargs, final_d]
        d = protocol.loginToServer()
        d.addCallback(lambda result: self.__loginSucceeded(cmdState))
        d.addErrback(lambda failure: self.__failed(final_d, protocol, 
                                                   "Could not login to bank. Reason: %s" % str(failure)))
        return final_d
        
class PlaygroundOnlineBank(playground.network.client.ClientApplicationServer.ClientApplicationServer):
    MIB_BALANCES = "BankBalances"

    def __init__(self, passwordFile, bank):
        #super(PlaygroundOnlineBank, self).__init__(self)
        self.__bank = bank
        self.__passwordData = PasswordData(passwordFile)
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_BALANCES, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_BALANCES):
            balances = []
            for account in self.__bank.getAccounts():
                balances.append("%s: %s (b^)" % (account, str(self.__bank.getBalance(account))))
            return balances
        return []
        
    def configureMIBAddress(self, *args, **kargs):
        playground.network.client.ClientApplicationServer.ClientApplicationServer.configureMIBAddress(self, *args, **kargs)
        self.__loadMibs()
    
    def buildProtocol(self, addr):
        p = BankServerProtocol(self, addr, self.__passwordData, self.__bank)
        return p
    

    
class PlaygroundOnlineBankClient(playground.network.client.ClientApplicationServer.ClientApplicationClient):
    def __init__(self, cert, loginName, pw):
        #super(PlaygroundOnlineBankClientTest, self).__init__(self)
        self._cert = cert
        self._loginName = loginName
        self._pw = pw
        
    def buildProtocol(self, addr):
        return BankClientProtocol(self, addr, self._cert, self._loginName, self._pw)

class AdminBankCLIClient(CLIShell, ErrorHandler):
    NON_ADMIN_PROMPT = "Bank Client >"
    ADMIN_PROMPT = "Bank Client [Admin] >"

    def __init__(self, clientBase, bankClientFactory, bankAddr, connectionType):
        CLIShell.__init__(self, prompt=self.NON_ADMIN_PROMPT)
        self.__d = None
        self.__backlog = []
        self.__bankClient = None
        self.__bankAddr = bankAddr
        self.__bankClientFactory = bankClientFactory
        self.__connectionType = connectionType
        self.__clientBase = clientBase
        self.__connected = False
        self.__admin = False
        self.__quitCalled = False
        
    def __loginToServer(self, success):
        if not success:
            return self.__noLogin(Exception("Failed to login"))
        self.__d = self.__bankClient.loginToServer()
        self.__d.addCallback(self.__login)
        self.__d.addErrback(self.__noLogin)
        
    def __login(self, success):
        self.__connected = True
        self.reset()
        self.__loadCommands()
        self.transport.write("Logged in to bank\n")
        
    def __noLogin(self, e):
        self.transport.write("Failed to login to bank: %s\n" % str(e))
        self.transport.write("Quiting")
        Timer.callLater(.1, self.quit)
        
    def __listAccountsResponse(self, msgObj):
        responseTxt = "  CurrentAccounts\n"
        for account in msgObj.Accounts:
            responseTxt += "    "+account+"\n"
        self.transport.write(responseTxt+"\n")
        self.reset()
        
    def __listUsersResponse(self, msgObj):
        responseTxt = "  CurrentUsers\n"
        for user in msgObj.Users:
            responseTxt += "    "+user+"\n"
        self.transport.write(responseTxt+"\n")
        self.reset()
        
    def __currentAccount(self, msgObj):
        if msgObj.Account:
            self.transport.write("  You are currently logged into account " + msgObj.Account)
        else:
            self.transport.write("  You are not logged into an account")
        self.transport.write("\n")
        self.reset()
        
    def __switchAccount(self, msgObj):
        self.transport.write("  Successfully logged into account.")
        self.transport.write("\n")
        self.reset()
    
    def __balances(self, msgObj):
        accounts, balances = msgObj.Accounts, msgObj.Balances
        if len(accounts) != len(balances):
            self.transport.write("Inernal Error. Got %d accounts but %d balances\n" % (len(accounts), len(balances)))
            return
        responseTxt = ""
        responseTxt += "  Current Balances:\n"
        for i in range(len(accounts)):
            responseTxt += "    %s: %d\n" % (accounts[i],balances[i])
        self.transport.write(responseTxt + "\n")
        self.reset()
        
    def __curAccess(self, msgObj):
        accounts, access = msgObj.Accounts, msgObj.Access
        if len(accounts) != len(access):
            self.transport.write("  Inernal Error. Got %d accounts but %d access\n" % (len(accounts), len(access)))
            return
        responseTxt = "  Current Access:\n"
        for i in range(len(accounts)):
            responseTxt += "    %s: %s\n" % (accounts[i], access[i])
        self.transport.write(responseTxt + "\n")
        self.reset()               
        
    def __accountBalanceResponse(self, msgObj):
        result = msgObj.Balance
        self.transport.write("Current account balance: %d\n" % result)
        self.reset()
        
    def __withdrawl(self, msgObj):
        result = msgObj.bpData
        filename = "bp"+str(time.time())
        open(filename,"wb").write(result)
        self.transport.write("  Withdrew bitpoints into file %s" % filename)
        self.transport.write("\n")
        self.reset()
        
    def __receipt(self, msgObj):
        receiptFile = "bank_receipt."+str(time.time())
        sigFile = receiptFile + ".signature"
        self.transport.write("Receipt and signature received. Saving as %s and %s\n" % (receiptFile, sigFile))
        with open(receiptFile, "wb") as f:
            f.write(msgObj.Receipt)
        with open(sigFile, "wb") as f:
            f.write(msgObj.ReceiptSignature)
        if not self.__bankClient.verify(msgObj.Receipt, msgObj.ReceiptSignature):
            responseTxt = "Received a receipt with mismatching signature\n"
            responseTxt += "Please report this to the bank administrator\n"
            responseTxt += "Quitting\n"
            self.transport.write(responseTxt)
            self.quit()
        else:
            self.transport.write("Valid receipt received. Transaction complete.")
            self.transport.write("\n")
            self.reset()
        
    def __createAccount(self, result):
        self.transport.write("  Account created.")
        self.transport.write("\n")
        self.reset()
        
    def __createUser(self, result):
        self.transport.write("  User created.")
        self.transport.write("\n")
        self.reset()
        
    def __changePassword(self, result):
        self.transport.write("  Password changed successfully.")
        self.transport.write("\n")
        self.reset()
        
    def __changeAccess(self, result):
        self.transport.write("  Access changed successfully.")
        self.transport.write("\n")
        self.reset()
        
    def __exportLedgerResponse(self, msgObj):
        filename = "ledger_%f" % time.time()
        self.transport.write("  Exported ledger downloaded.\n")
        self.transport.write("  Saving to file %s\n" % filename)
        with open(filename,"w+") as f:
            for line in msgObj.Lines:
                f.write(line+"\n")
        self.transport.write("  Done.\n")
        self.reset()
        
    def __failed(self, e):
        self.transport.write("  Operation failed. Reason: %s\n" % str(e))
        self.reset()
        
    def handleError(self, message, reporter=None, stackHack=0):
        self.transport.write("Client Error: %s\n" % message)
        
    def quit(self, writer=None):
        self.__bankClient.close()
        if self.__quitCalled: return
        self.__quitCalled = True
        self.transport.write("Exiting bank client.\n")
        Timer.callLater(0, self.transport.loseConnection)
        Timer.callLater(.1, self.__clientBase.disconnectFromPlaygroundServer)
    
    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        errMsg = traceback.format_exc()
        self.handleError(errMsg)
        if fatal:
            self.quit()
        
    def reset(self):
        self.__d = None

    def connectionMade(self):
        try:
            srcPort, self.__bankClient = self.__clientBase.connect(self.__bankClientFactory, 
                                                          self.__bankAddr,
                                                          BANK_FIXED_PLAYGROUND_PORT,
                                                          self.__connectionType)
                                                          
            self.__bankClient.setLocalErrorHandler(self)
            self.__d = self.__bankClient.waitForConnection()#self.__bankClient.loginToServer()
            self.__bankClient.waitForTermination().addCallback(lambda *args: self.quit())
            self.__d.addCallback(self.__loginToServer)
            self.__d.addErrback(self.__noLogin)
            self.transport.write("Logging in to bank. Waiting for server\n")
        except Exception, e:
            print e
            self.transport.loseConnection()

    def lineReceived(self, line):
        if self.__d:
            if line.strip().lower() == "__break__":
                self.__d = None
                self.transport.write("Operation cancelled on client. Unknown server state.\n")
            elif not self.__connected:
                self.transport.write("Still waiting for bank to login. Retry command later.\n")
            else:
                self.transport.write("Cannot execute [%s]. Waiting for previous command to complete\n"%line)
                self.transport.write("Type: __break__ to return to shell (undefined behavior).\n")
            return (False, None)
        try:
            self.lineReceivedImpl(line)
            return (True, self.__d)
        except Exception, e:
            self.handleException(e)
            return (False, None)
            
    def __toggleAdmin(self, writer):
        self.__admin = not self.__admin
        if self.__admin:
            self.prompt = self.ADMIN_PROMPT
        else: self.prompt = self.NON_ADMIN_PROMPT
        
    def __accessCurrent(self, writer, arg1=None, arg2=None):
        if not arg1 and not arg2:
            user = None
            account = None
        elif arg1 and not arg2:
            if self.__admin:
                # in admin mode, one arg is the user (get all account access)
                user = arg1
                account = None
            elif not self.__admin:
                # in non-admin, one arg is the account (get my access in account)
                user = None
                account = arg1
        else:
            user = arg1
            account = arg2

                    
        self.__d = self.__bankClient.currentAccess(user, account)
        self.__d.addCallback(self.__curAccess)
        self.__d.addErrback(self.__failed)
        
    def __accessSet(self, writer, user, access, account=None):
        if access == "*":
            access = PasswordData.ACCOUNT_PRIVILEGES
        if access == "__none__":
            access = ''
        self.__d = self.__bankClient.changeAccess(user, access, account)
        self.__d.addCallback(self.__changeAccess)
        self.__d.addErrback(self.__failed)
        
    def __listAccounts(self, writer, user=None):
        if user and not self.__admin:
            writer("Not in admin mode\n")
            return
        self.__d = self.__bankClient.listAccounts(user)
        self.__d.addCallback(self.__listAccountsResponse)
        self.__d.addErrback(self.__failed)
        
    def __listUsers(self, writer, account=None):
        self.__d = self.__bankClient.listUsers(account)
        self.__d.addCallback(self.__listUsersResponse)
        self.__d.addErrback(self.__failed)
        
    def __accountCurrent(self, writer):
        self.__d = self.__bankClient.currentAccount()
        self.__d.addCallback(self.__currentAccount)
        self.__d.addErrback(self.__failed)
        
    def __accountSwitch(self, writer, switchToAccount):
        if switchToAccount == "__none__":
            switchToAccount = ''
        self.__d = self.__bankClient.switchAccount(switchToAccount)
        self.__d.addCallback(self.__switchAccount)
        self.__d.addErrback(self.__failed)
        
    def __accountBalance(self, writer, all=False):
        if not all:
            self.__d = self.__bankClient.getBalance()
            self.__d.addCallback(self.__accountBalanceResponse)
            self.__d.addErrback(self.__failed)
        else:
            if not self.__admin:
                writer("Not in admin mode\n")
                return
            self.__d = self.__bankClient.adminGetBalances()
            self.__d.addCallback(self.__balances)
            self.__d.addErrback(self.__failed)
            
    def __accountDeposit(self, writer, bpFile):
        if not os.path.exists(bpFile):
            writer("NO such file\n")
            return
        with open(bpFile) as f:
            bpData = f.read()
            self.__d = self.__bankClient.deposit(bpData)
            self.__d.addCallback(self.__receipt)
            self.__d.addErrback(self.__failed)
            
    def __accountWithdrawArgsHandler(self, writer, amountStr):
        try:
            amount = int(amountStr)
        except:
            writer("Not a valid amount %s\n" % amountStr)
            return None
        if amount < 1:
            writer("Amount cannot be less than 1\n")
            return None
        return (amount,)
            
    def __accountWithdraw(self, writer, amount):
        self.__d = self.__bankClient.withdraw(amount)
        self.__d.addCallback(self.__withdrawl)
        self.__d.addErrback(self.__failed)
        
    def __accountTransferArgsHandler(self, writer, dst, amountStr, memo):
        try:
            amount = int(amountStr)
        except:
            writer("Invalid amount %s" % amountStr)
            return None
        if amount < 1:
            writer("Amount cannot be less than 1\n")
            return None
        return (dst, amount, memo)
        
    def __accountTransfer(self, writer, dstAcct, amount, memo):
        self.__d = self.__bankClient.transfer(dstAcct, amount, memo)
        self.__d.addCallback(self.__receipt)
        self.__d.addErrback(self.__failed)
        
    def __accountCreate(self, writer, accountName):
        if not self.__admin:
            writer("Not in admin mode\n")
            return
        self.__d = self.__bankClient.adminCreateAccount(accountName)
        self.__d.addCallback(self.__createAccount)
        self.__d.addErrback(self.__failed)
        
    def __userCreate(self, writer, userName):
        if not self.__admin:
            writer("Not in admin mode\n")
            return
        password = getpass.getpass("Enter account password for [%s]: " % userName)
        password2 = getpass.getpass("Re-enter account password for [%s]: " % userName)
        if password != password2:
            self.transport.write("Mismatching passwords\n")
            return
        self.__d = self.__bankClient.adminCreateUser(userName, password)
        self.__d.addCallback(self.__createAccount)
        self.__d.addErrback(self.__failed)
        
    def __userPasswd(self, writer, userName=None):
        if not userName:
            oldPassword = getpass.getpass("Enter current account password: ")
        else:
            if not self.__admin:
                writer("Not in admin mode\n")
                return 
            writer("Login name specified as [%s]. This requires Admin access\n"%userName)
            oldPassword = None
        password2 = getpass.getpass("Enter new account password: ")
        password3 = getpass.getpass("Re-enter new account password: ")
        if password2 != password3:
            writer("Mismatching passwords\n")
            return
        self.__d = self.__bankClient.changePassword(password2, loginName=userName, oldPassword=oldPassword)
        self.__d.addCallback(self.__changePassword)
        self.__d.addErrback(self.__failed)
        
    def __exportLedger(self, writer, account=None):
        if not account and not self.__admin:
            writer("Not in admin mode.\n")
            return
        self.__d = self.__bankClient.exportLedger(account)
        self.__d.addCallback(self.__exportLedgerResponse)
        self.__d.addErrback(self.__failed)
        
    def __loadCommands(self):
        adminCommandHandler = CLIShell.CommandHandler("admin","Toggle admin mode",self.__toggleAdmin)
        accessCommandHandler = CLIShell.CommandHandler("access","Configure access right",
                                                       mode=CLIShell.CommandHandler.SUBCMD_MODE)
        accessCurrentHandler = CLIShell.CommandHandler("current",
                                                        "Get the current access for a user/account",
                                                        mode=CLIShell.CommandHandler.STANDARD_MODE,
                                                        defaultCb=self.__accessCurrent)
        accessCurrentHandler.configure(1, self.__accessCurrent, usage="[user/account]",
                                       helpTxt="Get the access of the user or account depending on admin mode.")
        accessCurrentHandler.configure(2, self.__accessCurrent, usage="[user] [account]",
                                       helpTxt="Get the access of the user/account pair")
        accessCommandHandler.configureSubcommand(accessCurrentHandler)
        accessSetHandler = CLIShell.CommandHandler("set",helpTxt="Set access for a user",
                                                   mode=CLIShell.CommandHandler.STANDARD_MODE)
        accessSetHandler.configure(2, self.__accessSet, usage="[username] [access]",
                                   helpTxt="Set the access for username on current account")
        accessSetHandler.configure(3, self.__accessSet, usage="[username] [access] [account]",
                                   helpTxt="Set the access for username on account")
        accessCommandHandler.configureSubcommand(accessSetHandler)
        accountHandler = CLIShell.CommandHandler("account",helpTxt="Commands related to an account",
                                                 mode=CLIShell.CommandHandler.SUBCMD_MODE)
        accountListHandler = CLIShell.CommandHandler("list",helpTxt="List accounts for current user",
                                                     defaultCb=self.__listAccounts,
                                                     mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountListHandler.configure(1, self.__listAccounts, helpTxt="Admin: List accounts for a specific user",
                                    usage="[user]")
        accountHandler.configureSubcommand(accountListHandler)
        accountCurrentHandler = CLIShell.CommandHandler("current",helpTxt="Get the current account name",
                                                        defaultCb=self.__accountCurrent)
        accountHandler.configureSubcommand(accountCurrentHandler)
        accountSwitchHandler = CLIShell.CommandHandler("switch",helpTxt="Switch the current account",
                                                       mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountSwitchHandler.configure(1, self.__accountSwitch, "Switch to [account name]",
                                       usage="[account name]")
        accountHandler.configureSubcommand(accountSwitchHandler)
        accountBalanceHandler = CLIShell.CommandHandler("balance",helpTxt="Get the current account balance",
                                                        defaultCb=self.__accountBalance,
                                                        mode=CLIShell.CommandHandler.SUBCMD_MODE)
        accountBalanceAllHandler = CLIShell.CommandHandler("all",helpTxt="Admin: Get ALL balances",
                                                           defaultCb=lambda writer: self.__accountBalance(writer, True),
                                                           mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountBalanceHandler.configureSubcommand(accountBalanceAllHandler)
        accountHandler.configureSubcommand(accountBalanceHandler)
        accountDepositHandler = CLIShell.CommandHandler("deposit",helpTxt="Deposit bitpoints",
                                                        mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountDepositHandler.configure(1, self.__accountDeposit, "Deposit a file of bitpoints",
                                        usage="[bp file]")
        accountHandler.configureSubcommand(accountDepositHandler)
        accountWithdrawHandler = CLIShell.CommandHandler("withdraw",helpTxt="Withdraw bitpoints",
                                                        mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountWithdrawHandler.configure(1, self.__accountWithdraw, "Withdraw an amount of bitpoints",
                                         argHandler=self.__accountWithdrawArgsHandler,
                                        usage="[amount]")
        accountHandler.configureSubcommand(accountWithdrawHandler)
        accountTransferHandler = CLIShell.CommandHandler("transfer",helpTxt="Transfer funds to another account",
                                                         mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountTransferHandler.configure(3, self.__accountTransfer, "Transfer amount to dst with memo",
                                         argHandler=self.__accountTransferArgsHandler,
                                         usage="[dst] [amount] [memo]")
        accountHandler.configureSubcommand(accountTransferHandler)
        accountCreateHandler = CLIShell.CommandHandler("create",helpTxt="Admin: create new account",
                                                       mode=CLIShell.CommandHandler.STANDARD_MODE)
        accountCreateHandler.configure(1, self.__accountCreate, "Create account named [account name]",
                                       usage="[account name]")
        accountHandler.configureSubcommand(accountCreateHandler)
        userHandler = CLIShell.CommandHandler("user",helpTxt="Manage user(s)",
                                              mode = CLIShell.CommandHandler.SUBCMD_MODE)
        userListHandler = CLIShell.CommandHandler("list",helpTxt="List all users for the current account",
                                                  defaultCb=self.__listUsers,
                                                  mode=CLIShell.CommandHandler.STANDARD_MODE)
        userListHandler.configure(1, self.__listUsers, helpTxt="List the users with access to [account]",
                                  usage="[account]")
        userHandler.configureSubcommand(userListHandler)
        userCreateHandler = CLIShell.CommandHandler("create",helpTxt="Admin: create a new user",
                                                    mode=CLIShell.CommandHandler.STANDARD_MODE)
        userCreateHandler.configure(1, self.__userCreate, helpTxt="Admin: create user [username]",
                                    usage="[username]")
        userHandler.configureSubcommand(userCreateHandler)
        userPasswdHandler = CLIShell.CommandHandler("passwd",helpTxt="Set password",
                                                    defaultCb=self.__userPasswd,
                                                    mode=CLIShell.CommandHandler.STANDARD_MODE)
        userPasswdHandler.configure(1, self.__userPasswd, helpTxt="Admin: Set the password for user",
                                    usage="[user]")
        userHandler.configureSubcommand(userPasswdHandler)
        exportCommandHandler = CLIShell.CommandHandler("export",helpTxt="[Admin] Export the entire ledger",
                                                       defaultCb=self.__exportLedger,
                                                       mode=CLIShell.CommandHandler.STANDARD_MODE)
        exportCommandHandler.configure(1, self.__exportLedger, helpTxt="Export ledger for a specific acocunt", 
                                       usage="[account]")
        self.registerCommand(adminCommandHandler)
        self.registerCommand(accessCommandHandler)
        self.registerCommand(accountHandler)
        self.registerCommand(userHandler)
        self.registerCommand(exportCommandHandler)
        
            
class PlaygroundNodeControl(object):
    Name = "OnlineBank"
    def __init__(self):
        self.__mode = None
        self.__stdioUI = None
    
    def processServer(self, serverArgs):
        if len(serverArgs) == 1:
            bankServerConfigFile = serverArgs[0]
            if not os.path.exists(bankServerConfigFile):
                return (False, "Bank server config file %s does not exists" % bankServerConfigFile)
            configOptions = LoadOptions(bankServerConfigFile)
            
            commonData = configOptions.getSection("bank.common")
            certPath, connectionType = commonData["cert_path"], commonData["connection_type"]
            
            serverData = configOptions.getSection("bank.server")
            passwordFile, bankPath = serverData["online_password_file"], serverData["bank_path"]
        elif len(serverArgs) == 4:
            passwordFile, bankPath, certPath, connectionType = serverArgs
        else:
            return (False, "Bank server requires either a config file or " +
                            "passwordFile, bankPath, certPath, connectionType")
        if not os.path.exists(passwordFile):
            return (False, "Could not locate passwordFile " + passwordFile)
        if not os.path.exists(certPath):
            return (False, "Could not locate cert file " + certPath)
        with open(certPath) as f:
            cert = X509Certificate.loadPEM(f.read())
        ledgerPassword = getpass.getpass("Enter bank password:")
        bank = Ledger(bankPath, cert, ledgerPassword)
        self.bankServer = PlaygroundOnlineBank(passwordFile, bank)
        self.clientBase.listen(self.bankServer, 
                               BANK_FIXED_PLAYGROUND_PORT, 
                               connectionType=connectionType)
        if serverData.has_key("mint_cert_file"):
            mintCertFile = serverData["mint_cert_file"]
            with open(mintCertFile) as f:
                cert = X509Certificate.loadPEM(f.read())
            result = bank.registerMintCert(cert)
            if not result.succeeded():
                print "Could not load certificate", result.msg()
        self.__mode = "server"
        logctx = LoggingContext()
        logctx.nodeId = "onlinebank_"+BANK_FIXED_PLAYGROUND_ADDR.toString()
        #logctx.doPacketTracing = True
        playground.playgroundlog.startLogging(logctx)
        return (True,"")
    
    def processClient(self, clientArgs):
        if len(clientArgs) == 2:
            bankPlaygroundAddr, configFile = clientArgs
            bankPlaygroundAddr = playground.network.common.PlaygroundAddress.FromString(bankPlaygroundAddr)
            if not os.path.exists(configFile):
                return (False, "No such bank client CLI config file %s" % configFile)
            configOptions = LoadOptions(configFile)
            
            commonData = configOptions.getSection("bank.common")
            certPath, connectionType = commonData["cert_path"], commonData["connection_type"]
            
            clientData = configOptions.getSection("bank.client_cli")
            loginName = clientData["login_name"]
        else:
            return (False, "Bank client CLI requires a config file.")
        if not os.path.exists(certPath):
            return (False, "Could not locate cert file " + certPath)
        with open(certPath) as f:
            cert = X509Certificate.loadPEM(f.read())
        passwd = getpass.getpass("Enter bank account password for %s: "%loginName)
        clientFactory = PlaygroundOnlineBankClient(cert, loginName, passwd)
        uiFactory = AdminBankCLIClient(self.clientBase,
                                       clientFactory,
                                       bankPlaygroundAddr,
                                       connectionType)
        self.__stdioUI = uiFactory
        self.__mode = "client"
        logctx = LoggingContext()
        logctx.nodeId = loginName+"_bankclient_"+BANK_FIXED_PLAYGROUND_ADDR.toString()
        #logctx.doPacketTracing = True
        playground.playgroundlog.startLogging(logctx)
        return (True, "")
    
    def getStdioProtocol(self):
        return self.__stdioUI
    
    def start(self, clientBase, args):
        self.clientBase = clientBase
        if len(args) == 0 or args[0] not in ['server', 'client']:
            return (False, "OnlineBank requires either 'server' or 'client' not %s" % args[0])
        if args[0] == 'server':
            return self.processServer(args[1:])
        if args[0] == 'client':
            return self.processClient(args[1:])
        return (False, "Internal inconsistency. Should not get here")
    
    def stop(self):
        # not yet implemented
        return (True,"")
    
class PasswordData(object):
    # NOTE. Uses shelve.
    #  Originally used "sync" but wouldn't sync!
    #  So, now, I use close to force it to sync
    
    PASSWORD_TABLE = "pw"
    ACCOUNT_TABLE = "act"
    USER_ACCESS_TABLE = "acc"
    
    ACCOUNT_PRIVILEGES = "btdwa" # balance, transfer, deposit, withdraw, administer
    ADMIN_PRIVILEGES = "BSAFC" # balance (all users), switch (to admin accounts)
                                # administer, freeze, confiscate
                                
    ADMIN_ACCOUNT = "__admin__"
    
    def __init__(self, filename):
        self.__filename = filename
        if not os.path.exists(self.__filename):
            self.__createDB(self.__filename)
        else: self.__loadDB(self.__filename)
            
    def __createDB(self, filename):
        #if filename.endswith(".db"):
        #    filename = filename[:-3]
        # this open is soley to create the file
        db = shelve.open(filename)
        db.close()
        self.__tmpPwTable = {}
        self.__tmpAccountTable = {self.ADMIN_ACCOUNT:0}
        self.__tmpUserTable = {}
        for tableName in Ledger.INITIAL_ACCOUNTS:
            self.__tmpAccountTable[tableName]=0
        self.sync()
        
    def __loadDB(self, filename):
        #if filename.endswith(".db"):
        #    filename = filename[:-3]
        with closing(shelve.open(filename)) as db:
            # this is all currently loaded into memory. Find something better?
            self.__tmpUserTable = db[self.USER_ACCESS_TABLE]
            self.__tmpAccountTable = db[self.ACCOUNT_TABLE]
            self.__tmpPwTable = db[self.PASSWORD_TABLE]
        
    def sync(self):
        with closing(shelve.open(self.__filename)) as db:
            db[self.USER_ACCESS_TABLE] = self.__tmpUserTable
            db[self.ACCOUNT_TABLE] = self.__tmpAccountTable
            db[self.PASSWORD_TABLE] = self.__tmpPwTable
        
    def __setUser(self, username, passwordHash):
        self.__tmpPwTable[username] = passwordHash
        
    def __delUser(self, userName):
        del self.__tmpPwTable[userName]
        if self.__tmpUserTable.has_key(userName):
            del self.__tmpUserTable[userName]
            
    def __addAccount(self, accountName):
        self.__tmpAccountTable[accountName] = 1
        
    def hasUser(self, userName):
        return self.__tmpPwTable.has_key(userName)
    
    def hasAccount(self, accountName):
        return self.__tmpAccountTable.has_key(accountName)
    
    def iterateAccounts(self):
        return self.__tmpAccountTable.iterkeys()
    
    def iterateUsers(self, account=None):
        if not account:
            return self.__tmpPwTable.iterkeys()
        else:
            return [username for username in self.__tmpUserTable.iterkeys() 
                    if self.__tmpUserTable[username].has_key(account)]
    
    def __getUserPw(self, userName):
        return self.__tmpPwTable[userName]
    
    def currentAccess(self, userName, accountName=None):
        access = self.__tmpUserTable.get(userName, {})
        if accountName:
            return access.get(accountName, {})
        else: return access
    
    def __setUserAccess(self, userName, accountName, privilegeData):
        if not self.__tmpUserTable.has_key(userName):
            self.__tmpUserTable[userName] = {}
        self.__tmpUserTable[userName][accountName] = privilegeData
        
    def isValidAccessSpec(self, access, accountName):
        if accountName == self.ADMIN_ACCOUNT:
            allAccess = self.ADMIN_PRIVILEGES
        else:
            allAccess = self.ACCOUNT_PRIVILEGES
        for accessLetter in access:
            if accessLetter not in allAccess:
                return False
        return True
            
    def createUser(self, userName, passwordHash, modify=False):
        if self.hasUser(userName)and not modify:
            raise Exception("User  %s already exists" % userName)
        self.__setUser(userName, passwordHash)
        
    def currentUserPassword(self, userName):
        if not self.hasUser(userName):
            raise Exception("User  %s does not already exist" % userName)
        return self.__getUserPw(userName)
                
    def createAccount(self, accountName):
        if self.hasAccount(accountName):
            raise Exception("Account %s already exists" % accountName)
        self.__addAccount(accountName)
        
    def configureAccess(self, userName, accountName, access):
        if not self.hasUser(userName):
            raise Exception("No such user %s to assign to account" % userName)
        if not self.hasAccount(accountName):
            raise Exception("No such account %s for user privileges" % accountName)
        if not self.isValidAccessSpec(access, accountName):
            raise Exception("Unknown access %s" % (access, )) 
        self.__setUserAccess(userName, accountName, access)
        
    def removeUser(self, userName):
        if not self.hasUser(userName):
            raise Exception("No such user %s to remove" % userName)
        self.__delUser(userName)       
        
control = PlaygroundNodeControl()
Name = control.Name
start = control.start
stop = control.stop
getStdioProtocol = control.getStdioProtocol

USAGE = """
OnlineBank.py pw <passwordFile> user [add <username>] [del <username>] [change <username>]
OnlineBank.py pw <passwordFile> account [add <accountname]
OnlineBank.py pw <passwordFile> chmod <username> <accountname> [<privileges>]
\tPrivileges must be one of %s or %s
OnlineBank.py server <passwordFile> <bankpath> <cert> <playground server IP> <playground server port> <connection_type>
OnlineBank.py server <bank addr> <chaperone addr> <config>
OnlineBank.py client_cli -f <config> 
""" % (PasswordData.ACCOUNT_PRIVILEGES, PasswordData.ADMIN_PRIVILEGES)

BANK_FIXED_PLAYGROUND_ADDR = playground.network.common.PlaygroundAddress(20151, 0, 1, 1)

def getPasswordHashRoutine(currentPw=None):
    newPw = None
    oldPw = None
    while currentPw != oldPw:
        oldPw = getpass.getpass("ENTER CURRENT PASSWORD:")
        oldPw = PasswordHash(oldPw)
    while newPw == None:
        newPw = getpass.getpass("Enter new password:")
        newPw2 = getpass.getpass("Re-enter new password:")
        if newPw != newPw2:
            print "Passwords did not match"
            newPw = None
    return PasswordHash(newPw)

if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] == "help" or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        sys.exit(USAGE)
    if sys.argv[1] == "pw":
        if len(sys.argv) < 4:
            sys.exit(USAGE)
        pwfile, cmd = sys.argv[2:4]
        pwDB = PasswordData(pwfile)
        if cmd == "user":
            if len(sys.argv) != 6:
                sys.exit(USAGE)
            subcmd, userName = sys.argv[4:6]
            if subcmd == "add":
                if pwDB.hasUser(userName):
                    sys.exit("User %s already exists" % userName)
                newPw = getPasswordHashRoutine()
                pwDB.createUser(userName, newPw, modify=False)
            elif subcmd == "del":
                if not pwDB.hasUser(userName):
                    sys.exit("No such user login name: " + userName)
                pwDB.removeUser(userName)
            elif subcmd == "change":
                if not pwDB.hasUser(userName):
                    sys.exit("User %s does not already exist" % userName)
                oldPwHash = pwDB.currentUserPassword(userName)
                newPw = getPasswordHashRoutine(oldPwHash)
                pwDB.createUser(userName, newPw, modify=True)
            else:
                sys.exit(USAGE)
        elif cmd == "account":
            if len(sys.argv) != 6:
                sys.exit(USAGE)
            subcmd, accountName = sys.argv[4:6]
            if subcmd == "add":
                if pwDB.hasAccount(accountName):
                    sys.exit("Account %s already exists" % accountName)
                pwDB.createAccount(accountName)
            else:
                sys.exit(USAGE)
        elif cmd == "chmod":
            if len(sys.argv) == 5:
                userName = sys.argv[4]
                accountName, accessString = None, None
            elif len(sys.argv) == 6:
                userName, accountName = sys.argv[4:6]
                accessString = None
            elif len(sys.argv) == 7:
                userName, accountName, accessString = sys.argv[4:7]
            else:
                sys.exit(USAGE)
            if not pwDB.hasUser(userName):
                sys.exit("User %s does not already exist" % userName)
            if accountName and not pwDB.hasAccount(accountName):
                sys.exit("Account %s does not exist" % accountName)
            if accountName and accessString:
                if not pwDB.isValidAccessSpec(accessString, accountName):
                    sys.exit("Invalid access spec")
                pwDB.configureAccess(userName, accountName, accessString)
            else:
                print "current privileges", pwDB.currentAccess(userName, accountName)
        pwDB.sync()
        sys.exit("Finished.")
    elif sys.argv[1] == "verify_receipt":
        certfile = sys.argv[2]
        receipt = sys.argv[3]
        receiptSig = sys.argv[4]
        with open(certfile) as f:
            cert = X509Certificate.loadPEM(f.read())
        rsaKey = RSA.importKey(cert.getPublicKeyBlob())
        verifier = PKCS1_v1_5.new(rsaKey)
        with open(receipt) as f:
            receiptData = f.read()
        with open(receiptSig) as f:
            receiptSigData = f.read()
        print "Verification result = ", verifier.verify(SHA.new(receiptData), receiptSigData)
    elif sys.argv[1] in ["server", "client"]:
        bankAddr = playground.network.common.PlaygroundAddress.FromString(sys.argv[2])
        chaperoneAddr = sys.argv[3]
        runner = PlaygroundNode(bankAddr, chaperoneAddr, 9090, standAlone=True)
        bankModule = PlaygroundNodeControl()
        args = [sys.argv[1]]+sys.argv[4:]
        tasks = []
        tasks.append(StandaloneTask(runner.startScript, [bankModule, args]))
        if sys.argv[1] == "client":
            tasks.append(StandaloneTask(lambda: stdio.StandardIO(bankModule.getStdioProtocol()),[]))
        runner.startLoop(*tasks)
        """
        if len(sys.argv) == 4 and sys.argv[2] == "-f":
            if not os.path.exists(sys.argv[3]):
                sys.exit("No such config file %s")
            configOptions = LoadOptions(sys.argv[3])
            serverData = configOptions.getSection("bank.server")
            passwordFile = serverData["online_password_file"]
            bankPath = serverData["bank_path"]
            certPath = serverData["cert_path"]
            playgroundAddr = serverData["playground_server"]
            playgroundPort = serverData["playground_tcp_port"]
            connectionType = serverData["connection_type"]
        else:
            if len(sys.argv) != 8:
                sys.exit(USAGE)
            passwordFile, bankPath, certPath, playgroundAddr, playgroundPort, connectionType = sys.argv[2:]
        playgroundPort = int(playgroundPort)
        if not os.path.exists(passwordFile):
            sys.exit("Could not locate passwordFile " + passwordFile)
        if not os.path.exists(certPath):
            sys.exit("Could not locate cert file " + certPath)
        with open(certPath) as f:
            cert = X509Certificate.loadPEM(f.read())
        ledgerPassword = getpass.getpass("Enter bank password:")
        bank = Ledger(bankPath, cert, ledgerPassword)
        bankServer = PlaygroundOnlineBank(passwordFile, bank)
        client = playground.network.client.ClientBase(BANK_FIXED_PLAYGROUND_ADDR)
        client.listen(bankServer, BANK_FIXED_PLAYGROUND_PORT, connectionType=connectionType)
        
        logctx = LoggingContext()
        logctx.nodeId = "onlinebank_"+BANK_FIXED_PLAYGROUND_ADDR.toString()
        #logctx.doPacketTracing = True
        playground.playgroundlog.startLogging(logctx)
        
        client.connectToChaperone(playgroundAddr, playgroundPort)
    elif sys.argv[1] == "client_cli":
        if len(sys.argv) == 4 and sys.argv[2] == "-f":
            if not os.path.exists(sys.argv[3]):
                sys.exit("No such config file %s")
            configOptions = LoadOptions(sys.argv[3])
            clientData = configOptions.getSection("bank.client_cli")
            loginName = clientData["login_name"]
            certPath = clientData["cert_path"]
            clientAddrString = clientData["address"]
            playgroundAddr = clientData["playground_server"]
            playgroundPort = clientData["playground_tcp_port"]
            connectionType = clientData["connection_type"]
        else:
            sys.exit(USAGE)
        playgroundPort = int(playgroundPort)
        with open(certPath) as f:
            cert = X509Certificate.loadPEM(f.read())
        #client = playground.network.client.ClientBase(playground.network.common.PlaygroundAddress(20151, 0, 1, 999))
        clientAddr = playground.network.common.PlaygroundAddress.FromString(clientAddrString)
        client = playground.network.client.ClientBase(clientAddr)
        passwd = getpass.getpass("Enter bank account password for %s: "%loginName)
        clientFactory = PlaygroundOnlineBankClient(cert, loginName, passwd)
        #delayedConnect = lambda: client.connect(clientFactory, BANK_FIXED_PLAYGROUND_ADDR, BANK_FIXED_PLAYGROUND_PORT, connectionType=connectionType)
        delayedCLI = lambda: stdio.StandardIO(AdminBankCLIClient(client, 
                                                                 clientFactory, 
                                                                 BANK_FIXED_PLAYGROUND_ADDR, 
                                                                 connectionType))
        
        logctx = LoggingContext()
        logctx.nodeId = "client_cli"
        #logctx.doPacketTracing = True
        playground.playgroundlog.startLogging(logctx)
        
        client.runWhenConnected(delayedCLI)
        client.connectToChaperone(playgroundAddr, playgroundPort)"""
    else:
        sys.exit(USAGE)