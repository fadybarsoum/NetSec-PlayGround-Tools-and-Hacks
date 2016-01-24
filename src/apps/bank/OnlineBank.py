'''
Created on Mar 27, 2014

@author: sethjn
'''

import playground, random, sys, os, getpass, pickle, shelve
from BankMessages import OpenSession, SessionOpen, BalanceRequest, TransferRequest, Close
from BankMessages import BalanceResponse, Receipt, LoginFailure, RequestFailure
from BankMessages import VaultDepositRequest, CreateAccountRequest, ChangePasswordRequest, AdminBalanceRequest
from BankMessages import VaultDepositReceipt, RequestSucceeded, AdminBalanceResponse
from playground.network.message import MessageData
from playground.network.common import Timer
from CipherUtil import SHA, X509Certificate, RSA, PKCS1_v1_5
from Exchange import BitPoint

from playground.playgroundlog import logging, LoggingContext
from playground.config import LoadOptions
from playground.error import ErrorHandler
from computePi import PlaygroundNodeControl
logger = logging.getLogger(__file__)

from BankCore import Ledger, LedgerLine
from contextlib import closing

from twisted.internet import defer
from twisted.internet.protocol import Protocol as TwistedProtocol
from twisted.internet import stdio
from twisted.protocols import basic

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

class BankServerProtocol(playground.network.common.SimpleMessageHandlingProtocol):
    MIB_CURRENT_STATE = "CurrentState"
    
    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    
    ADMIN_LOGIN_NAME = "__admin__"
    ADMIN_ACCOUNT = "VAULT"
    def __init__(self, factory, addr, pwFile, bank):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__pwFile = pwFile
        with closing(self.loadLoginData(self.__pwFile)) as testLoginData:
            if testLoginData == InvalidPwFile:
                raise Exception("Invalid password file")
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0,
                           "AccountName":None,
                           "LoginName":None}
        self.__state = self.STATE_UNINIT
        self.__bank = bank
        self.registerMessageHandler(OpenSession, self.__handleOpenSession)
        self.registerMessageHandler(BalanceRequest, self.__handleBalanceRequest)
        self.registerMessageHandler(TransferRequest, self.__handleTransferRequest)
        self.registerMessageHandler(VaultDepositRequest, self.__handleVaultDeposit)
        self.registerMessageHandler(AdminBalanceRequest, self.__handleAdminBalanceRequest)
        self.registerMessageHandler(CreateAccountRequest, self.__handleCreateAccount)
        self.registerMessageHandler(ChangePasswordRequest, self.__handleChangePassword)
        self.registerMessageHandler(Close, self.__handleClose)
    
    @classmethod
    def loadLoginData(cls, pwFile):
        dbName = pwFile
        if dbName.endswith(".db"):
            dbName = dbName[:-3]
        logger.debug("opening %s" % dbName)
        loginData = shelve.open(dbName)
        if loginData.get(cls.ADMIN_LOGIN_NAME, (None,None))[1] != cls.ADMIN_ACCOUNT:
            loginData.close()
            return InvalidPwFile
        return loginData
        
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
    
    def __error(self, errMsg, requestId = 0):
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
        self.__state = self.STATE_ERROR
        self.transport.writeMessage(response)
        self.callLater(1,self.transport.loseConnection)
        return None
    
    def __getSessionAccount(self, msgObj):
        if self.__state != self.STATE_OPEN:
            self.__error("Session not logged-in", msgObj.RequestId)
            return None
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None
        account = self.__connData["AccountName"]
        return account
    
    def __validateAdminPeerConnection(self):
        peer = self.transport.getPeer()
        if not peer: return False
        return True
    
    def __getAdminAccount(self, msgObj):
        if not self.__validateAdminPeerConnection():
            self.__error("Unauthorized connection location. Will be logged", msgObj.RequestId)
            return None
        account = self.__getSessionAccount(msgObj)
        if account != self.ADMIN_ACCOUNT:
            self.__error("Unauthorized account", msgObj.RequestId)
            return None
        return account
    
    def __createResponse(self, msgObj, responseType):
        response = MessageData.GetMessageBuilder(responseType)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(msgObj.ServerNonce)
        return response
    
    def __handleOpenSession(self, protocol, msg):
        if self.__state != self.STATE_UNINIT:
            return self.__error("Session not uninitialized. State %s" % self.__state)
        msgObj = msg.data()
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        with closing(self.loadLoginData(self.__pwFile)) as loginData:
            if not loginData.has_key(msgObj.Login):
                return self.__error("Invalid Login")
            if msgObj.Login == self.ADMIN_LOGIN_NAME and not self.__validateAdminPeerConnection():
                return self.__error("Unauthorized connection to access admin")
            passwordHash, accountName = loginData[msgObj.Login]
        if not passwordHash == msgObj.PasswordHash:
            return self.__error("Invalid Login")
        if not  accountName in self.__bank.getAccounts():
            return self.__error("Invalid Login")
        self.__connData["ServerNonce"] = RANDOM_u64()
        self.__connData["AccountName"] = accountName
        self.__connData["LoginName"] = msgObj.Login
        self.__state = self.STATE_OPEN
        response = MessageData.GetMessageBuilder(SessionOpen)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(self.__connData["ServerNonce"])
        response["Account"].setData(accountName)
        self.transport.writeMessage(response)
    
    def __handleBalanceRequest(self, protocol, msg):
        msgObj = msg.data()
        account = self.__getSessionAccount(msgObj)
        if not account:
            return
        balance = self.__bank.getBalance(account)
        response = self.__createResponse(msgObj, BalanceResponse)
        response["RequestId"].setData(msgObj.RequestId)
        response["Balance"].setData(balance)
        self.transport.writeMessage(response)
        
    def __handleAdminBalanceRequest(self, protocol, msg):
        msgObj = msg.data()
        account = self.__getAdminAccount(msgObj)
        if not account:
            return
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
        msgObj = msg.data()
        account = self.__getSessionAccount(msgObj)
        if not account:
            return
        dstAccount = msgObj.DstAccount
        if not dstAccount in self.__bank.getAccounts():
            return self.__error("Invalid destination account %s" % dstAccount, msgObj.RequestId)
        amount = msgObj.Amount
        if amount < 0: 
            return self.__error("Invalid (negative) amount %d" % amount, msgObj.RequestId)
        if amount > self.__bank.getBalance(account):
            return self.__error("Insufficient Funds to pay %d" % amount, msgObj.RequestId)
        result = self.__bank.transfer(account,dstAccount, amount, msgObj.Memo)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId)
        # Assume single threaded. The last transaction will still be the one we care about
        result = self.__bank.generateReceipt(dstAccount)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId)
        receipt, signature = result.value()
        response = self.__createResponse(msgObj, Receipt)
        response["RequestId"].setData(msgObj.RequestId)
        response["Receipt"].setData(receipt)
        response["ReceiptSignature"].setData(signature)
        self.transport.writeMessage(response)
        
    def __handleVaultDeposit(self, protocol, msg):
        msgObj = msg.data()
        account = self.__getAdminAccount(msgObj)
        if not account:
            return
        bps = []
        bpData = msgObj.bpData
        while bpData:
            newBitPoint, offset = BitPoint.deserialize(bpData)
            bpData = bpData[offset:]
            bps.append(newBitPoint)
        result = bank.depositCash("VAULT",bps)
        if not result.succeeded():
            response = self.__createResponse(msgObj, RequestFailure)
            response["RequestId"].setData(msgObj.RequestId)
            response["ErrorMessage"].setData(result.msg())
        else:
            response = self.__createResponse(msgObj, VaultDepositReceipt)
            response["RequestId"].setData(msgObj.RequestId)
            response["Balance"].setData(bank.getBalance("VAULT"))
        self.transport.writeMessage(response)
        
    def __handleCreateAccount(self, protocol, msg):
        msgObj = msg.data()
        account = self.__getAdminAccount(msgObj)
        if not account:
            return
        
        response = self.__createResponse(msgObj, RequestSucceeded)
        newAccountName = msgObj.AccountName
        accountLogin = msgObj.loginName
        accountPassword = msgObj.pwHash
        with closing(self.loadLoginData(self.__pwFile)) as loginData:
            if loginData.has_key(accountLogin):
                response = self.__createResponse(msgObj, RequestFailure)
                response["RequestId"].setData(msgObj.RequestId)
                response["ErrorMessage"].setData("That login already exists")
            else:
                result = bank.createAccount(newAccountName)
                if result.succeeded():
                    loginData[accountLogin] = (accountPassword, newAccountName)
                    #self.__loginData.close() # flush
                    #self.__loginData = self.loadLoginData(self.__pwFile)
                    #if not self.__loginData:
                        # this should never happen. If it does, we should try to die!
                    #    self.reportException(Exception("unexpected internal error!"), fatal=True)
                response["RequestId"].setData(msgObj.RequestId)
            self.transport.writeMessage(response)
        
    def __handleChangePassword(self, protocol, msg):
        msgObj = msg.data()
        if (msgObj.loginName != "") or (msgObj.oldPwHash == ""):
            account = self.__getAdminAccount(msgObj)
            loginName = msgObj.loginName
            oldPassword = None
        else:
            account = self.__getSessionAccount(msgObj)
            loginName = self.__connData["LoginName"]
            oldPassword = msgObj.oldPwHash
        if not account:
            return
        
        response = self.__createResponse(msgObj, RequestSucceeded)
        response["RequestId"].setData(msgObj.RequestId)
        newPassword = msgObj.newPwHash
        with closing(self.loadLoginData(self.__pwFile)) as loginData:
            origPassword, account = loginData.get(loginName, (None, None))
            if not account:
                response = self.__createResponse(msgObj, RequestFailure)
                response["RequestId"].setData(msgObj.RequestId)
                response["ErrorMessage"].setData("No such login")
            elif oldPassword != None and origPassword != oldPassword:
                response = self.__createResponse(msgObj, RequestFailure)
                response["RequestId"].setData(msgObj.RequestId)
                response["ErrorMessage"].setData("Invalid original password")
            else:
                loginData[loginName] = (newPassword, account)
                #self.__loginData.close() # flush
                #self.__loginData = self.loadLoginData(self.__pwFile)
                #if not self.__loginData:
                    # this should never happen. If it does, we should try to die!
                #    self.reportException(Exception("unexpected internal error!"), fatal=True)
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
        self.__deferred = {"CONNECTION":defer.Deferred()}
        self.__state = self.STATE_UNINIT
        self.__account = None
        rsaKey = RSA.importKey(cert.getPublicKeyBlob())
        self.__verifier = PKCS1_v1_5.new(rsaKey)
        self.registerMessageHandler(SessionOpen, self.__handleSessionOpen)
        self.registerMessageHandler(BalanceResponse, self.__handleBalanceResponse)
        self.registerMessageHandler(Receipt, self.__handleReceipt)
        self.registerMessageHandler(LoginFailure, self.__handleLoginFailure)
        self.registerMessageHandler(RequestFailure, self.__handleRequestFailure)
        self.registerMessageHandler(AdminBalanceResponse, self.__handleAdminBalancesResponse)
        self.registerMessageHandler(VaultDepositReceipt, self.__handleVaultDepositResponse)
        self.registerMessageHandler(RequestSucceeded, self.__handleRequestSucceeded)
        
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
        
    def getBalance(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        balanceMsg, d = self.__createStdSessionRequest(BalanceRequest)
        self.transport.writeMessage(balanceMsg)
        return d
    
    def __handleBalanceResponse(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback(msgObj.Balance)
        
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
        
    def __handleReceipt(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        d = self.__validateStdSessionResponse(msgObj)
        if not d: return
        
        if not self.__verifier.verify(SHA.new(msgObj.Receipt), msgObj.ReceiptSignature):
            return d.errback(Exception("Received a receipt with mismatching signature\n%s\n%s" % (SHA.new(msgObj.Receipt), msgObj.ReceiptSignature)))
        d.callback((msgObj.Receipt, msgObj.ReceiptSignature))
        
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
    
    def __handleAdminBalancesResponse(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback((msgObj.Accounts, msgObj.Balances))
        
    def adminVaultDeposit(self, serializedBp):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        depositMsg, d = self.__createStdSessionRequest(VaultDepositRequest)
        depositMsg["bpData"].setData(serializedBp)
        self.transport.writeMessage(depositMsg)
        return d
    
    def __handleVaultDepositResponse(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback(msgObj.Balance)
        
    def adminCreateAccount(self, loginName, accountName, password):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        createMsg, d = self.__createStdSessionRequest(CreateAccountRequest)
        createMsg["loginName"].setData(loginName)
        createMsg["AccountName"].setData(accountName)
        createMsg["pwHash"].setData(PasswordHash(password))
        self.transport.writeMessage(createMsg)
        return d
    
    def changePassword(self, newPassword, oldPassword=None, loginName=None):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        changeMsg, d = self.__createStdSessionRequest(ChangePasswordRequest)
        if loginName:
            changeMsg["loginName"].setData(loginName)
        else: changeMsg["loginName"].setData("")
        if oldPassword:
            changeMsg["oldPwHash"].setData(PasswordHash(oldPassword))
        else: changeMsg["oldPwHash"].setData("")
        changeMsg["newPwHash"].setData(PasswordHash(newPassword))
        self.transport.writeMessage(changeMsg)
        return d
    
    def __handleRequestSucceeded(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Response")
        msgObj = msg.data()
        
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback(True)
        
class PlaygroundOnlineBank(playground.network.client.ClientApplicationServer.ClientApplicationServer):
    MIB_BALANCES = "BankBalances"

    def __init__(self, passwordData, bank):
        #super(PlaygroundOnlineBank, self).__init__(self)
        with closing(BankServerProtocol.loadLoginData(passwordData)) as pwCheck:
            if pwCheck == InvalidPwFile:
                raise Exception("password data file %s is invalid" % passwordData)
        self.__bank = bank
        self.__passwordData = passwordData
        
    def __loadMibs(self):
        if self.MIBAddressEnabled():
            self.registerLocalMIB(self.MIB_BALANCES, self.__handleMib)
        
    def __handleMib(self, mib, args):
        if mib.endswith(self.MIB_BALANCES):
            balances = []
            for account in self.__bank.getAccounts():
                balances.append("%s: %s (b^)" % (account, str(bank.getBalance(account))))
            return balances
        return []
        
    def configureMIBAddress(self, *args, **kargs):
        playground.network.client.ClientApplicationServer.ClientApplicationServer.configureMIBAddress(self, *args, **kargs)
        self.__loadMibs()
    
    def buildProtocol(self, addr):
        p = BankServerProtocol(self, addr, self.__passwordData, self.__bank)
        return p
    
class ClientTest(object):
    def __init__(self, depositAccount, connectionType = "RAW"):
        self._count = 0
        self._deposit = depositAccount
        self._connType
        
    def runTest(self, clientFactory, client, addr, port):#protocol):
        protocol = client.connect(clientFactory, addr, port, connectionType=self._connType)
        self._factory = clientFactory
        self._protocol = protocol.getApplicationLayer()
        conn = self._protocol.waitForConnection()
        conn.addCallback(self.login)
        conn.addErrback(self.noConnection)
        
    def noConnection(self, f):
        print "Could not get connection."
        print f
        return f
        
    def login(self, prevResult):
        print "Connected. Logging in"
        conn = self._protocol.loginToServer()
        conn.addCallback(self.getBalance)
        conn.addErrback(self.loginFailed)
    
    def getBalance(self, prevResult):
        req = self._protocol.getBalance()
        req.addCallback(self.gotBalance)
        req.addErrback(self.getBalanceFailed)
        
    def loginFailed(self, f):
        print "Could not login",self._factory._loginName
        print f
        return f
    
    def gotBalance(self, balance):
        print "Got balance", balance
        if self._count >= 5:
            print "TEST FINISHED"
            return
        self._count += 1
        req = self._protocol.transfer(self._deposit, 200, "transfer %d" % self._count)
        req.addCallback(self.transferDone)
        req.addErrback(self.transferFailed)
        
    def getBalanceFailed(self, f):
        print "Could not get balance"
        print f
        return f
    
    def transferDone(self, result):
        receipt, receiptSignature = result
        print "got receipt"
        l = pickle.loads(receipt)
        for a in [self._protocol.account(), self._deposit]:
            print "Receipt for account", a
            print "\tTransfer this transaction:",l.getTransactionAmount(a)
            print "\tBalance:",l.getBalance(a)
        self.getBalance(True)
        
    def transferFailed(self, f):
        print "Could not perform transfer"
        print f
        return f
    
class PlaygroundOnlineBankClient(playground.network.client.ClientApplicationServer.ClientApplicationClient):
    def __init__(self, cert, loginName, pw):
        #super(PlaygroundOnlineBankClientTest, self).__init__(self)
        self._cert = cert
        self._loginName = loginName
        self._pw = pw
        
    def buildProtocol(self, addr):
        return BankClientProtocol(self, addr, self._cert, self._loginName, self._pw)

class AdminBankCLIClient(basic.LineReceiver, ErrorHandler):
    from os import linesep as delimiter
    
    def __init__(self, clientBase, bankClientFactory, bankAddr, connectionType):
        self.__d = None
        self.__backlog = []
        self.__bankClient = None
        self.__bankAddr = bankAddr
        self.__bankClientFactory = bankClientFactory
        self.__connectionType = connectionType
        self.__clientBase = clientBase
        self.__admin = False
        
    def __loginToServer(self, success):
        if not success:
            return self.__noLogin(Exception("Failed to login"))
        self.__d = self.__bankClient.loginToServer()
        self.__d.addCallback(self.__login)
        self.__d.addErrback(self.__noLogin)
        
    def __login(self, success):
        self.reset()
        
    def __noLogin(self, e):
        self.transport.write("Failed to login to bank: %s\n" % str(e))
        self.transport.write("Quiting")
        Timer.callLater(.1, self.__quit)
    
    def __balances(self, result):
        accounts, balances = result
        if len(accounts) != len(balances):
            self.transport.write("Inernal Error. Got %d accounts but %d balances\n" % (len(accounts), len(balances)))
            return
        self.transport.write("\tCurrent Balances:\n")
        for i in range(len(accounts)):
            self.transport.write("\t\t%s: %d\n" % (accounts[i],balances[i]))
        self.transport.write("\n\n>")
        self.reset()
        
    def __accountBalance(self, result):
        self.transport.write("Current account balance: %d\n" % result)
        self.transport.write("\n\n")
        self.reset()
        
    def __vaultDeposit(self, newBalance):
        self.transport.write("\tDeposited. New balance is %d\n" % newBalance)
        self.transport.write("\n\n>")
        self.reset()
        
    def __transfer(self, result):
        #receipt, rSig = result
        self.transport.write("\tTransfer complete.\n")
        self.transport.write("\n\n>")
        self.reset()
        
    def __createAccount(self, result):
        self.transport.write("\tAccount created.\n")
        self.transport.write("\n\n>")
        self.reset()
        
    def __changePassword(self, result):
        self.transport.write("\tPassword changed successfully.\n")
        self.transport.write("\n\n>")
        self.reset()
        
    def __failed(self, e):
        self.transport.write("\tOperation failed. Reason: %s\n" % str(e))
        self.transport.write("\n\n>")
        self.reset()
        
    def handleError(self, message, reporter=None, stackHack=0):
        self.transport.write("Error: %s\n" % message)
        
    def __quit(self):
        self.transport.write("Exiting.\n")
        Timer.callLater(0, self.__clientBase.disconnectFromPlaygroundServer())
    
    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        self.handleError(str(e))
        
    def reset(self):
        self.__d = None
        if self.__backlog:
            nextBackLog = self.__backlog.pop(0)
            self.lineReceived(nextBackLog)
        else:
            self.transport.write(">>> ")

    def connectionMade(self):
        print "connection made in bank cli"
        try:
            srcPort, self.__bankClient = self.__clientBase.connect(self.__bankClientFactory, 
                                                          self.__bankAddr,
                                                          BANK_FIXED_PLAYGROUND_PORT,
                                                          self.__connectionType)
                                                          
            self.__bankClient.setLocalErrorHandler(self)
            self.__d = self.__bankClient.waitForConnection()#self.__bankClient.loginToServer()
            self.__d.addCallback(self.__loginToServer)
            self.__d.addErrback(self.__noLogin)
            print "waiting for server"
        except Exception, e:
            print e
            self.transport.loseConnection()

    def lineReceived(self, line):
        try:
            self.__lineReceivedImpl(line)
        except Exception, e:
            self.handleException(e)
            
    def __lineReceivedImpl(self, line):
        print "received line", line
        bankClient = self.__bankClient
        if self.__d:
            self.__backlog.append(line)
            return
        line = line.strip()
        lineParts = line.split(" ")
        if len(lineParts) > 0:
            cmd, args = lineParts[0], lineParts[1:]
            if cmd == "admin":
                self.__admin = not self.__admin
                return self.reset()
            elif cmd == "balance":
                if len(args) == 0:
                    self.__d = bankClient.getBalance()
                    self.__d.addCallback(self.__accountBalance)
                    self.__d.addErrback(self.__failed)
                elif len(args) == 1 and args[0] == "all":
                    if not self.__admin:
                        self.transport.write("Not in admin mode\n")
                        return self.reset()
                    self.__d = bankClient.adminGetBalances()
                    self.__d.addCallback(self.__balances)
                    self.__d.addErrback(self.__failed)
                else:
                    self.transport.write("No arguments expected or argument 'all' to list all balances (admin only)\n")
                    return self.reset()
            elif cmd == "deposit":
                if not self.__admin:
                    self.transport.write("Not in admin mode\n")
                    return self.reset()
                if len(args) != 1:
                    self.transport.write("Expected filename\n")
                    return self.reset()
                bpFile = args[0]
                if not os.path.exists(bpFile):
                    self.transport.write("NO such file\n")
                    return self.reset()
                with open(bpFile) as f:
                    bpData = f.read()
                    self.__d = bankClient.adminVaultDeposit(bpData)
                    self.__d.addCallback(self.__vaultDeposit)
                    self.__d.addErrback(self.__failed)
            elif cmd == "transfer":
                if len(args) != 3:
                    self.transport.write("Requires a destination account, amount, and memo\n")
                    return self.reset()
                dstAcct, amount, memo = args
                try:
                    amount = int(amount)
                except Exception, e:
                    self.transport.write("Can't convert amount to int\n")
                    return self.reset()
                self.__d = bankClient.transfer(dstAcct, amount, memo)
                self.__d.addCallback(self.__transfer)
                self.__d.addErrback(self.__failed)
            elif cmd == "account":
                if len(args) == 0:
                    self.transport.write("Requires at least one more argument\n")
                    return self.reset()
                subcmd = args.pop(0)
                if subcmd == "create":
                    if not self.__admin:
                        self.transport.write("Not in admin mode\n")
                        return self.reset()
                    if len(args) != 2:
                        self.transport.write("Requires a login name and account name\n")
                        return self.reset()
                    loginName, accountName = args
                    password = getpass.getpass("Enter account password: ")
                    password2 = getpass.getpass("Re-enter account password: ")
                    if password != password2:
                        self.transport.write("Mismatching passwords\n")
                        return self.reset()
                    self.__d = bankClient.adminCreateAccount(loginName, accountName, password)
                    self.__d.addCallback(self.__createAccount)
                    self.__d.addErrback(self.__failed)
                elif subcmd == "passwd":
                    if len(args) == 0:
                        loginName = None
                        oldPassword = getpass.getpass("Enter current account password: ")
                    elif len(args) == 1:
                        if not self.__admin:
                            self.transport.write("Not in admin mode\n")
                            return self.reset()
                        loginName = args[0]
                        self.transport.write("Login name specified as [%s]. This requires Admin access\n"%loginName)
                        oldPassword = None
                    password2 = getpass.getpass("Enter new account password: ")
                    password3 = getpass.getpass("Re-enter new account password: ")
                    if password2 != password3:
                        self.transport.write("Mismatching passwords\n")
                        return self.reset()
                    self.__d = bankClient.changePassword(password2, loginName=loginName, oldPassword=oldPassword)
                    self.__d.addCallback(self.__changePassword)
                    self.__d.addErrback(self.__failed)
            elif cmd == "quit":
                bankClient.close()
                self.transport.loseConnection()
                self.__clientBase.disconnectFromPlaygroundServer()
            else:
                self.transport.write("Unknown command\n")
                self.reset()
        else:
            self.reset()
            
class PlaygroundNodeControl(object):
    
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
        self.__mode = "server"
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
        return (True, "")
    
    def getStdioProtocol(self):
        return self.__stdioUI
    
    def start(self, clientBase, args):
        self.clientBase = clientBase
        if len(args) == 0 or args[0] not in ['start_server', 'start_client']:
            return (False, "OnlineBank requires either 'start_server' or 'start_client'")
        if args[0] == 'start_server':
            return self.processServer(args[1:])
        if args[0] == 'start_client':
            return self.processClient(args[1:])
        return (False, "Internal inconsistency. Should not get here")
    
    def stop(self):
        # not yet implemented
        return (True,"")
        
Name = "OnlineBank"
control = PlaygroundNodeControl()
start = control.start
stop = control.stop
getStdioProtocol = control.getStdioProtocol

USAGE = """
OnlineBank.py pw <passwordFile> <loginName> --delete
OnlineBank.py pw <passwordFile> <loginName> <accountName>
OnlineBank.py server <passwordFile> <bankpath> <cert> <playground server IP> <playground server port> <connection_type>
OnlineBank.py server -f <config>
OnlineBank.py client_cli -f <config>
"""

BANK_FIXED_PLAYGROUND_ADDR = playground.network.common.PlaygroundAddress(20151, 0, 1, 1)

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "help" or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        sys.exit(USAGE)
    if sys.argv[1] == "pw":
        if len(sys.argv) != 5:
            sys.exit(USAGE)
        pwfile, loginName, accountName = sys.argv[2:]
        if pwfile.endswith(".db"):
            pwfile = pwfile[:-3]
        pwDB = shelve.open(pwfile)
        if accountName == "--delete":
            if not pwDB.has_key(loginName):
                sys.exit("No such user login name: " + loginName)
            else:
                del pwDB[loginName]
        else:
            if pwDB.has_key(loginName):
                oldHash, oldAccountName = pwDB[loginName]
                if accountName != oldAccountName:
                    print "Login name %s already associated with account %s" % oldAccountName
                    allow = raw_input("Are you sure you want to change the account? [Y/n]")
                    if not allow: allow = "Y"
                    if allow[0].upper() != "Y":
                        sys.exit("Password change cancelled")
                print "\nChange password for " + loginName
                oldPw = getpass.getpass("ENTER CURRENT PASSWORD:")
                if oldHash != PasswordHash(oldPw):
                    sys.exit("Incorrect password.")
            newPw = getpass.getpass("Enter new password:")
            newPw2 = getpass.getpass("Re-enter new password:")
            if newPw != newPw2:
                sys.exit("New passwords do not match")
            pwDB[loginName] = [PasswordHash(newPw), accountName]
        pwDB.close()
        sys.exit("Finished.")
    elif sys.argv[1] == "server":
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
    elif sys.argv[1] == "testclient":
        sys.exit("Currently Disabled. Probably not needed and should be removed")
        if len(sys.argv) != 8:
            sys.exit(USAGE)
        loginName, loginPasswd, depositAccount, cert, playgroundAddr, playgroundPort = sys.argv[2:]
        playgroundPort = int(playgroundPort)
        if not os.path.exists(cert):
            sys.exit("Could not locate cert file " + cert)
        with open(cert) as f:
            cert = X509Certificate.loadPEM(f.read())
        clientFactory = PlaygroundOnlineBankClient(cert, loginName, loginPasswd)
        client = playground.network.client.ClientBase(playground.network.common.PlaygroundAddress(20151, 0, 1, 999))
        tester = ClientTest(depositAccount)
        client.runWhenConnected(lambda: tester.runTest(clientFactory, client, BANK_FIXED_PLAYGROUND_ADDR, BANK_FIXED_PLAYGROUND_PORT))
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
        client.connectToChaperone(playgroundAddr, playgroundPort)
    else:
        sys.exit(USAGE)