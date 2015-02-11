'''
Created on Mar 27, 2014

@author: sethjn
'''

import playground, random, sys, os, getpass, pickle
from BankMessages import OpenSession, SessionOpen, BalanceRequest, TransferRequest, Close
from BankMessages import BalanceResponse, Receipt, LoginFailure, RequestFailure
from playground.network.message import MessageData
from CipherUtil import SHA, X509Certificate, RSA, PKCS1_v1_5

from playground.playgroundlog import logging, LoggingContext
logger = logging.getLogger(__file__)

from BankCore import Ledger, LedgerLine

from twisted.internet import defer

RANDOM_u64 = lambda: random.randint(0,(2**64)-1)

PasswordHash = lambda pw: SHA.new(pw).digest()

"""
Protocol
[c] -> [ob (server)] :: C sends openSession(login_name, password)
[c] <- [ob (server)] :: ob either closes connection or sends "OK"
[c] -> [ob (server)] :: C sends request
[c] <- [ob (server)] :: ob sends response + receipt
"""

class BankServerProtocol(playground.network.common.SimpleMessageHandlingProtocol):
    MIB_CURRENT_STATE = "CurrentState"
    
    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    def __init__(self, factory, addr, loginData, bank):
        playground.network.common.SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.__loginData = loginData
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0,
                           "AccountName":None}
        self.__state = self.STATE_UNINIT
        self.__bank = bank
        self.registerMessageHandler(OpenSession, self.__handleOpenSession)
        self.registerMessageHandler(BalanceRequest, self.__handleBalanceRequest)
        self.registerMessageHandler(TransferRequest, self.__handleTransferRequest)
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
    
    def __handleOpenSession(self, protocol, msg):
        if self.__state != self.STATE_UNINIT:
            return self.__error("Session already logged-in")
        msgObj = msg.data()
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        if not self.__loginData.has_key(msgObj.Login):
            return self.__error("Invalid Login")
        passwordHash, accountName = self.__loginData[msgObj.Login]
        if not passwordHash == msgObj.PasswordHash:
            return self.__error("Invalid Login")
        if not  accountName in self.__bank.getAccounts():
            return self.__error("Invalid Login")
        self.__connData["ServerNonce"] = RANDOM_u64()
        self.__connData["AccountName"] = accountName
        self.__state = self.STATE_OPEN
        response = MessageData.GetMessageBuilder(SessionOpen)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(self.__connData["ServerNonce"])
        response["Account"].setData(accountName)
        self.__state = self.STATE_OPEN
        self.transport.writeMessage(response)
    
    def __handleBalanceRequest(self, protocol, msg):
        msgObj = msg.data()
        if self.__state != self.STATE_OPEN:
            return self.__error("Session not logged-in", msgObj.RequestId)
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            return self.__error("Invalid connection data", msgObj.RequestId)
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            return self.__error("Invalid connection data", msgObj.RequestId)
        account = self.__connData["AccountName"]
        balance = self.__bank.getBalance(account)
        response = MessageData.GetMessageBuilder(BalanceResponse)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(msgObj.ServerNonce)
        response["RequestId"].setData(msgObj.RequestId)
        response["Balance"].setData(balance)
        self.transport.writeMessage(response)
        
    def __handleTransferRequest(self, protocol, msg):
        msgObj = msg.data()
        if self.__state != self.STATE_OPEN:
            return self.__error("Session not logged-in", msgObj.RequestId)
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            return self.__error("Invalid connection data", msgObj.RequestId)
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            return self.__error("Invalid connection data", msgObj.RequestId)
        account = self.__connData["AccountName"]
        dstAccount = msgObj.DstAccount
        if not dstAccount in self.__bank.getAccounts():
            return self.__error("Invalid destination account", msgObj.RequestId)
        amount = msgObj.Amount
        if amount < 0: 
            return self.__error("Invalid (negative) amount", msgObj.RequestId)
        if amount > self.__bank.getBalance(account):
            return self.__error("Insufficient Funds", msgObj.RequestId)
        result = self.__bank.transfer(account,dstAccount, amount, msgObj.Memo)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId)
        # Assume single threaded. The last transaction will still be the one we care about
        result = self.__bank.generateReceipt(dstAccount)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId)
        receipt, signature = result.value()
        response = MessageData.GetMessageBuilder(Receipt)
        response["ClientNonce"].setData(msgObj.ClientNonce)
        response["ServerNonce"].setData(msgObj.ServerNonce)
        response["RequestId"].setData(msgObj.RequestId)
        response["Receipt"].setData(receipt)
        response["ReceiptSignature"].setData(signature)
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
        
    def __errorCallbackWrapper(self, e, d):
        self.__error(e)
        d.errback(e)
        
    def __error(self, e):
        if self.__state != self.STATE_ERROR:
            self.__state = self.STATE_ERROR
            self.reportException(e)
            self.transport.loseConnection()
            
    def __reportErrorAsDeferred(self, e, closeConnection=True):
        d = defer.Deferred()
        # we need a call later so the client code has enough time to set the errback handler
        self.callLater(0,lambda: self.__errorCallbackWrapper(e, d))
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
            self.callLater(.1, lambda: d.callback(None))
        return d
        
    def loginToServer(self):
        if self.__deferred.has_key("CONNECTION"):
            # we haven't connected yet!
            raise Exception("Can't login. Connection not yet made.")
        if self.__state != self.STATE_UNINIT:
            return self.__reportErrorAsDeferred(Exception("Cannot login. State: %s" % self.__state))
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
            return self.__error(Exception("Unexpected Session Open Message. State is (%s)" % self.__state))
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error(Exception("Invalid internal state. No LOGIN deferred"))
        del self.__deferred["LOGIN"]
        
        msgObj = msg.data()
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return d.errback(Exception("Invalid Connection Data"))
        self.__connData["ServerNonce"] = msgObj.ServerNonce
        self.__account = msgObj.Account
        self.__state = self.STATE_OPEN
        d.callback(True)
        
    def __handleLoginFailure(self, protocol, msg):
        if self.__state != self.STATE_WAIT_FOR_LOGIN:
            return self.__error(Exception("Unexpected Session Open Message"))
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error(Exception("Invalid internal state. No LOGIN deferred"))
        del self.__deferred["LOGIN"]
        
        msgObj = msg.data()
        d.errback(Exception(msgObj.ErrorMessage))
        
    def getBalance(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportErrorAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        requestId, d = self.__nextRequestData()
        balanceMsg = MessageData.GetMessageBuilder(BalanceRequest)
        balanceMsg["ClientNonce"].setData(self.__connData["ClientNonce"])
        balanceMsg["ServerNonce"].setData(self.__connData["ServerNonce"])
        balanceMsg["RequestId"].setData(requestId)
        self.transport.writeMessage(balanceMsg)
        return d
    
    def __handleBalanceResponse(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error(Exception("Unexpected Request Response"))
        msgObj = msg.data()
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            return self.__error(Exception("Invalid internal state. No deferred for request %d" % msgObj.RequestId))
        del self.__deferred[msgObj.RequestId]
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return d.errback(Exception("Invalid Connection Data (ClientNonce)"))
        if msgObj.ServerNonce != self.__connData["ServerNonce"]:
            return d.errback(Exception("Invalid Connection Data (ServerNonce"))
        d.callback(msgObj.Balance)
        
    def transfer(self, dstAccount, amount, memo):
        if self.__state != self.STATE_OPEN:
            return self.__reportErrorAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        requestId, d = self.__nextRequestData()
        transferMsg = MessageData.GetMessageBuilder(TransferRequest)
        transferMsg["ClientNonce"].setData(self.__connData["ClientNonce"])
        transferMsg["ServerNonce"].setData(self.__connData["ServerNonce"])
        transferMsg["RequestId"].setData(requestId)
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
            closeMsg = MessageData.GetMessageBuilder(Close)
            closeMsg["ClientNonce"].setData(self.__connData["ClientNonce"])
            closeMsg["ServerNonce"].setData(self.__connData["ServerNonce"])
        
            self.transport.writeMessage(closeMsg)
            self.callLater(.1, self.transport.loseConnection)
        
    def __handleReceipt(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error(Exception("Unexpected Request Response"))
        msgObj = msg.data()
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            return self.__error(Exception("Invalid internal state. No deferred for request %d" % msgObj.RequestId))
        del self.__deferred[msgObj.RequestId]
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return d.errback(Exception("Invalid Connection Data (ClientNonce)"))
        if msgObj.ServerNonce != self.__connData["ServerNonce"]:
            return d.errback(Exception("Invalid Connection Data (ServerNonce"))
        if not self.__verifier.verify(SHA.new(msgObj.Receipt), msgObj.ReceiptSignature):
            return d.errback(Exception("Received a receipt with mismatching signature"))
        d.callback((msgObj.Receipt, msgObj.ReceiptSignature))
        
    def __handleRequestFailure(self, protocol, msg):
        if self.__state != self.STATE_OPEN:
            return self.__error(Exception("Unexpected Session Open Message"))
        msgObj = msg.data()
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            return self.__error(Exception("Invalid internal state. No deferred for request %d" % msgObj.RequestId))
        del self.__deferred[msgObj.RequestId]
        
        d.errback(Exception(msgObj.ErrorMessage))
        
class PlaygroundOnlineBank(playground.network.client.ClientApplicationServer.ClientApplicationServer):
    MIB_BALANCES = "BankBalances"

    def __init__(self, passwordData, bank):
        #super(PlaygroundOnlineBank, self).__init__(self)
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
    def __init__(self, depositAccount):
        self._count = 0
        self._deposit = depositAccount
        
    def runTest(self, clientFactory, client, addr, port):#protocol):
        protocol = client.openClientConnection(clientFactory, addr, port, connectionType="RAW")
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

USAGE = """
OnlineBank.py pw <passwordFile> <loginName> --delete
OnlineBank.py pw <passwordFile> <loginName> <accountName>
OnlineBank.py server <passwordFile> <bankpath> <cert> <playground server IP> <playground server port>
"""

BANK_FIXED_PLAYGROUND_ADDR = playground.network.common.PlaygroundAddress(20151, 0, 1, 1)

BANK_FIXED_PLAYGROUND_PORT = 700

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "help" or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        sys.exit(USAGE)
    if sys.argv[1] == "pw":
        if len(sys.argv) != 5:
            sys.exit(USAGE)
        pwfile, loginName, accountName = sys.argv[2:]
        if not os.path.exists(pwfile):
            lwData = {}
        else:
            with open(pwfile) as f:
                pData = f.read()
            try:
                lwData = pickle.loads(pData)
            except:
                sys.exit("%s is not a valid password file" % pwfile)
        #with open(pwfile, "w") as pwWriter:
        if accountName == "--delete":
            if not lwData.has_key(loginName):
                sys.exit("No such user login name: " + loginName)
            else:
                del lwData[loginName]
        else:
            if lwData.has_key(loginName):
                oldHash, oldAccountName = lwData[loginName]
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
            lwData[loginName] = [PasswordHash(newPw), accountName]
        pwfileContents = pickle.dumps(lwData)
        with open(pwfile, "w") as pwWriter:
            pwWriter.write(pwfileContents)
        sys.exit("Finished.")
    elif sys.argv[1] == "server":
        if len(sys.argv) != 7:
            sys.exit(USAGE)
        passwordFile, bankPath, cert, playgroundAddr, playgroundPort = sys.argv[2:]
        playgroundPort = int(playgroundPort)
        if not os.path.exists(passwordFile):
            sys.exit("Could not locate passwordFile " + passwordFile)
        with open(passwordFile) as f:
            pData = f.read()
            try:
                passwordData = pickle.loads(pData)
            except:
                sys.exit("Password file in incorrect format")
        if not os.path.exists(cert):
            sys.exit("Could not locate cert file " + cert)
        with open(cert) as f:
            cert = X509Certificate.loadPEM(f.read())
        ledgerPassword = getpass.getpass("Enter bank password:")
        bank = Ledger(bankPath, cert, ledgerPassword)
        bankServer = PlaygroundOnlineBank(passwordData, bank)
        client = playground.network.client.ClientBase(BANK_FIXED_PLAYGROUND_ADDR)
        client.installClientServer(bankServer, BANK_FIXED_PLAYGROUND_PORT, connectionType="RAW")
        
        logctx = LoggingContext()
        logctx.nodeId = "onlinebank_"+BANK_FIXED_PLAYGROUND_ADDR.toString()
        #logctx.doPacketTracing = True
        playground.playgroundlog.startLogging(logctx)
        
        client.connectToPlaygroundServer(playgroundAddr, playgroundPort)
    elif sys.argv[1] == "testclient":
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
        client.connectToPlaygroundServer(playgroundAddr, playgroundPort)