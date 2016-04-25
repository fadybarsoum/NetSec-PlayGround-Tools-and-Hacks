'''
Created on Apr 13, 2016

@author: sethjn
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message import MessageData
from playground.network.common import SimpleMessageHandlingProtocol
from playground.crypto import X509Certificate
from playground.network.client.ClientApplicationServer import ClientApplicationServer,\
    ClientApplicationClient
from playground.network.common import Timer
from playground.network.common.PlaygroundAddress import PlaygroundAddress
from utils.ui import CLIShell, stdio

from twisted.internet import defer
from twisted.python.failure import Failure

import shelve, os
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class N2PSet(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.network.N2P.SET"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Name",STRING),
            ("Address",STRING),
            ("Unset",BOOL1),
            ("NameCertChain",LIST(STRING),DEFAULT_VALUE([])),
            ("AddrCertChain",LIST(STRING),DEFAULT_VALUE([])),
            ("NameSignature",STRING,DEFAULT_VALUE("")),
            ("AddrSignature",STRING,DEFAULT_VALUE(""))
            ]

class N2PSetResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.network.N2P.SET_RESPONSE"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Name",STRING),
            ("Address",STRING),
            ("Result",STRING)]

class N2PGet(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.network.N2P.GET"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Name",STRING)
            ]
    
class N2PGetResponse(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "apps.network.N2P.GET_RESPONSE"
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("Name",STRING),
            ("Address",STRING),
            ("Authoritative",BOOL1)
            ]
    
class N2PServerProtocol(SimpleMessageHandlingProtocol):
    SET_SUCCESSFUL = "SET_SUCCESSFUL"
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        rootfile = factory.getRootCert()
        with open(rootfile) as f:
            self.__root = f.read()
        self.registerMessageHandler(N2PSet, self.__setHandler)
        self.registerMessageHandler(N2PGet, self.__getHandler)
        
    def __verifyChain(self, chain):
        curCert = chain[0]
        for cert in chain[1:]:
            if curCert.getIssuer() != cert.getSubject():
                return False, "Issuer Mismatch %s v %s" % (curCert.getIssuer(), cert.getSubject())
            if cert == chain[-1]:
                continue
            certCN = cert.getSubject()["commonName"]
            if certCN[-1] != ".": certCN = certCN + "."
            if not curCert.getSubject()["commonName"].startswith(certCN):
                return False, "Name prefix mismatch %s v %s" % (curCert.getSubject()["commonName"], certCN)
            curCert = cert
        return True, ""
    
    def __getOrgChain(self, certs):
        orgs = []
        for cert in certs:
            certOrg = cert.getSubject()["organizationName"]
            if (not orgs) or (orgs[-1] != certOrg):
                orgs.append(certOrg)
        return orgs
        
    def __verifySet(self, name, address, nameCertChain, addrCertChain):
        # first, verify that address is the same as addrCertChain[0].commonName
        if address != addrCertChain[0].getSubject()["commonName"]:
            return False, "Invalid Address. Does not match cert"
        if name != nameCertChain[0].getSubject()["commonName"]:
            return False, "Invalid Name. Does not match cert"
        # second, verify that addrCertChain verifies correctly back to root
        res, resMsg = self.__verifyChain(addrCertChain)
        if not res:
            return res, resMsg
        # third, verify that nameCertChain verified correctly back to root
        res, resMsg = self.__verifyChain(nameCertChain)
        if not res:
            return res, resMsg
        # fourth, ensure that the organization chain is identical
        addrOrgs = self.__getOrgChain(addrCertChain)
        nameOrgs = self.__getOrgChain(nameCertChain)
        if addrOrgs != nameOrgs:
            return False, "Org chains do not match. Addr Orgs = %s, Name Orgs = %s" % (addrOrgs, nameOrgs)
        return True, ""
    
    def __verifySignature(self, data, signature, cert):
        publicKey = RSA.importKey(cert.getPublicKeyBlob())
        rsaVerifier = PKCS1_v1_5.new(publicKey)
        return rsaVerifier.verify(SHA256.new(data), signature)
    
    def __setHandler(self, protocol, msg):
        msgObj = msg.data()
        mb = MessageData.GetMessageBuilder(N2PSetResponse)
        mb["Address"].setData(msgObj.Address)
        mb["Name"].setData(msgObj.Name)
        if msgObj.AddrCertChain:
            if msgObj.AddrCertChain[-1] != self.__root:
                msgObj.AddrCertChain.append(self.__root)
            if msgObj.NameCertChain[-1] != self.__root:
                msgObj.NameCertChain.append(self.__root)
            addrCertChain = map(X509Certificate.loadPEM, msgObj.AddrCertChain)
            nameCertChain = map(X509Certificate.loadPEM, msgObj.NameCertChain)
            if not self.__verifySignature(msgObj.Address, msgObj.AddrSignature, addrCertChain[0]):
                result, resultMsg = False, "Address is not signed by a valid cert"
            elif not self.__verifySignature(msgObj.Name, msgObj.NameSignature, nameCertChain[0]):
                result, resultMsg = False, "Name is not signed by a valid cert"
            else:
                result, resultMsg = self.__verifySet(msgObj.Name, msgObj.Address, 
                                                     nameCertChain, addrCertChain)
            if not result:
                mb["Result"].setData(resultMsg)
                self.transport.writeMessage(mb)
                return
            authoritative = True
        else:
            authoritative = False
        res, resMsg = self._factory.registerNameToAddress(msgObj.Name, msgObj.Address, authoritative, msgObj.Unset)
        if not res:
            mb["Result"].setData(resMsg)
        else:
            mb["Result"].setData(self.SET_SUCCESSFUL)
        self.transport.writeMessage(mb)
        
    def __getHandler(self, protocol, msg):
        msgObj = msg.data()
        mb = MessageData.GetMessageBuilder(N2PGetResponse)
        mb["Name"].setData(msgObj.Name)
        address, authoritative = self._factory.resolveNameToAddress(msgObj.Name)
        mb["Address"].setData(address)
        mb["Authoritative"].setData(authoritative)
        self.transport.writeMessage(mb)
        
class N2PServer(ClientApplicationServer):
    DEFAULT_SERVING_PORT = 1
    Protocol = N2PServerProtocol
    def __init__(self, rootCertFilename, dbFilename):
        self.__dbFilename = dbFilename
        self.__rootCert = rootCertFilename
        #self.__db = shelve.open(dbFilename)
        
    def getRootCert(self):
        return self.__rootCert
        
    def registerNameToAddress(self, name, address, authoritative, unset):
        db = shelve.open(self.__dbFilename)
        res = (True, "")
        if unset:
            storedAddress, storedAuthoritative = db.get(name,("",False))
            if storedAddress != address:
                res = (False, "Name-2-Playground Address data did not match %s, %s for %s" % (storedAddress, address, name))
            elif storedAuthoritative and not authoritative:
                res = (False, "Cannot unauthoritatively unset authoritative data")
            else:
                del db[name]
        else:
            db[name] = (address, authoritative)
        db.close()
        return res
            
    def resolveNameToAddress(self, name):
        db = shelve.open(self.__dbFilename)
        addr, authoritative = db.get(name,("",False))
        db.close()
        return addr, authoritative
    
class N2PClientProtocol(SimpleMessageHandlingProtocol):
    def __init__(self, factory, addr):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.registerMessageHandler(N2PSetResponse, self.__handleSetResponse)
        self.registerMessageHandler(N2PGetResponse, self.__handleGetResponse)
        self.__connected = False
        self.__connD = defer.Deferred()
        self.__setD = {}
        self.__getD = {}
        
    def connectionMade(self):
        SimpleMessageHandlingProtocol.connectionMade(self)
        self.__connected = True
        self.__connD.callback(True)
        self.__connD = None
        
    def waitForConnection(self):
        if self.__connected:
            d = defer.Deferred()
            self.callLater(.1, lambda: d.callback(True))
            return d
        return self.__connD
    
    def set(self, name, addr, nameCerts, addrCerts, nameSig, addrSig, unset=False):
        if not self.__connected:
            errD = defer.Deferred()
            self.callLater(.1, lambda: errD.errback(Exception("set called before connect")))
            return errD
        if self.__setD.has_key((name, addr)):
            errD = defer.Deferred()
            self.callLater(.1, lambda: errD.errback(Exception("set called on same key before completion")))
            return errD
        self.__setD[(name,addr)] = defer.Deferred()
        mb = MessageData.GetMessageBuilder(N2PSet)
        mb["Name"].setData(name)
        mb["Address"].setData(addr)
        mb["NameCertChain"].setData(nameCerts)
        mb["AddrCertChain"].setData(addrCerts)
        mb["NameSignature"].setData(nameSig)
        mb["AddrSignature"].setData(addrSig)
        mb["Unset"].setData(unset)
        self.transport.writeMessage(mb)
        return self.__setD[(name,addr)]
    
    def __handleSetResponse(self, protocol, msg):
        msgObj = msg.data()
        if not self.__setD.has_key((msgObj.Name, msgObj.Address)):
            return
        d = self.__setD[(msgObj.Name, msgObj.Address)]
        del self.__setD[(msgObj.Name, msgObj.Address)]
        d.callback(msgObj.Result)
    
    def get(self, name):
        if not self.__connected:
            errD = defer.Deferred()
            self.callLater(.1, lambda: errD.errback(Exception("set called before connect")))
            return errD
        if self.__getD.has_key(name):
            errD = defer.Deferred()
            self.callLater(.1, lambda: errD.errback(Exception("duplicate lookup before completion")))
            return errD
        self.__getD[name] = defer.Deferred()
        mb = MessageData.GetMessageBuilder(N2PGet)
        mb["Name"].setData(name)
        self.transport.writeMessage(mb)
        return self.__getD[name]
    
    def __handleGetResponse(self, protocol, msg):
        msgObj = msg.data()

        if not self.__getD.has_key(msgObj.Name):
            return
        d = self.__getD[msgObj.Name]
        del self.__getD[msgObj.Name]
        d.callback((msgObj.Address, msgObj.Authoritative))
        
class N2PClient(ClientApplicationClient):
    Protocol = N2PClientProtocol
        
class ResolvingConnector(object):
    def __init__(self, clientBase, n2pServerAddr, requireAuthoritative=False):
        self.__clientBase = clientBase
        self.__n2pServerAddr = n2pServerAddr
        self.__requireAuthoritative = requireAuthoritative
        self.__trueConnectD = defer.Deferred()
        
    def connect(self, factory, name, port, connectionType="RAW"):
        name = str(name) # force to a string in case we're accidentally given an addr
        try:
            pAddr = PlaygroundAddress.FromString(name)
        except:
            pAddr = None
        self.__trueConnectD = defer.Deferred()
        trueConnect = lambda address: self.__trueConnectD.callback(self.__clientBase.connect(factory, address, port, connectionType))
        if not pAddr:
            srcport, self.__resolver = self.__clientBase.connect(N2PClient(), 
                                                 self.__n2pServerAddr, N2PServer.DEFAULT_SERVING_PORT,
                                                 "SECURE_STREAM")
            d = self.__resolver.waitForConnection()
            d.addCallback(lambda result: self.__resolverConnected(name, trueConnect))
            d.addErrback(self.__resolverConnectFailed)
        else:
            Timer.callLater(.1,lambda: self.__trueConnectD.callback(name))       
        return self.__trueConnectD
        
    def __resolverConnected(self, nameToResolve, trueConnect):
        d = self.__resolver.get(nameToResolve)
        d.addCallback(lambda result: self.__resolverFinished(nameToResolve, result[0], result[1], trueConnect))
        d.addErrback(self.__resolverFinishFailure)
        
    def __resolverConnectFailed(self, failure):
        if self.__resolver.transport:
            self.__resolver.transport.loseConnection()
        return self.__trueConnectD.errback(failure)
        
    def __resolverFinished(self, name, address, authoritative, trueConnect):
        if not address:
            raise Exception("Could not resolve '%s'" % name)
        if not authoritative and self.__requireAuthoritative:
            raise Exception("Could not resolve '%s' authoritatively" % name)
        if self.__resolver.transport:
            self.__resolver.transport.loseConnection()
        trueConnect(PlaygroundAddress.FromString(address))
        
    def __resolverFinishFailure(self, failure):
        if self.__resolver.transport:
            self.__resolver.transport.loseConnection()
        return self.__trueConnectD.errback(failure)
        
class N2PClientCLI(CLIShell):
    def __init__(self, n2pClient):
        CLIShell.__init__(self, prompt="%s::n2p> " % n2pClient.transport.getPeer().host)
        self.__client = n2pClient
        setCommandHandler = CLIShell.CommandHandler("set", "Set the name-to-playground mapping",
                                                    mode=CLIShell.CommandHandler.STANDARD_MODE)
        setCommandHandler.configure(2, self.__set, usage="[name] [address]",
                                    helpTxt="Set name-to-playground mapping (Non-authoritative)")
        setCommandHandler.configure(4, self.__set, usage="[name] [address] [certs_dir] [keys_dir]",
                                    helpTxt="Set the authoritative name-to playground mapping. " +
                                    "The certs_dir MUST have all of the certificates required " +
                                    "for building both chains and the keys_dir MUST have the " +
                                    "both keys. Files in these directories MUST be named " + 
                                    "CN_signed.cert for certs, where CN is the commonName. " +
                                    "Keys must be named CN.key. The chains will " +
                                    "be constructed automatically from these directories.")
        unsetCommandHandler = CLIShell.CommandHandler("unset", "Unset a name-to-playground mapping",
                                                    mode=CLIShell.CommandHandler.STANDARD_MODE)
        unsetCommandHandler.configure(2, self.__unset, usage="[name] [address]",
                                    helpTxt="Unset name-to-playground mapping (Non-authoritative)")
        unsetCommandHandler.configure(4, self.__unset, usage="[name] [address] [certs_dir] [keys_dir]",
                                    helpTxt="Unset the authoritative name-to playground mapping. " +
                                    "If the set was authoritative, it cannot be unset without " +
                                    "verified authoritative information.")
        getCommandHandler = CLIShell.CommandHandler("get", "Get a name-to-playground resolution",
                                                    mode=CLIShell.CommandHandler.STANDARD_MODE)
        getCommandHandler.configure(1, self.__get, usage="[name]",
                                    helpTxt="Get an address resolution for a name.")
        
        self.registerCommand(setCommandHandler)
        self.registerCommand(getCommandHandler)
        self.registerCommand(unsetCommandHandler)
        self.__d = None
        
    def __generalFailure(self, e):
        self.transport.write("Got error: %s\n"%e)
        Timer.callLater(.1,self.shutdown)
        return Failure
    
    def quit(self, *args, **kargs):
        self.shutdown()
    
    def shutdown(self):
        try:
            self.__client.transport.loseConnection()
        except:
            pass
        self.transport.loseConnection()
        
    def __loadChain(self, cn, certDir):
        chain = []
        parts = cn.split(".")
        while parts:
            cnName = ".".join(parts)
            certName = os.path.join(certDir,"%s_signed.cert" % cnName)
            if os.path.exists(certName):
                with open(certName) as f:
                    chain.append(f.read())
            parts.pop(-1)
        return chain
    
    def __loadPrivateKey(self, cn, keyDir):
        keyName = os.path.join(keyDir,"%s.key"%cn)
        if os.path.exists(keyName):
            with open (keyName) as f:
                return f.read()
        raise Exception("could not load private key as file %s does not exist" % keyName)
    
    def __sign(self, field, privKey):
        privKey = RSA.importKey(privKey)
        rsaSigner = PKCS1_v1_5.new(privKey)
        return rsaSigner.sign(SHA256.new(field))
    
    def __set(self, writer, name, address, certsDir=None, keysDir=None):
        return self.__setUnset(writer, name, address, False, certsDir, keysDir)
    
    def __unset(self, writer, name, address, certsDir=None, keysDir=None):
        return self.__setUnset(writer, name, address, True, certsDir, keysDir)
    
    def __setUnset(self, writer, name, address, unset, certsDir=None, keysDir=None):
        try:
            PlaygroundAddress.FromString(address)
        except Exception, e:
            writer("Invalid address. %s\n" % e)
            return
        if certsDir or keysDir:
            if not certsDir or not keysDir:
                writer("Both name certs dir and keys dir must be specified.\n")
                return
            nameCertChain = self.__loadChain(name, certsDir)
            addrCertChain = self.__loadChain(address, certsDir)
            namePrivateKey = self.__loadPrivateKey(name, keysDir)
            addrPrivateKey = self.__loadPrivateKey(address, keysDir)
            plainname, plainaddress = name, address
            nameSig = self.__sign(name, namePrivateKey)
            addressSig = self.__sign(address, addrPrivateKey)
            writer("Sending Authoritative (Un)Set Request on %s::%s\n" % (plainname, plainaddress))
        else:
            nameCertChain = []
            addrCertChain = []
            nameSig = ""
            addressSig = ""
            writer("Sending Unauthoritative (Un)Set Request on %s::%s\n" % (name, address))
        self.__d = self.__client.set(name, address, nameCertChain, addrCertChain, nameSig, addressSig, unset)
        self.__d.addCallback(lambda result: self.__setResponse(writer, result))
        self.__d.addErrback(self.__generalFailure)
        
    def __setResponse(self, writer, result):
        if result == N2PServerProtocol.SET_SUCCESSFUL:
            writer("SET request SUCCEEDED.\n")
        else:
            writer("SET request FAILED: %s\n" % result)
        self.__d = None
            
    def __get(self, writer, name):
        self.__d = self.__client.get(name)
        self.__d.addCallback(lambda result: self.__getResponse(writer, name, result[0], result[1]))
        self.__d.addErrback(self.__generalFailure)
        
    def __getResponse(self, writer, name, address, authoritative):
        if not address:
            writer("Could not resolve '%s' to an address\n" % name)
        else:
            writer("RESOLVED '%s' to '%s' (Authoritative=%s)\n" % (name, address, authoritative))
        self.__d = None
        
    def lineReceived(self, line):
        if self.__d:
            if line.strip().lower() == "__break__":
                self.__d = None
                self.transport.write("Operation cancelled on client. Unknown server state.\n")
            else:
                self.transport.write("Cannot execute [%s]. Waiting for previous command to complete\n"%line)
                self.transport.write("Type: __break__ to return to shell (undefined behavior).\n")
            return (False, None)
        try:
            self.lineReceivedImpl(line)
            return (True, self.__d)
        except Exception, e:
            self.__generalFailure(e)
            return (False, None)
        
class N2PNodeControl(object):
    Name = "N2P"
    def __init__(self):
        self.__stdio = None
    
    def getStdioProtocol(self):
        return self.__stdio
    
    def processServer(self, clientBase, args):
        if len(args) == 2:
            rootCertFile, dbFile = args
            port = N2PServer.DEFAULT_SERVING_PORT
        elif len(args) == 3:
            rootCertFile, dbFile, port = args
            port = int(port)
        else:
            return (False, "Usage: N2PServer rootCertFile dbFile [port]")
        n2pServer = N2PServer(rootCertFile, dbFile)
        clientBase.listen(n2pServer, port, "SECURE_STREAM")
        return (True, "")
    
    def processClient(self, clientBase, args):
        if len(args) != 2:
            return (False, "Expected server address and port")
        serverAddr, serverPort = args
        serverAddr = PlaygroundAddress.FromString(serverAddr)
        serverPort = int(serverPort)
        srcport, p = clientBase.connect(N2PClient(), serverAddr, serverPort, "SECURE_STREAM")
        d = p.waitForConnection()
        d.addCallback(lambda result: self.__clientConnected(p))
        return (True,"")
        
    def __clientConnected(self, p):
        self.__stdio = N2PClientCLI(p)
        stdio.StandardIO(self.__stdio)
    
    def start(self, clientBase, args):
        if not args or args[0] not in ['client',  'server']:
            return (False, "N2P requires either 'client' or 'server' for first argument")
        if args[0] == "server":
            return self.processServer(clientBase, args[1:])
        else:
            return self.processClient(clientBase, args[1:])
    
    def stop(self):
        return (True, "")
    
control = N2PNodeControl()
Name = control.Name
start = control.start
stop = control.stop
getStdioProtocol = control.getStdioProtocol
        
if __name__=="__main__":
    import sys
    from PlaygroundNode import PlaygroundNode, StandaloneTask
    addr, chaperoneAddr = sys.argv[1:3]
    args = sys.argv[3:]
    runner = PlaygroundNode(PlaygroundAddress.FromString(addr), chaperoneAddr, 9090, standAlone=True)
    n2pModule = N2PNodeControl()
    tasks = []
    tasks.append(StandaloneTask(runner.startScript, [n2pModule, args]))
    runner.startLoop(*tasks)
        