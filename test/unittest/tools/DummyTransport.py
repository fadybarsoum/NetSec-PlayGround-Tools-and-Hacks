
class DummyTransportBase(object):
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        
    def write(self, buf):
        raise NotImplementedError("Must be instantiated by subclass")
        
    def writeMessage(self, msg):
        self.write(msg.serialize())
        
    def getHost(self):
        return self.src
    
    def getPeer(self):
        return self.dst

class DummyTransportToProtocol(DummyTransportBase):
    def __init__(self, src, dst, dstProtocol):
        DummyTransportBase.__init__(self, src, dst)
        self.dstProtocol = dstProtocol
        
    def write(self, buf):
        self.dstProtocol.dataReceived(buf)
    
class DummyTransportToStorage(DummyTransportBase):
    def __init__(self, src, dst):
        DummyTransportBase.__init__(self, src, dst)
        self.storage = []
        
    def write(self, buf):
        self.storage.append(buf)