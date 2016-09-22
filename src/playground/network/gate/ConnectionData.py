'''
Created on Sep 20, 2016

@author: sethjn
'''

from playground.config import GlobalPlaygroundConfigData
from playground.network.common import PlaygroundAddress
configData = GlobalPlaygroundConfigData.getConfig(__name__)

class ConnectionData(object):
    @classmethod
    def CreateFromConfig(cls, configKey=None, defaultKey=None):
        if not configKey:
            if not defaultKey:
                defaultKey = "default"
            configKey = configData[defaultKey]
        g2gConfig = configData.getSection(configKey)
        if not g2gConfig:
            raise Exception("Unknown gate configuration %s" % configKey)
        chaperoneAddr = g2gConfig["chaperone_IPaddr"]
        chaperonePort = g2gConfig["chaperone_TCPport"]
        gatePort = g2gConfig["gate_TCPport"]
        playgroundAddr = g2gConfig["playground_addr"]
        return cls(chaperoneAddr, chaperonePort, gatePort, playgroundAddr)
    
    def __init__(self, chaperoneAddr, chaperonePort, gatePort, gateAddr):
        self.chaperoneAddr = chaperoneAddr
        self.chaperonePort = int(chaperonePort)
        self.playgroundAddr = PlaygroundAddress.FromString(gateAddr)
        self.gatePort = int(gatePort)
        