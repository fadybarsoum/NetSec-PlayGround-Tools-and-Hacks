"""
Unfortunately, the python standard configparser module doesn't have nested
sections. We need nested sections

We could use ConfigObj, but it's too late in the semester to have this be
a required module
"""

from Parser import Parser
from ConfigOptions import ConfigOptions
import os, sys

def LoadOptions(filename):
    p = Parser()
    f = open(filename)
    data = p.parse(f)
    f.close()
    return ConfigOptions(data)

def extractList(opt, key, default):
    v = opt.get(key, default)
    l = []
    for vx in v.split(","):
        vx = vx.strip()
        if not vx: continue
        l.append(vx)
    return l

class GlobalPlaygroundConfigData(object):
    CONFIG_DATA = None
    CONFIG_FILE_NAME = "playground.conf"
    
    @classmethod
    def getConfig(cls, sectionName):
        return cls.CONFIG_DATA.getSection(sectionName)
    
    @classmethod
    def LoadPlaygroundConfig(cls, orderedSearchDirs):
        
        for d in orderedSearchDirs:
            pathToConfig = os.path.join(d, cls.CONFIG_FILE_NAME)
            if os.path.exists(pathToConfig):
                cls.CONFIG_DATA = LoadOptions(pathToConfig)
                break
        if not cls.CONFIG_DATA:
            cls.CONFIG_DATA = ConfigOptions({})