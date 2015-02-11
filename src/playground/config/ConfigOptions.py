'''
Created on Mar 26, 2014

@author: sethjn
'''

from collections import OrderedDict

class ConfigOptions(object):
    NOT_SET = object()
    
    def __init__(self, rawDictionary, defaultDefault=None, name="", parent=None):
        self.__name = name
        self.__parent = parent
        self.__raw = OrderedDict()
        self.__defaults = {}
        self.__defaultDefault = defaultDefault
        for k,v in rawDictionary.items():
            if isinstance(v, OrderedDict):
                self.__raw[k] = ConfigOptions(v, self.__defaultDefault, name=k, parent=self)
            else: self.__raw[k] = v
            
    def toDictionaries(self):
        d = {}
        for k in self.__raw.keys():
            v = self.get(k)
            if isinstance(v, ConfigOptions):
                v = v.toDictionaries()
            d[k] = v
        return d
            
    def parentConfig(self):
        return self.__parent
    
    def sectionName(self, fullyQualified=False):
        if fullyQualified:
            parentName = self.__parent and (self.__parent.sectionName(fullyQualified)+".") or ""
            return parentName + self.__name
        return self.__name
        
    def setDefault(self, dottedKey, default):
        parts = dottedKey.split(".")
        section = ".".join(parts[:-1])
        sectionConfig = self.getSection(section)
        sectionConfig.__defaults[parts[-1]] = default
        
    def get(self, dottedKey, forceDefault=NOT_SET, raw=False):
        parts = dottedKey.split(".")
        myPart = parts[0]
        remainingKey = ".".join(parts[1:])
        if self.__raw.has_key(myPart):
            v = self.__raw[myPart]
            if not remainingKey: 
                if type(v) == str and not raw: return v % SafeStringFormatDictionary(self)
                return v
            if isinstance(v, ConfigOptions):
                return self.__raw[myPart].get(remainingKey, forceDefault)
        if forceDefault != ConfigOptions.NOT_SET:
            return forceDefault
        return self.__defaults.get(dottedKey, forceDefault)
    
    def getSection(self, dottedKey):
        parts = dottedKey.split(".")
        cur = self
        for p in parts:
            if not p: continue
            if not cur.__raw.has_key(p):
                cur.__raw[p] = ConfigOptions({})
            cur = cur.__raw[p]
            if not isinstance(cur, ConfigOptions):
                raise Exception("Key [%s] does not resolve to a section, but to an option" % dottedKey)
        return cur
    
    def has_key(self, dottedKey):
        # not very efficient...
        return dottedKey in self.keys()
    
    def keys(self, topLevelOnly=False):
        for k, v in self.__raw.items():
            if topLevelOnly or not isinstance(v, ConfigOptions):
                yield k
            else:
                for sk in v.keys():
                    yield k+"."+sk
    
    def values(self):
        for k in self.keys():
            yield self.get(k)
            
    def items(self):
        for k in self.keys():
            yield k,self.get(k)
    
    def dump(self):
        d = ""
        for k, v in self.items():
            d += "%s: %s\n" % (k, v)
        return d
    
    def __iter__(self):
        for k in self.keys():
            yield (k,self.get(k))
            
    def __setitem__(self, k, v):
        parts = k.split(".")
        sectionName = ".".join(parts[:-1])
        section = self.getSection(sectionName)

        section.__raw[parts[-1]] = v
    
    def __getitem__(self, k):
        return self.get(k)
    
    def __repr__(self):
        return "<ConfigOptions %d> (%s)" % (id(self), ", ".join(self.__raw.keys()))
    
class SafeStringFormatDictionary(object):
    def __init__(self, original):
        self.__original = original
        
    def __getitem__(self, k):
        checker = self.__original
        while checker != None:
            if checker.has_key(k):
                return checker.get(k, raw=True)
            checker = checker.parentConfig()
        return "%("+k+")s"
