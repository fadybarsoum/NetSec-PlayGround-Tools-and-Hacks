'''
Created on Mar 26, 2014

@author: sethjn
'''
from collections import OrderedDict
class ConfigFileParseError(Exception):
    def __init__(self, msg, filename, lineNo):
        super(ConfigFileParseError, self).__init__(self, msg)
        self.filename = filename
        self.lineNo = lineNo

class MalformedConfigFile(ConfigFileParseError):
    def __init__(self, msg, filename, lineNo):
        super(MalformedConfigFile, self).__init__(self, "Malformed Config File: " + msg, filename, lineNo)

class Parser(object):
    COMMENT_TOKENS = ['#', ';']
    WHITESPACE = [' ', '\t']
    SPLIT_TOKENS = [':','=']
    
    def __init__(self):
        self.reset()
        
    def reset(self):
        self.lineNumber = -1
        self.curSections = []
        self.curOption = None
        self.configData = OrderedDict()
        
    def removeComments(self, line):
        # Find the earliest instance of any comment token
        commentStart = None
        for cToken in self.COMMENT_TOKENS:
            cTokenFind = line.find(cToken)
            
            # if it's greater than -1, we've found one
            if cTokenFind > -1:
                # We require a whitespace before the comment
                if cTokenFind != 0 and line[cTokenFind-1] not in self.WHITESPACE:
                    continue
                
                # Only update if we haven't found one before or this new one is earlier
                if commentStart == None or cTokenFind < commentStart:
                    commentStart = cTokenFind
        if commentStart == None:
            return line
        return line[:commentStart]
    
    def __curSectionLevel(self):
        return len(self.curSections)
    
    def __getCurrentSection(self):
        section = self.configData
        for p in self.curSections:
            section = section[p]
        return section
        
    def __handleSection(self, line):
        sectionLevel = 0
        while line and line[0] == '=' and line[-1] == '=':
            sectionLevel += 1
            line = line[1:-1]
        if not line:
            raise MalformedConfigFile("Section Names Cannot be Empty", self.config_file_name, self.lineNumber)
        sectionName = line
        while self.__curSectionLevel() >= sectionLevel:
            self.curSections.pop(-1)
        if sectionLevel > self.__curSectionLevel() + 1:
            raise MalformedConfigFile("Section Name %s has Too Many Brackets" % sectionName, self.config_file_name, self.lineNumber)
        self.__getCurrentSection()[sectionName] = OrderedDict()
        self.curSections.append(sectionName)
        
    def __handleEntry(self, line):
        split = None
        for token in self.SPLIT_TOKENS:
            splitFind = line.find(token)
            if splitFind == -1: continue
            if split == None or splitFind < split:
                split = splitFind
        if split == None:
            if self.curOption:
                self.__getCurrentSection()[self.curOption] += line
            else:
                raise MalformedConfigFile("Line has not key/value split", self.config_file_name, self.lineNumber)
        k = line[:split].strip()
        v = line[split+1:].strip()
        self.__getCurrentSection()[k] = v
        self.curOption = k
            
    def parse(self, fp, name=None):
        self.reset()
        self.config_file_name = name and name or fp.name
        for line in fp.readlines():
            self.lineNumber += 1
            line = self.removeComments(line)
            line = line.strip()
            if not line: continue
            
            if line[0] == '=':
                self.__handleSection(line)
            else: self.__handleEntry(line)
        return self.configData