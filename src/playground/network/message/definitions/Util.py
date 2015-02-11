'''
Created on Oct 23, 2013

@author: sethjn
'''

def playgroundIdentifier(moduleName):
    moduleNameParts = moduleName.split(".")
    identifier = ""
    while len(moduleNameParts) > 0 and moduleNameParts[-1] != "playground":
        identifier = "." + moduleNameParts.pop(-1) + identifier
    identifier = "playground" + identifier
    return identifier