'''
Created on Apr 13, 2016

@author: sethjn
'''

import os, time, logging, subprocess
logger = logging.getLogger(__name__)

sandboxdir = os.path.realpath(os.path.dirname(__file__))

class SandboxCodeRunner(object):
    INTERACT_FILE = os.path.join(sandboxdir, "pypy_interact_x.py")
    PYPY_TEMPLATE = "pypy %(interact)s --tmp=%(tmp)s /usr/lib/pypy-sandbox/pypy-c-sandbox %(script)s"
    
    def __generatePypyCmd(self, scriptCmd):
        args = {"interact":self.INTERACT_FILE,
                "tmp":self.__tmpDir,
                "script":scriptCmd
                }
        return self.PYPY_TEMPLATE % args
    
    def __init__(self, tmpDir="/tmp", timeout=0):
        self.__tmpDir = tmpDir
        self.__timeout = timeout
        
    def __call__(self, codestring):
        s = codestring
        termTag = "MARK_"+os.urandom(5).encode('hex')
        filenameBase = "mobilecode_%s" % str(time.time()).replace(".","_")
        filename = filenameBase + ".py"
        logger.info("Creating mobile code file %s with %d bytes." % (filename, len(s)))
        mcfile = os.path.join(self.__tmpDir, filename)
        with open(mcfile, "wb+") as f:
            f.write(s)
        #resultFilename = filenameBase + ".result.txt"
        #exceptionFilename = filenameBase + ".execption.txt"
        exeCode = ""
        exeCode += "import sys\n"
        exeCode += "sys.path.insert(0,'/bin/site-packages')\n"
        exeCode += "import pickle, os, traceback\n"
        exeCode += "sys.path.append('/tmp/')\n"
        exeCode += "resultStr, exceptionStr = '', ''\n"
        exeCode += "try:\n"
        exeCode += "\tfrom %s import result\n" % filenameBase
        exeCode += "\tresultStr = pickle.dumps(result)\n"
        exeCode += "except Exception,e:\n"
        exeCode += "\twrap_e = Exception(traceback.format_exc(limit=20))\n"
        exeCode += "\texceptionStr = pickle.dumps(wrap_e)\n"
        #exeCode += "f = open('%s','w+')\n" % os.path.join("/tmp",resultFilename)
        exeCode += "print '"+termTag+"RESULT: %d' % len(resultStr)\n"
        exeCode += "print resultStr\n"#f.write(resultStr)\n"
        #exeCode += "f.close()\n"
        #exeCode += "f = open('%s', 'w+')\n" % os.path.join("/tmp",exceptionFilename)
        #exeCode += "print 'EXCEPTION: %d' % len(execptionStr)\n"
        exeCode += "print exceptionStr\n"#"f.write(exceptionStr)\n"
        #exeCode += "f.close()\n"
        executer = os.path.join(self.__tmpDir, "exeMobileCode.py")
        with open(executer, 'w+') as f:
            f.write(exeCode)
        logger.debug("Created exeMobileCode.py with the following contents: %s" % exeCode)
        cmd = self.__generatePypyCmd("exeMobileCode.py")
        if self.__timeout:
            cmd += " --timeout=%d" % (self.__timeout)
        logger.info("Executing pypy cmd: %s" % cmd)
        try:
            rawResult = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)#os.system(cmd)
        except Exception, e:
            pass
        finally:
            os.system("rm -f %s" % mcfile)
            os.system("rm -f %s" % executer)
        resultStart = rawResult.find(termTag)
        logger.debug("Skipping pre-result output: " + rawResult[:resultStart])
        rawResult = rawResult[resultStart:]
        firstLinePos = rawResult.find("\n")
        firstLine, rawResult = rawResult[:firstLinePos], rawResult[firstLinePos+1:]
        resultLen = int(firstLine.split(":")[1].strip())
        resultData, exceptionData = rawResult[:resultLen], rawResult[resultLen+1:]
        resultData = resultData.strip()
        exceptionData = exceptionData.strip()
        logger.info("Got result: " + resultData)
        logger.info("Got exception: " + exceptionData)
        """if not os.path.exists(os.path.join(self.__tmpDir, exceptionFilename)):
            logger.error("The executed code did not produce an execption output. This is a serious internal error.")
            raise Exception("Script failed. No exception data")
            #return str(error), pickle.dumps(error), "", ""
        with open(os.path.join(self.__tmpDir, exceptionFilename)) as f:
            exceptionData = f.read()
            if exceptionData:
                logger.info("The executed code returned an exception. Pickled data is: %s" % exceptionData)
                return ("", exceptionData, "", "")
        if not os.path.exists(os.path.join(self.__tmpDir, resultFilename)):
            logger.error("There was not an exception, but the executed code did not produce a result. This is a serious internal error.")
            raise Exception("Script failed. No result data")
            #return str(error), pickle.dumps(error), "", ""
        with open(os.path.join(self.__tmpDir, resultFilename)) as f:
            resultData = f.read()
            logger.info("The executed code produced a result. Returning pickle of size %d" % (len(resultData),))"""
        return ("", "", "", resultData)