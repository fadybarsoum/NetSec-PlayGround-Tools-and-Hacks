'''
Created on Mar 21, 2015

@author: sethjn
Copied with few modifications from pypy_interact.py (version 2.2.1)
'''
import sys, os
import pypy
sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(pypy.__file__), "sandbox")))
from rpython.translator.sandbox.vfs import Dir, RealDir, RealFile
LIB_ROOT = "/usr/lib/pypy"

from extensible_sandbox import ExtensibleSandboxedProc

class PyPySandboxedProc(ExtensibleSandboxedProc):
    argv0 = '/bin/pypy-c'
    virtual_console_isatty = True

    def __init__(self, executable, arguments, tmpdir=None, debug=True, extraPyPackages=None):
        self.executable = executable = os.path.abspath(executable)
        self.tmpdir = tmpdir
        self.debug = debug
        self.extraPyPackages = extraPyPackages and extraPyPackages or {}
        super(PyPySandboxedProc, self).__init__([self.argv0] + arguments,
                                                executable=executable)

    def build_virtual_root(self):
        # build a virtual file system:
        # * can access its own executable
        # * can access the pure Python libraries
        # * can access the temporary usession directory as /tmp
        exclude = ['.pyc', '.pyo']
        if self.tmpdir is None:
            tmpdirnode = Dir({})
        else:
            tmpdirnode = RealDir(self.tmpdir, exclude=exclude)
        libroot = str(LIB_ROOT)
        
        binDirData = {
                'pypy-c': RealFile(self.executable,  mode=011),
                'lib-python': RealDir(os.path.join(libroot, 'lib-python'),
                                      exclude=exclude),
                'lib_pypy': RealDir(os.path.join(libroot, 'lib_pypy'),
                                      exclude=exclude),
                }
        for vpath, realpath in self.extraPyPackages.items():
            binDirData[vpath] = RealDir(os.path.abspath(realpath), exclude=exclude)

        return Dir({
             'bin': Dir(binDirData),
             'tmp': tmpdirnode,
             })


def main():
    from getopt import getopt      # and not gnu_getopt!
    options, arguments = getopt(sys.argv[1:], 't:hv',
                                ['tmp=', 'heapsize=', 'timeout=', 'log=',
                                 'verbose', 'help'])
    tmpdir = None
    timeout = None
    logfile = None
    debug = False
    extraoptions = []

    def help():
        print >> sys.stderr, __doc__
        sys.exit(2)

    for option, value in options:
        if option in ['-t', '--tmp']:
            value = os.path.abspath(value)
            if not os.path.isdir(value):
                raise OSError("%r is not a directory" % (value,))
            tmpdir = value
        elif option == '--heapsize':
            value = value.lower()
            if value.endswith('k'):
                bytes = int(value[:-1]) * 1024
            elif value.endswith('m'):
                bytes = int(value[:-1]) * 1024 * 1024
            elif value.endswith('g'):
                bytes = int(value[:-1]) * 1024 * 1024 * 1024
            else:
                bytes = int(value)
            if bytes <= 0:
                raise ValueError
            if bytes > sys.maxint:
                raise OverflowError("--heapsize maximum is %d" % sys.maxint)
            extraoptions[:0] = ['--heapsize', str(bytes)]
        elif option == '--timeout':
            timeout = int(value)
        elif option == '--log':
            logfile = value
        elif option in ['-v', '--verbose']:
            debug = True
        elif option in ['-h', '--help']:
            help()
        else:
            raise ValueError(option)

    if len(arguments) < 1:
        help()

    xtraDir = os.path.join(os.path.dirname(__file__), "extra_py_packages")
    sandproc = PyPySandboxedProc(arguments[0], extraoptions + arguments[1:],
                                 tmpdir=tmpdir, debug=debug,
                                 extraPyPackages={"site-packages":xtraDir})
    if timeout is not None:
        sandproc.settimeout(timeout, interrupt_main=True)
    if logfile is not None:
        sandproc.setlogfile(logfile)
    try:
        sandproc.interact()
    finally:
        sandproc.kill()

if __name__ == '__main__':
    main()
