'''
Created on Mar 21, 2015

@author: sethjn
'''
from rpython.translator.sandbox.sandlib import SimpleIOSandboxedProc
from rpython.translator.sandbox.sandlib import VirtualizedSandboxedProc

class ExtensibleSandboxedProc(VirtualizedSandboxedProc, SimpleIOSandboxedProc):
    """
    This class allows for relatively easy extensions to the default pypy sandbox.
    
    For example, to change the sandbox to allow writing, use the virtualfileio
    module's WritelableRealFile to represent the file and modify do_ll_os__ll_os_open
    and do_ll_os__ll_os_write. Currently, open only opens read only and write
    only handles writing between the python processes.
    
    Note, in general, when you modify one of these syscall handlers, you should
    be call the super's method if it isn't something you are handling directly.
    For example, if you implement writing, you need to know if it's a file
    descriptor that you've opened for writing. If it is, do the write. If it
    isn't, call the super's write method. Why? Because many of these methods
    handle operations necessary to have the sandbox work. The write method is
    an example. 
    
    If you need to add a new "node" type, make sure you inherit from the appropriate
    node class. Most of the time, it is RealFile but directories inherit from 
    a directory class. See virtualfileio module and the pypy code for more details
    """
    def __init__(self, arguments, executable):
        super(ExtensibleSandboxedProc, self).__init__(arguments, executable=executable)
        
        ### these are set in the VirtualizedSandboxedProc class
        ### May be used in altering your sandbox
        
        self.virtual_env = {}  # Used for the env related syscalls (e.g., getenv)
        self.virtual_cwd = '/tmp' # Used for virtual file system current working dir.
        self.virtual_fd_range = range(3, 50) # File descriptor range. Used in "allocated_fds"
        
        # The following is inherited from VirtualizedSandboxedProc
        # self.open_fds = {}   # {virtual_fd: (real_file_object, node)}
        # All open virtual files are stored here
        # used by the get_file method
    
    def do_ll_os__ll_os_open(self, name, flags, mode):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_open(name, flags, mode)
        
    def do_ll_os__ll_os_read(self, fd, size):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_read(fd, size)
        
    def do_ll_os__ll_os_write(self, fd, data):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_write(fd, data)
        
    def do_ll_os__ll_os_envitems(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_envitems()

    def do_ll_os__ll_os_getenv(self, name):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_getenv(name)

    def translate_path(self, vpath):
        ## Probably does not need to be overwritten, but useful for debugging
        return super(ExtensibleSandboxedProc, self).translate_path(vpath)
    
    ## Do not overwrite these without understanding code in sandlib.py, especially resulttype
    # def do_ll_os__ll_os_stat(self, node):
    # def do_ll_os__ll_os_lstat(self, node):
    # def do_ll_os__ll_os_fstat(self, fd):
    # def do_ll_os__ll_os_lseek(self, fd, pos, how):
    
    def do_ll_os__ll_os_access(self, vpathname, mode):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_access(vpathname, mode)

    def do_ll_os__ll_os_isatty(self, fd):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_isatty(fd)

    def allocate_fd(self, f, node=None):
        ## Probably does not require modification, but useful for debugging
        return super(ExtensibleSandboxedProc, self).allocate_fd(f, node)

    def get_fd(self, fd, throw=True):
        ## Probably does not require modification, but useful for debugging
        return super(ExtensibleSandboxedProc, self).get_fd(fd, throw)
    
    def get_file(self, fd, throw=True):
        return super(ExtensibleSandboxedProc, self).get_file(fd, throw)

    def do_ll_os__ll_os_close(self, fd):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_close(fd)

    def do_ll_os__ll_os_getcwd(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_getcwd()

    def do_ll_os__ll_os_strerror(self, errnum):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_strerror(errnum)

    def do_ll_os__ll_os_listdir(self, vpathname):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_listdir(vpathname)

    def do_ll_os__ll_os_getuid(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_getuid()
    
    def do_ll_os__ll_os_geteuid(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_geteuid()

    def do_ll_os__ll_os_getgid(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_getgid()
    
    def do_ll_os__ll_os_getegid(self):
        return super(ExtensibleSandboxedProc, self).do_ll_os__ll_os_getegid()