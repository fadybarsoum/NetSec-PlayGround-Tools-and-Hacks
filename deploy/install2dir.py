#!/usr/bin/python

import subprocess, sys, os, fnmatch, shutil

class InstallPlayground(object):
    # TODO: yes, I should use distutils. But don't have time this semester
    Manifest = [
                "%(srcRoot)s/README.md",
                "%(srcRoot)s/*.py",
                "%(srcRoot)s/src/playground.conf.sample",
                ]
    
    def __init__(self, srcRoot):
        self.srcRoot = os.path.abspath(srcRoot)
        srcFilters = map(lambda pattern: lambda name: fnmatch.fnmatch(name, pattern%{"srcRoot":self.srcRoot}), 
                         self.Manifest)
        self.srcFilter = lambda name: reduce(lambda x,y: x or y, 
                                             [filter(name) for filter in srcFilters], 
                                             False)
        
    def collectSources(self, **options):
        sources = []
        only=options.get("only",None)
        exclude=options.get("exclude",None)
        if only != None:
            only = only.split(",")
        if exclude != None:
            exclude = exclude.split(",")
        for dirpath, dirnames, fnames in os.walk(self.srcRoot):
            for fname in fnames:
                fqname = os.path.join(dirpath, fname)
                if not self.srcFilter(fqname): continue
                relname = os.path.relpath(fqname, self.srcRoot)
                if only != None: 
                    skip = True
                    for onlyPath in only:
                        if relname.startswith(onlyPath):
                            skip = False
                            break
                    if skip: continue 
                if exclude != None: 
                    skip = False
                    for excludePath in exclude:
                        if relname.startswith(excludePath): 
                            skip = True
                            break
                    if skip: continue
                sources.append(os.path.relpath(fqname, self.srcRoot))
        return sources
    
    def ensurePath(self, path, **options):
        if not os.path.exists(path):
            mode = options.get("mkdir_mode","770")
            mode = int(mode,8)
            if options.get("copymode","normal") == "dryrun":
                print "mkdir -p %s (%s)" % (path, oct(mode))
            else:
                os.makedirs(path, mode)
    
    def copy(self, relpath, src, dst, **options):
        relDir = os.path.dirname(relpath)
        dstDir = os.path.join(dst, relDir)
        srcFile = os.path.join(src, relpath)
        dstFile = os.path.join(dst, relpath)
        self.ensurePath(dstDir, **options)
        if options.get("copymode","normal") == "normal":
            shutil.copy2(srcFile, dstFile)
        elif options.get("copymode","normal") == "missing":
            if not os.path.exists(dstFile):
                shutil.copy2(srcFile, dstFile)
        elif options.get("copymode","normal") == "dryrun":
            print "cp %s %s" % (srcFile, dstFile)
        else:
            print "Unknown mode %s. Expected one of 'normal', 'missing', or 'dryrun'" % options['copymode']
    
    def toDir(self, installPath, **options):
        if not os.path.exists(installPath):
            raise Exception("Install path %s does not exist" % installPath)
        srcs = self.collectSources(**options)
        for relpath in srcs:
            self.copy(relpath, self.srcRoot, installPath, **options)

if __name__=="__main__":
    sourcedir, targetdir = sys.argv[1:3]
    options = {}
    for kvStr in sys.argv[3:]:
        k,v = kvStr.split("=")
        options[k] = v
    installer = InstallPlayground(sourcedir)
    installer.toDir(targetdir, **options)
    """
subprocess.call(["cp","-r","../src",targetdir])
if not os.path.exists(os.path.join(targetdir, "src", "playground.conf")):
    subprocess.call(["cp",os.path.join(targetdir, "src", "playground.conf.sample"),os.path.join(targetdir, "src", "playground.conf")])
    """