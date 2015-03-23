'''
Created on Mar 21, 2015

@author: sethjn
'''
from rpython.translator.sandbox.vfs import RealFile
import os, stat

class BitField(object):
    def __init__(self, bitfield):
        self.__bf = bitfield

    def __contains__(self, b):
        return self.hasBit(b)

    def __iter__(self):
        return self.getBits()

    def hasBit(self, b):
        if b == 0 and self.__bf != 0:
            return False
        return (b&self.__bf) == b

    def hasBits(self, *bs):
        for b in bs:
            if b in self: return False
        return True

    def getBits(self):
        if self.__bf == 0:
            yield 0
        else:
            c = self.__bf
            cb = 1
            while c > 0:
                if (c & 1): yield cb
                cb = cb << 1
                c = c >> 1

    def __str__(self):
        return " | ".join(map(str, list(self.getBits())))

class NamedBitField(BitField):
    def __init__(self, bitfield, nameDictionary):
        super(NamedBitField, self).__init__(bitfield)
        self.__d = nameDictionary

    def getBitAsString(self, b):
        return self.__d.get(b, "")

    def __str__(self):
        return " | ".join(map(self.__d.get, self.getBits()))
    

class FileUtil(object):
    O_FLAG_STRINGS = {
                      os.O_APPEND:"APPEND",
                      os.O_ASYNC:"ASYNC",
                      os.O_CREAT:"CREATE",
                      os.O_DIRECTORY:"DIRECTORY",
                      os.O_DSYNC:"DSYNC",
                      os.O_EXCL:"EXCL",
                      os.O_NDELAY:"NDELAY",
                      os.O_NOCTTY:"NOCTTY",
                      os.O_NOFOLLOW:"NOFOLLOW",
                      os.O_NONBLOCK:"NONBLOCK",
                      os.O_RDONLY:"READ ONLY",
                      os.O_RDWR:"READ/WRITE",
                      os.O_SYNC:"SYNC",
                      os.O_TRUNC:"TRUNC",
                      os.O_WRONLY:"WRITE ONLY"
                      }
    if hasattr(os, "O_EXLOCK"):
        O_FLAG_STRINGS[os.O_EXLOCK] = "EXLOCK"
    if hasattr(os, "O_SHLOCK"):
        O_FLAG_STRINGS[os.O_SHLOCK] = "SHLOCK"

    @classmethod
    def OFlags(cls, bitfield):
        return NamedBitField(bitfield, cls.O_FLAG_STRINGS)

    S_FLAG_STRINGS = {
                        stat.S_ENFMT:"ENFMT",
                        stat.S_IEXEC:"IEXEC",
                        stat.S_IFBLK:"IFBLK",
                        stat.S_IFCHR:"IFCHR",
                        stat.S_IFDIR:"IFDIR",
                        stat.S_IFIFO:"IFIFO",
                        stat.S_IFLNK:"IFLNK",
                        stat.S_IFREG:"IFREG",
                        stat.S_IFSOCK:"IFSOCK",
                        stat.S_IREAD:"IREAD",
                        stat.S_IRGRP:"IRGRP",
                        stat.S_IROTH:"IROTH",
                        stat.S_IRUSR:"IRUSR",
                        stat.S_IRWXG:"IRWXG",
                        stat.S_IRWXO:"IRWXO",
                        stat.S_IRWXU:"IRWXU",
                        stat.S_IWGRP:"IWGRP",
                        stat.S_IWOTH:"IWOTH",
                        stat.S_IWRITE:"IWRITE",
                        stat.S_IWUSR:"IWUSR",
                        stat.S_IXGRP:"IXGRP",
                        stat.S_IXOTH:"IXOTH",
                        stat.S_IXUSR:"IXUSR",
                        stat.S_ISUID:"ISUID",
                        stat.S_ISVTX:"ISVTX"
                        }
    @classmethod
    def SFlags(cls, bitfield):
        return NamedBitField(bitfield, cls.S_FLAG_STRINGS)

class WriteableRealFile(RealFile):
    @staticmethod
    def getOpenModeString(flags):
        if os.O_RDONLY in flags:
            return "rb"
        elif os.O_WRONLY in flags and os.O_TRUNC in flags:
            return "wb"
        elif os.O_WRONLY in flags:
            return "ab"
        elif os.O_RDWR in flags and os.O_TRUNC in flags:
            return "wb+"
        elif os.O_RDWR in flags:
            return "ab+"
        return "rb"

    def __init__(self, path):
        super(WriteableRealFile, self).__init__(path)
        self.mode = "<unopened>"

    def __repr__(self):
        return '<RealFile %s %s>' % (self.path,self.mode)

    def open(self, flags, mode):
        try:
            oFlags = FileUtil.OFlags(flags)
            self.mode = WriteableRealFile.getOpenModeString(oFlags)
            f =  open(self.path, self.mode)
            if not os.O_RDONLY in oFlags:
                self.read_only = False
            return f
        except IOError, e:
            raise OSError(e.errno, "open failed")