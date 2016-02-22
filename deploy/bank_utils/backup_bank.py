#!/usr/bin/python

import os,sys,time

backupdirbase, pwdb, bankpath, bankkey, bankcert = sys.argv[1:6]
for pathName in sys.argv[1:6]:
  if not os.path.exists(pathName):
    sys.exit("NO such file/directory %s" %  pathName)
backupdir = backupdirbase+"/bank_back_%f" % time.time()
if os.path.exists(backupdir):
  sys.exit("Backup dir %s already exists" % backupdir)
os.system("mkdir %s" % backupdir)
if not os.path.exists(backupdir):
  sys.exit("Could not create  %s" % backupdir)

os.system("cp %s %s" % (pwdb, backupdir))
os.system("cp %s %s" % (bankkey, backupdir))
os.system("cp %s %s" % (bankcert, backupdir))
os.system("cp -r %s %s" % (bankpath, backupdir))

