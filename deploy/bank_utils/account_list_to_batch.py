#!/usr/bin/python

import os, sys

inputfile, outputfile = sys.argv[1:3]
outputlines = []
with open(inputfile) as f:
  for line in f.readlines():
    line = line.strip()
    if not line: continue
    account, manager = line.split("\t")
    account_name = ""
    for letter in account:
      if letter.isalnum():
        account_name += letter
    if not account_name:
      print "could not get account_name for", account
      continue
    account_name = account_name.lower() + "1"
    user_name = ""
    name_parts = manager.split(" ")
    for letter in name_parts[0]:
      if letter.isalnum():
        user_name += letter
    if len(name_parts) > 1:
      user_name += name_parts[-1][0]
    user_name = user_name.lower()
    outputlines.append("account create " + account_name)
    outputlines.append("user create " + user_name)
    outputlines.append("access set %s * %s" % (user_name, account_name))
with open(outputfile,"w+") as f:
  for line in outputlines:
    f.write(line+"\n")

