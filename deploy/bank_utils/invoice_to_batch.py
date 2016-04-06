#!/usr/bin/python

import os,sys

batchfile = sys.argv[1]
invoiceFiles = sys.argv[2:]

d = {
"FROM":None,
"COMPANY":None,
"ACCOUNT":None,
"INVOICE":None,
"AMOUNT":None,
"DATE":None,
}
outputlines = []#["account switch illuminati"]
total = 0
for invoicefile in invoiceFiles:
  with open(invoicefile) as f:
    d_copy = {}
    d_copy.update(d)
    for line in f.readlines():
      line = line.strip()
      k,v = line.split(":")
      k = k.upper()
      if k == "DETAILS": break
      d_copy[k] = v
  if None in d_copy.values():
    print "Missing required filed in invoice %s" % invoicefile
    continue
  total += int(d_copy["AMOUNT"])
  memo = "Invoice #%s, submitted by %s on behalf of %s on %s" % (d_copy["INVOICE"], d_copy["FROM"], d_copy["COMPANY"], d_copy["DATE"])
  outputlines.append('account transfer %s %d "%s"' % (d_copy["ACCOUNT"], int(d_copy["AMOUNT"]), memo)) 
outputlines = ["account switch illuminati"] + outputlines
with open(batchfile, "w+") as f:
  for line in outputlines:
    f.write(line+"\n")

