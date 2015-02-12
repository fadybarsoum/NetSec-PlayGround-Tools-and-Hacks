#!/usr/bin/python

import subprocess, sys, os

targetdir = sys.argv[1]
subprocess.call(["cp","-r","../src",targetdir])
if not os.path.exists(os.path.join(targetdir, "src", "playground.conf")):
    subprocess.call(["cp",os.path.join(targetdir, "src", "playground.conf.sample"),os.path.join(targetdir, "src", "playground.conf")])
