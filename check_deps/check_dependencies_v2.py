#!/usr/bin/env python2

import sys
import imp

modules = ['unittest',
           'subprocess',
           'resource',
           'getopt',
           'httplib',
           're',
           'json',
           ]

modules_apt = [
            'scapy',
            'paramiko',
            'subprocess32',
            'configparser',
            ]

print("Checking python2 modules")

all_present = True

absent = []

for module in modules:
    try:
        imp.find_module(module)
        print("\tModule '%s' is installed" % module)
    except ImportError:
        print("\tModule '%s' does not installed" % module)
        absent.append(module)
        all_present = False

install = []

for module in modules_apt:
    try:
        imp.find_module(module)
        print("\tModule '%s' is installed" % module)
    except ImportError:
        print("\tModule '%s' does not installed" % module)
        absent.append(module)
        install.append("python-%s" % module)
        all_present = False

if all_present == False:
    print("Need to install modules:")
    for module in absent:
        print("\t%s" % module)
    if len(install) > 0:
        ims = " ".join(install)
        print("\n\tRun apt-get install %s\n" % ims)
    sys.exit(1)

print("All required modules installed")
sys.exit(0)
