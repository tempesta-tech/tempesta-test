#!/usr/bin/env python2

import sys
import imp

modules = ['unittest',
           'subprocess',
           'resource',
           'getopt',
           'httplib',
           'scapy',
           'json',
           'paramiko',
           're',
           'configparser',
           ]

all_present = True

absent = []

for module in modules:
    try:
        imp.find_module(module)
    except ImportError:
        print("Module '%s' does not installed" % module)
        absent.append(module)
        all_present = False

if all_present == False:
    print("Need to install modules:")
    for module in absent:
        print("\t%s" % module)
    sys.exit(1)

print("All required modules installed")
sys.exit(0)
