#!/usr/bin/env python2

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import sys
import imp

modules = ['unittest',
           'scapy',
           'Cryptodome',
           'tinyec',
           'subprocess',
           'resource',
           'getopt',
           'httplib',
           're',
           'json',
           ]

modules_apt = [
            'paramiko',
            'subprocess32',
            'configparser',
            ]


def make_report_line(name):
    filler_len = max(3, 20 - len(name))
    return '{} {}'.format(name, '.' * filler_len)


print("\tChecking for required python2 modules:")

all_present = True

absent = []

for module in modules:
    try:
        imp.find_module(module)
        print("\t\t{} found".format(make_report_line(module)))
    except ImportError:
        print("\t\t{} not found".format(make_report_line(module)))
        absent.append(module)
        all_present = False

package_list = []

for module in modules_apt:
    try:
        imp.find_module(module)
        print("\t\t{} found".format(make_report_line(module)))
    except ImportError:
        print("\t\t{} not found".format(make_report_line(module)))
        absent.append(module)
        package_list.append("python-%s" % module)
        all_present = False

if not all_present:
    print("\n\tMissing modules:")
    for module in absent:
        print("\t\t%s" % module)
    if len(package_list) > 0:
        print('\n\t\tRun "apt-get install %s"\n' % ' '.join(package_list))
    sys.exit(1)

print("\n\tFound all required python modules.\n")
sys.exit(0)
