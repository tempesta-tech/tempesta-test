#!/usr/bin/env python3

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2020 Tempesta Technologies, Inc."
__license__ = "GPL2"

import importlib.util
import sys

modules = [
    "unittest",
    "scapy",
    "Cryptodome",
    "tinyec",
    "subprocess",
    "resource",
    "getopt",
    "re",
    "json",
    "configparser",
]

modules_apt = [
    "paramiko",
    "subprocess32",
]


def make_report_line(name):
    filler_len = max(3, 20 - len(name))
    return "{} {}".format(name, "." * filler_len)


print("\tChecking for required python3 modules:")

all_present = True

absent = []

for module in modules:
    if module in sys.modules:
        print("\t\t{} found".format(make_report_line(module)))
    elif importlib.util.find_spec(module) is not None:
        print("\t\t{} found".format(make_report_line(module)))
    else:
        print("\t\t{} not found".format(make_report_line(module)))
        absent.append(module)
        all_present = False

package_list = []

for module in modules_apt:
    if module in sys.modules:
        print("\t\t{} found".format(make_report_line(module)))
    elif importlib.util.find_spec(module) is not None:
        print("\t\t{} found".format(make_report_line(module)))
    else:
        print("\t\t{} not found".format(make_report_line(module)))
        absent.append(module)
        package_list.append("python-%s" % module)
        all_present = False

if not all_present:
    print("\n\tMissing modules:")
    for module in absent:
        print("\t\t%s" % module)
    if len(package_list) > 0:
        print('\n\t\tRun "apt-get install %s"\n' % " ".join(package_list))
    sys.exit(1)

print("\n\tFound all required python modules.\n")
sys.exit(0)
