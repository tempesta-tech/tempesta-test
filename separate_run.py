#! /usr/bin/python3

"""
    Separate runner - script written to avoid bug:
    filedescriptor out of range in select()
    https://github.com/secdev/scapy/issues/3696
"""

import os, sys
from subprocess import Popen

path = os.path.dirname(os.path.abspath(__file__))
cmd = path+'/run_tests.py -L'
out = os.popen(cmd).read()
test_groups = set()
results = {}

for test in out.split("\n")[1:]:
    if len(test.split(".")[0]) != 0:
        test_groups.add(test.split(".")[0])
for group in test_groups:
    _args= ' '.join(sys.argv[1:])
    cmd = f'./run_tests.py {_args} {group}'
    print("Run:", cmd)
    proc = Popen(cmd, shell=True)
    results[group] = proc.wait()

# If some tests fails
for value in results.values():
    if value != 0:
        print("Tests failed")
        exit(value)
print("Tests OK")
