#!/usr/bin/env python3

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import sys
import re
import os

sys.path.append("../")

from helpers import remote, tf_cfg

remote.connect()

cmds = {
    remote.server : [
        os.path.normpath(tf_cfg.cfg.get("Server", "resources") + "/index.html")
    ],
}


def make_report_line(name):
    filler_len = max(3, 20 - len(name))
    return '{} {}'.format(name, '.' * filler_len)


all_ok = True

for node in cmds:
    print('\tChecking files on "{}" node:'.format(node.type))
    for file in cmds[node]:
        cmd = "if [ -e \"%s\" ]; then echo -n true; else echo -n false; fi"
        res,_ = node.run_cmd(cmd % file)
        if res == "true":
            print("\t\t{} found".format(make_report_line(file)))
        else:
            print("\t\t{} not found".format(make_report_line(file)))
            all_ok = False

print("")

sys.exit(0 if all_ok else 1)
