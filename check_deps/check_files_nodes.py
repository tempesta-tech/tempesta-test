#!/usr/bin/env python2

import sys
import re
import os

sys.path.append("../")

from helpers import remote, tf_cfg

remote.connect()

all_ok = True

cmds = {
    remote.server : [
        os.path.normpath(tf_cfg.cfg.get("Server", "resources") + "/index.html")
    ],
}

all_ok = True

for node in cmds:
    print("\tChecking files on %s" % node.type)
    for file in cmds[node]:
        cmd = "if [ -e \"%s\" ]; then echo -n true; else echo -n false; fi"
        res,_ = node.run_cmd(cmd % file)
        if res == "true":
            print("\t\tFile '%s' exists" % file)
        else:
            print("\t\tFile '%s' doesn't exist" % file)
            all_ok = False

if all_ok == False:
    sys.exit(1)

sys.exit(0)