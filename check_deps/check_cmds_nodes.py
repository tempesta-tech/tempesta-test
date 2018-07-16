#!/usr/bin/env python2

import sys
import re

sys.path.append("../")

from helpers import remote, tf_cfg

remote.connect()

all_ok = True

cmds = {
    remote.client : ["python3", tf_cfg.cfg.get("Client", "wrk")],
    remote.tempesta : ["netstat", "iptables", "tcpdump"],
    remote.server : [tf_cfg.cfg.get("Server", "nginx")],
}

for node in cmds:
    print("\tChecking commands on %s" % node.type)
    try:
        node.run_cmd("whereis sh")
    except Exception as e:
        print("\t\tCan not use `whereis` on %s: %s" % (node.type, str(e)))
        all_ok = False
        continue
    print("\t\tCommand `whereis` installed")

    for cmd in cmds[node]:
        command = "whereis -b %s" % cmd
        res,_ = node.run_cmd(command)
        patt = "%s: " % cmd
        result = res[len(patt):]
        if len(result) == 0:
            print("\t\tCommand `%s` doesn't installed" % cmd)
            all_ok = False
        else:
            print("\t\tCommand `%s` is installed" % cmd)

if all_ok:
    sys.exit(0)
else:
    sys.exit(1)