#!/usr/bin/env python2

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import sys
import re

sys.path.append("../")

from helpers import remote, tf_cfg

remote.connect()

all_ok = True

cmds = {
    remote.host : [
                        {
                            "cmd" : "curl",
                            "install" : "curl"
                        },
                        {
                            "cmd" : "iptables",
                            "install" : "iptables"
                        },
                    ],
    remote.client : [
                        {
                            "cmd" : tf_cfg.cfg.get("Client", "wrk"),
                            "install" : "wrk"
                        }
                    ],
    remote.tempesta : [
                        {
                            "cmd" : "netstat",
                            "install" : "net-tools"
                        },
                        {
                            "cmd" : "iptables",
                            "install" : "iptables"
                        },
                        {
                            "cmd" : "tcpdump",
                            "install" : "tcpdump"
                        },
                        {
                            "cmd" : "bc",
                            "install" : "bc"
                        },
                        {
                            "cmd" : "systemtap",
                            "install" : "systemtap"
                        },
                        {
                            "cmd" : "ethtool",
                            "install" : "ethtool"
                        }
                    ],
    remote.server : [
                        {
                            "cmd" : tf_cfg.cfg.get("Server", "nginx"),
                            "install" : "nginx"
                        },
                        {
                            "cmd" : "netstat",
                            "install" : "net-tools"
                        }
                    ],
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

    install = []

    for cmd in cmds[node]:
        command = "whereis -b %s" % cmd["cmd"]
        res,_ = node.run_cmd(command)
        patt = "%s: " % cmd["cmd"]
        result = res[len(patt):]
        if len(result) == 0:
            print("\t\tCommand `%s` doesn't installed" % cmd["cmd"])
            install.append(cmd["install"])
            all_ok = False
        else:
            print("\t\tCommand `%s` is installed" % cmd["cmd"])

    if len(install) > 0:
        cmds = " ".join(install)
        print("\n\t\tPlease run apt-get install %s\n" % cmds)

if all_ok:
    sys.exit(0)
else:
    sys.exit(1)
