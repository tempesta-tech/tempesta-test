#!/usr/bin/env python3

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
                        },
                        {
                            "cmd" : tf_cfg.cfg.get("Client", "h2load"),
                            "install" : "nghttp2-client"
                        },
                        {
                            "cmd" : tf_cfg.cfg.get("Client", "tls-perf"),
                            "install" : ""
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

def make_report_line(name):
    filler_len = max(3, 20 - len(name))
    return '{} {}'.format(name, '.' * filler_len)


for node in cmds:
    print('\tChecking prerequisites on "%s" node:' % node.type)
    try:
        node.run_cmd("whereis sh")
    except Exception as e:
        print("\t\t{} not found\n".format(make_report_line('whereis')))
        all_ok = False
        continue

    package_list = []

    for cmd in cmds[node]:
        command = "whereis -b %s" % cmd["cmd"]
        res,_ = node.run_cmd(command)
        patt = "%s: " % cmd["cmd"]
        result = res[len(patt):]
        if len(result) == 0:
            print("\t\t{} not found".format(make_report_line(cmd["cmd"])))
            package_list.append(cmd["install"])
            all_ok = False
        else:
            print("\t\t{} found".format(make_report_line(cmd["cmd"])))

    print("")

    if len(package_list) > 0:
        print('\t\tRun "apt-get install {}" on "{}" node\n'.format(
              " ".join(package_list), node.type))

sys.exit(0 if all_ok else 1)
