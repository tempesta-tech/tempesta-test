__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

import re
from typing import List

from helpers import remote, tf_cfg


class FreePortsChecker(object):

    node = remote.server
    port_checks = []

    def check_ports_status(self):
        cmd = "netstat --inet -apn"
        netstat, _ = self.node.run_cmd(cmd)

        listen = []

        for line in netstat.decode().splitlines():
            portline = line.split()
            if portline[0] != "tcp":
                continue
            if portline[5] != "LISTEN":
                continue
            tf_cfg.dbg(5, "\tListen %s" % str(portline))
            listen.append(portline)

        for addrport in self.port_checks:
            ip = addrport[0]
            port = addrport[1]

            match_exact = "%s:%s" % (ip, port)
            match_common = "0.0.0.0:%s" % port

            tf_cfg.dbg(5, "\tChecking %s:%s" % (ip, port))
            for portline in listen:
                if portline[3] == match_common or portline[3] == match_exact:
                    tf_cfg.dbg(2, "Error: port already used %s" % str(portline))
                    msg = "Trying to use already used port: %s" % portline
                    raise Exception(msg)

    def check_ports_established(self, ip: str, ports: List[int]):
        """Return True if connections are established from Tempesta FW
        to all the specified ports on the given IP.
        Can be used to check that server is started.
        """
        # Command to output "Address:Port" column
        # of the list of TCP connections established to IP
        cmd = f"ss --no-header --tcp --numeric state established dst '{ip}' | awk '{{print $4}}'"
        addrport, _ = remote.tempesta.run_cmd(cmd)

        expected = {int(port) for port in ports}
        established = {int(line.split(":")[-1]) for line in addrport.decode().splitlines() if line}

        return expected <= established
