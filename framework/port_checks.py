__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from helpers import tf_cfg, remote

class FreePortsChecker(object):

    node = remote.server
    port_checks = []

    def check_ports_status(self):
        cmd = "netstat --inet -apn"
        netstat, _ = self.node.run_cmd(cmd)

        listen = []

        for line in netstat.splitlines():
            portline = line.split()
            if portline[0] != 'tcp':
                continue
            if portline[5] != 'LISTEN':
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
