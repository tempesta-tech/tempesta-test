__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import ipaddress
from typing import List

from helpers import remote
from helpers.remote import ANode
from helpers.tf_cfg import test_logger


class FreePortsChecker(object):
    def __init__(self):
        self.node = remote.server
        self.__port_checks = []
        super().__init__()

    @property
    def node(self) -> ANode:
        return self.__node

    @node.setter
    def node(self, node: ANode) -> None:
        self.__node = node

    def add_port_to_checks(self, ip: str, port: int) -> None:
        if port <= 0:
            raise ValueError("Port MUST be greater than 0.")
        ipaddress.ip_address(ip)

        self.__port_checks.append((ip, port))

    def clean_ports_to_checks(self) -> None:
        self.__port_checks = []

    def check_ports_status(self, verbose=True):
        cmd = "netstat -tlnp"
        netstat, _ = self.node.run_cmd(cmd)

        listen = []

        for line in netstat.decode().splitlines()[2:]:
            portline = line.split()
            test_logger.info(f"Listen {portline}")
            listen.append(portline)

        for addrport in self.__port_checks:
            ip = addrport[0]
            port = addrport[1]

            match_exact = "%s:%s" % (ip, port)
            match_common = "0.0.0.0:%s" % port

            test_logger.info(f"Checking {ip}:{port}")
            for portline in listen:
                if portline[3] == match_common or portline[3] == match_exact:
                    if verbose:
                        test_logger.critical(f"Error: port already used {portline}")
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

    @staticmethod
    def number_of_tcp_connections(ip: str, port: str) -> int:
        """Count the number of TCP connections for this port and IP."""
        stdout, _ = remote.tempesta.run_cmd(
            f"ss --no-header --tcp --numeric state established dst '{ip}' | awk '{{print $4}}'"
        )

        return stdout.decode().count(port)
