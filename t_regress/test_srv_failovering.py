"""
Test Server connections failovering.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random

from framework.deproxy_server import ServerConnection
from helpers import tempesta as tfw
from helpers.control import Tempesta
from test_suite import tester


class TestFailovering(tester.TempestaTest):
    """Start a lot of servers and randomly close some  connections.

    Check that the number of active and schedulable connections is always
    less than or equal to the number of connections to the server.
    """

    tempesta = {
        "config": """
            listen 443 proto=h2;
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            frang_limits {http_strict_host_checking false;}
            
            cache 0;
            block_action error reply;
            block_action attack reply;

            """
        + "".join(
            "server ${server_ip}:80%s;\n" % (step if step > 9 else f"0{step}")
            for step in range(tfw.servers_in_group())
        )
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    backends = [
        {
            "id": f"deproxy-{step}",
            "type": "deproxy",
            "port": f"80{step if step > 9 else f'0{step}'}",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-length: 0\r\n" "\r\n"),
        }
        for step in range(tfw.servers_in_group())
    ]

    def test_on_close(self) -> None:
        self.start_all_services()
        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertTrue(self.is_srvs_ready())
        self.assertEqual(tempesta.stats.srv_conns_active, len(self.server_connection_pool()))

        self.random_close_connections()
        self.check_server_connections(tempesta)

    def check_server_connections(self, tempesta: Tempesta) -> None:
        tempesta.get_stats()
        worker_connections: int = tfw.server_conns_default() ** 2  # 1024
        expected_conns_n: int = sum(srv.conns_n for srv in self.get_servers())
        self.assertLessEqual(tempesta.stats.srv_conns_active, worker_connections)
        self.assertLessEqual(len(self.server_connection_pool()), expected_conns_n)

    def random_close_connections(self) -> None:
        expected_conns_n = sum(srv.conns_n for srv in self.get_servers())
        for _ in range(expected_conns_n // 4):
            conn: ServerConnection = random.choice(self.server_connection_pool())
            if conn:
                conn.handle_close()

    def is_srvs_ready(self) -> bool:
        expected_conns_n: int = sum(srv.conns_n for srv in self.get_servers())
        self.assertEqual(expected_conns_n, len(self.server_connection_pool()))
        return expected_conns_n == len(self.server_connection_pool())

    def server_connection_pool(self) -> list[ServerConnection]:
        srv_connections = []
        for srv in self.get_servers():
            srv_connections.extend(srv.connections)
        return srv_connections


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
