"""Functional tests for `concurrent_tcp_connections` in Tempesta config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from helpers import tf_cfg, remote
from helpers.networker import NetWorker
from t_frang.frang_test_case import FrangTestCase
from test_suite import marks

ERROR = "Warning: frang: connections max num. exceeded"


class TestConcurrentConnectionsNonTempesta(FrangTestCase):
    tempesta = {
        "config": """

listen 127.0.0.1:80;

frang_limits {
    concurrent_tcp_connections 1;
    ip_block off;
}

""",
    }

    clients = [
        {
            "id": f"deproxy-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
        for id_ in range(3)
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "80",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                "x-deproxy-srv-id: 2\r\n"
                "Connection: keep-alive\r\n\r\n"
            ),
        },
    ]

    @staticmethod
    def __create_new_address():
        interface = tf_cfg.cfg.get("Server", "aliases_interface")
        base_ip = tf_cfg.cfg.get("Server", "aliases_base_ip")
        networker = NetWorker(node=remote.server)

        return networker.create_interfaces(interface, base_ip, 1)[0]

    def test(self):
        """
        Verify that Tempesta applies frang limits only to its socket.

        Start listen port 80 on two different interfaces, on loopback interface listening Tempesta,
        on newly created interface (using __create_new_address()) listening deproxy server.
        Establish 3 connections directly with deproxy server and check whether Tempesta applied
        frang limits to this connections or not.

        Expected behaviour: Limits must not be applied.
        Although the test looks artificially, we need to have it, bcause we had such bug.
        """
        self.disable_deproxy_auto_parser()

        ip = self.__create_new_address()
        server = self.get_server("deproxy")
        server.bind_addr = ip

        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        for client in self.get_clients():
            """
            Set the same address as for standalone deproxy server.
            Try to connect to this server directly avoid Tempesta.
            """
            client.conn_addr = ip
            client.start()
            """
            We need to be sure that previous client is establish or fail
            to establish connection because of limit exceeded. Otherwise
            there can be a race and we don't know what client fails because
            of limit violation.
            """
            time.sleep(0.2)

        for client in self.get_clients():
            client.make_request(client.create_request(method="GET", headers=[]))

        for client in self.get_clients():
            client.wait_for_response(timeout=2, strict=True)

        for client in self.get_clients():
            for resp in client.responses:
                self.assertEqual(resp.headers.get("x-deproxy-srv-id", None), "2")

        self.assertFrangWarning(warning=ERROR, expected=0)


class ConcurrentConnections(FrangTestCase):
    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    %(frang_config)s
}

""",
    }

    clients = [
        {
            "id": f"deproxy-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
        for id_ in range(10)
    ] + [
        {
            "id": f"deproxy-interface-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        }
        for id_ in range(3)
    ]

    def _base_scenario(self, clients: list, responses: int):
        self.disable_deproxy_auto_parser()
        for client in clients:
            client.start()
            """
            We need to be sure that previous client is establish or fail
            to establish connection because of limit exceeded. Otherwise
            there can be a race and we don't know what client fails because
            of limit violation.
            """
            time.sleep(0.2)

        for client in clients:
            client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        for client in clients:
            client.wait_for_response(timeout=2)

        if responses == 0:
            for client in clients:
                self.assertEqual(0, len(client.responses))
                self.assertTrue(client.wait_for_connection_close())
        elif responses == 2:
            self.assertEqual(1, len(clients[0].responses))
            self.assertEqual(1, len(clients[1].responses))
            self.assertEqual(0, len(clients[2].responses))
            self.assertTrue(clients[2].wait_for_connection_close())
            self.assertFalse(clients[0].connection_is_closed())
            self.assertFalse(clients[1].connection_is_closed())
        elif responses == 3:
            self.assertEqual(1, len(clients[0].responses))
            self.assertEqual(1, len(clients[1].responses))
            self.assertEqual(1, len(clients[2].responses))
            self.assertFalse(clients[0].connection_is_closed())
            self.assertFalse(clients[1].connection_is_closed())
            self.assertFalse(clients[2].connection_is_closed())

    def test_three_clients_same_ip(self):
        """
        For three clients with same IP and concurrent_tcp_connections 2, ip_block off:
            - Tempesta serves only two clients.
        """
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\n\tip_block off;")

        self._base_scenario(
            clients=[
                self.get_client("deproxy-0"),
                self.get_client("deproxy-1"),
                self.get_client("deproxy-2"),
            ],
            responses=2,
        )

        self.assertFrangWarning(warning=ERROR, expected=1)

    def test_three_clients_different_ip(self):
        """
        For three clients with different IP and concurrent_tcp_connections 2:
            - Tempesta serves three clients.
        """
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\n\tip_block off;")
        self._base_scenario(
            clients=[
                self.get_client("deproxy-interface-0"),
                self.get_client("deproxy-interface-1"),
                self.get_client("deproxy-interface-2"),
            ],
            responses=3,
        )

        self.assertFrangWarning(warning=ERROR, expected=0)

    def test_three_clients_same_ip_with_block_ip(self):
        """
        For three clients with same IP and concurrent_tcp_connections 2, ip_block on:
            - Tempesta does not serve clients.
        """
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\n\tip_block on;")
        self._base_scenario(
            clients=[
                self.get_client("deproxy-0"),
                self.get_client("deproxy-1"),
                self.get_client("deproxy-2"),
            ],
            responses=0,
        )

        self.assertFrangWarning(warning=ERROR, expected=1)

    @marks.Parameterize.expand(
        [
            marks.Param(name="equal", clients_n=2, warning_n=0),
            marks.Param(name="greater", clients_n=10, warning_n=8),
        ]
    )
    def test_clear_client_connection_stats(self, name, clients_n: int, warning_n: int):
        """
        Establish connections for many clients with same IP, then close them.
        Check that Tempesta cleared client connection stats and
        new connections are established.
        """
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\n\tip_block off;")

        non_blocked_clients = [self.get_client(f"deproxy-{n}") for n in range(2)]
        blocked_clients = [self.get_client(f"deproxy-{n}") for n in range(2, clients_n)]

        for n in [warning_n, warning_n * 2]:
            for client in non_blocked_clients + blocked_clients:  # establish 2 or more connections
                client.start()
                client.make_request(client.create_request(method="GET", headers=[]))

            for client in blocked_clients:
                self.assertTrue(
                    client.wait_for_connection_close(),
                    "Tempesta did not block concurrent TCP connections.",
                )
            for client in non_blocked_clients:
                self.assertTrue(client.wait_for_response())
                self.assertTrue(
                    client.conn_is_active, "Deproxy clients did not open connections with Tempesta."
                )
            self.assertFrangWarning(warning=ERROR, expected=n)

            for client in non_blocked_clients + blocked_clients:
                client.stop()
