"""Functional tests for `concurrent_tcp_connections` in Tempesta config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from t_frang.frang_test_case import FrangTestCase

ERROR = "Warning: frang: connections max num. exceeded"


class ConcurrentConnections(FrangTestCase):
    tempesta_template = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    %(frang_config)s
}

""",
    }

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-interface-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
        {
            "id": "deproxy-interface-2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
        {
            "id": "deproxy-interface-3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
        {
            "id": "parallel-curl",
            "type": "curl",
            "uri": "/[1-2]",
            "parallel": 2,
            "headers": {
                "Connection": "close",
                "Host": "debian",
            },
            "cmd_args": " --verbose",
        },
    ]

    def _base_scenario(self, clients: list, responses: int):
        for client in clients:
            client.start()

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
                self.get_client("deproxy-1"),
                self.get_client("deproxy-2"),
                self.get_client("deproxy-3"),
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
                self.get_client("deproxy-interface-1"),
                self.get_client("deproxy-interface-2"),
                self.get_client("deproxy-interface-3"),
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
                self.get_client("deproxy-1"),
                self.get_client("deproxy-2"),
                self.get_client("deproxy-3"),
            ],
            responses=0,
        )

        self.assertFrangWarning(warning=ERROR, expected=1)

    def test_clear_client_connection_stats(self):
        """
        Establish connections for many clients with same IP, then close them.
        Check that Tempesta cleared client connection stats and
        new connections are established.
        """
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\n\tip_block on;")

        client = self.get_client("parallel-curl")

        client.start()
        self.wait_while_busy(client)
        client.stop()

        time.sleep(self.timeout)

        self.assertFrangWarning(warning=ERROR, expected=0)
        self.assertIn("Closing connection 1", client.last_response.stderr)
        self.assertIn("Closing connection 0", client.last_response.stderr)

        time.sleep(1)

        client.start()
        self.wait_while_busy(client)
        client.stop()

        time.sleep(self.timeout)

        self.assertFrangWarning(warning=ERROR, expected=0)
        self.assertIn("Closing connection 1", client.last_response.stderr)
        self.assertIn("Closing connection 0", client.last_response.stderr)
