"""Tests for `framework.lxc_server.LXCServer`."""

from helpers import remote
from test_suite import tester


class TestLxcServer(tester.TempestaTest):
    tempesta = {
        "config": """
        listen 80 proto=http;
        server ${server_ip}:8000;
        """
    }

    backends = [{"id": "lxc", "type": "lxc", "external_port": "8000", "make_snapshot": False}]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_wait_for_connections_positive(self):
        """
        The server MUST work correctly after calling `wait_for_connections` method,
        and it MUST return a valid responses.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(method="GET", headers=[], uri="/license.txt"), "200"
        )

    def test_wait_for_connections_negative(self):
        """
        `wait_for_connections` method MUST return False
        if Tempesta and server has different connection ports.
        """
        server = self.get_server("lxc")
        server.external_port = "9000"

        server.start()
        self.start_tempesta()
        self.assertFalse(server.wait_for_connections(1))

    def test_status(self):
        """`server.status` MUST return a correct container status."""
        server = self.get_server("lxc")
        self.assertEqual(server.status, "stopped")

        server.start()
        self.start_tempesta()
        self.assertTrue(server.wait_for_connections(3))
        self.assertEqual(server.status, "running")
