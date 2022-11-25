"""Tests for Frang directive `ip_block`."""
import time

from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangIpBlockBase(FrangTestCase, base=True):
    """Base class for tests with 'ip_block' directive."""

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
    ]

    def get_responses(self, client_1, client_2):
        self.start_all_services(client=False)

        client_1.start()
        client_2.start()

        client_1.make_request("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        client_1.wait_for_response(1)

        client_2.make_request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        client_2.wait_for_response(1)


class FrangIpBlockMessageLimits(FrangIpBlockBase):
    """
    For `http_host_required true` and `block_action attack reply`:
    Create two client connections, then send invalid and valid requests and receive:
        - for different ip and ip_block on - RST and 200 response;
        - for single ip and ip_block on - RST and RST;
        - for single or different ip and ip_block off - 403 and 200 responses;
    """

    tempesta = {
        "config": """
frang_limits {
    http_host_required true;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack reply;
""",
    }

    def test_two_clients_two_ip_with_ip_block_on(self):
        client_1 = self.get_client("deproxy-interface-1")
        client_2 = self.get_client("deproxy-interface-2")

        self.get_responses(client_1, client_2)

        self.assertIsNone(client_1.last_response)
        self.assertIsNotNone(client_2.last_response)
        self.assertEqual(client_2.last_response.status, "200")

        time.sleep(self.timeout)

        self.assertTrue(client_1.connection_is_closed())
        self.assertFalse(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)

    def test_two_clients_one_ip_with_ip_block_on(self):
        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        self.get_responses(client_1, client_2)

        self.assertIsNone(client_1.last_response)
        self.assertIsNone(client_2.last_response)

        time.sleep(self.timeout)

        self.assertTrue(client_1.connection_is_closed())
        self.assertTrue(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)

    def test_two_client_one_ip_with_ip_block_off(self):
        self.tempesta = {
            "config": """
frang_limits {
    http_host_required true;
    ip_block off;
}

listen 80;

server ${server_ip}:8000;

block_action attack reply;
""",
        }
        self.setUp()

        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        self.get_responses(client_1, client_2)

        self.assertIsNotNone(client_1.last_response)
        self.assertIsNotNone(client_2.last_response)

        self.assertEqual(client_1.last_response.status, "403")
        self.assertEqual(client_2.last_response.status, "200")

        time.sleep(self.timeout)

        self.assertTrue(client_1.connection_is_closed())
        self.assertFalse(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)


class FrangIpBlockConnectionLimits(FrangIpBlockBase):
    """
    For `connection_rate 1` and `block_action attack reply`.
    Create two client connections, send valid requests and receive:
        - for different ip and ip_block on or off - 200 and 200 response;
        - for single ip and ip_block on - RST and RST;
        - for single ip and ip_block off - 200 response and RST;
    """

    tempesta = {
        "config": """
frang_limits {
    http_host_required false;
    connection_rate 1;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack reply;
""",
    }

    def test_two_clients_two_ip_with_ip_block_on(self):
        client_1 = self.get_client("deproxy-interface-1")
        client_2 = self.get_client("deproxy-interface-2")

        self.get_responses(client_1, client_2)

        self.assertIsNotNone(client_1.last_response)
        self.assertIsNotNone(client_2.last_response)

        self.assertEqual(client_2.last_response.status, "200")
        self.assertEqual(client_2.last_response.status, "200")

        time.sleep(self.timeout)

        self.assertFalse(client_1.connection_is_closed())
        self.assertFalse(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: new connections rate exceeded for", expected=0)

    def test_two_clients_one_ip_with_ip_block_on(self):
        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        self.get_responses(client_1, client_2)

        self.assertIsNone(client_1.last_response)
        self.assertIsNone(client_2.last_response)

        time.sleep(self.timeout)

        self.assertTrue(client_1.connection_is_closed())
        self.assertTrue(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: new connections rate exceeded for", expected=1)

    def test_two_clients_one_ip_with_ip_block_off(self):
        self.tempesta = {
            "config": """
frang_limits {
    http_host_required false;
    connection_rate 1;
    ip_block off;
}
listen 80;
server ${server_ip}:8000;
block_action attack reply;
""",
        }
        self.setUp()

        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        self.get_responses(client_1, client_2)

        self.assertIsNotNone(client_1.last_response)
        self.assertIsNone(client_2.last_response)

        self.assertEqual(client_1.last_response.status, "200")

        time.sleep(self.timeout)

        self.assertFalse(client_1.connection_is_closed())
        self.assertTrue(client_2.connection_is_closed())

        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: new connections rate exceeded for", expected=1)
