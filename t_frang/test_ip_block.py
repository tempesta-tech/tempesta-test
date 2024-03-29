"""Tests for Frang directive `ip_block`."""
import time

from helpers import analyzer, asserts, remote, util
from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangIpBlockBase(FrangTestCase, asserts.Sniffer, base=True):
    """Base class for tests with 'ip_block' directive."""

    clients = [
        {
            "id": "same-ip1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "same-ip2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "same-ip3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "same-ip4",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "another-ip",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
    ]

    def setUp(self):
        super().setUp()
        self.sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5)


class FrangIpBlockMsg(FrangIpBlockBase):
    """
    Test ip_block with message level of Frang.
    """

    tempesta = {
        "config": """
frang_limits {
    http_strict_host_checking true;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack drop;
""",
    }

    GOOD_REQ = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    BAD_REQ = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

    def test_on(self):
        self.disable_deproxy_auto_parser()
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("same-ip3")
        c4 = self.get_client("another-ip")
        c5 = self.get_client("same-ip4")
        four = util.ForEach(c1, c2, c3, c4)

        self.sniffer.start()
        self.start_all_services(client=False)
        four.start()
        self.save_must_reset_socks([c1, c2, c3])
        self.save_must_not_reset_socks([c4])

        # Good request: all is good
        four.send_request(self.GOOD_REQ, "200")
        self.assertEqual(set(four.conn_is_active), {True})

        # Bad request:
        # reset all current clients with the same IPs
        c2.send_request(self.BAD_REQ)
        # Last client wasn't blocked due to different IP
        self.assertTrue(c4.conn_is_active)
        c4.send_request(self.GOOD_REQ, "200")
        # New clients with blocked IP won't be accepted
        c5.start()
        c5.send_request(self.GOOD_REQ, timeout=1)
        self.assertFalse(c5.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assert_unreset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)

    def test_off(self):
        self.disable_deproxy_auto_parser()
        self.tempesta = {
            "config": """
frang_limits {
    http_strict_host_checking true;
    ip_block off;
}
listen 80;
server ${server_ip}:8000;
block_action attack drop;
""",
        }
        self.setUp()
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")

        self.sniffer.start()
        self.start_all_services(client=False)
        c1.start()
        c2.start()
        self.save_must_reset_socks([c1])
        self.save_must_not_reset_socks([c2])

        # Blocking is off: clients with the same IPs
        # handled separately
        c1.send_request(self.BAD_REQ)
        c2.send_request(self.GOOD_REQ, "200")
        self.assertTrue(c2.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assert_unreset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)


class FrangIpBlockConn(FrangIpBlockBase):
    """
    Test ip_block with connection level of Frang.
    """

    tempesta = {
        "config": """
frang_limits {
    tcp_connection_rate 2;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack drop;
""",
    }

    REQ = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    def test_on(self):
        self.disable_deproxy_auto_parser()
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("another-ip")
        c4 = self.get_client("same-ip3")
        c5 = self.get_client("same-ip4")
        four = util.ForEach(c1, c2, c3, c4)

        self.sniffer.start()
        self.start_all_services(client=False)
        four.start()
        self.save_must_reset_socks([c1, c2, c4])
        self.save_must_not_reset_socks([c3])

        # Last request triggers rate limit (3 same IPs > 2)
        four.send_request(self.REQ)

        # Reset all current clients with the same IPs
        # Client with different IP wasn't blocked
        self.assertEqual(c3.last_response.status, "200")
        self.assertTrue(c3.conn_is_active)
        # New clients with blocked IP won't be accepted
        c5.start()
        c5.send_request(self.REQ, timeout=1)
        self.assertFalse(c5.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assert_unreset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: new connections rate exceeded for", expected=1)

    def test_off(self):
        self.disable_deproxy_auto_parser()
        self.tempesta = {
            "config": """
frang_limits {
    tcp_connection_rate 1;
    ip_block off;
}
listen 80;
server ${server_ip}:8000;
block_action attack drop;
""",
        }
        self.setUp()

        c1 = self.get_client("same-ip1")
        c2 = self.get_client("another-ip")
        c3 = self.get_client("same-ip2")
        clients = util.ForEach(c1, c2, c3)

        self.sniffer.start()
        time.sleep(self.timeout)
        self.start_all_services(client=False)
        clients.start()
        self.save_must_reset_socks([c3])
        self.save_must_not_reset_socks([c1, c2])

        # Blocking is off: clients with the same IPs
        # handled separately
        c1.send_request(self.REQ, "200")
        # Client with different IP isn't accounted
        c2.send_request(self.REQ, "200")
        c3.send_request(self.REQ)
        self.assertTrue(c1.conn_is_active)
        self.assertTrue(c2.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assert_unreset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: new connections rate exceeded for", expected=1)
