"""Tests for Frang directive `ip_block`."""

import time

from helpers import analyzer, remote, util
from t_frang.frang_test_case import FrangTestCase
from test_suite import asserts

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
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

    def set_frang_config(self, frang_config: str):
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig % {
            "frang_config": frang_config,
        }


class FrangIpBlockMsg(FrangIpBlockBase):
    """
    Test ip_block with message level of Frang.
    """

    tempesta = {
        "config": """
frang_limits {
    %(frang_config)s
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
        self.set_frang_config(frang_config="http_strict_host_checking true;\nip_block 0;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("same-ip3")
        c4 = self.get_client("another-ip")
        c5 = self.get_client("same-ip4")
        four = util.ForEach(c1, c2, c3, c4)

        self.sniffer.start()
        self.start_all_services(client=False)
        four.start()

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
        # don't adjust timeout. At this moment Tempesta doesn't accepts SYN from blocked client
        # and network not heavy loaded, thus doesn't make sense to wait 60 seconds on tcp
        # segmentation, 5 sec must be enough
        c5.make_request(self.GOOD_REQ)
        c5.wait_for_response(timeout=5, adjust_timeout=False)
        self.assertFalse(c5.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets, [c1, c2, c3])
        self.assert_unreset_socks(self.sniffer.packets, [c4])
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)

    def test_blocktime_expired(self):
        self.disable_deproxy_auto_parser()
        self.set_frang_config(frang_config="http_strict_host_checking true;\nip_block 11;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("another-ip")
        three = util.ForEach(c1, c2, c3)

        self.sniffer.start()
        self.start_all_services(client=False)
        three.start()

        # Good request: all is good
        three.send_request(self.GOOD_REQ, "200")
        self.assertEqual(set(three.conn_is_active), {True})

        # Bad request:
        # reset all current clients with the same IPs
        c1.send_request(self.BAD_REQ)
        # Last client wasn't blocked due to different IP
        self.assertTrue(c3.conn_is_active)
        c3.send_request(self.GOOD_REQ, "200", timeout=5)
        # c2 disconnected during ip blocking
        self.assertTrue(c2.wait_for_connection_close(timeout=2))
        # New clients with blocked IP won't be accepted
        # wait 3 seconds timeout - client is blocked
        c2.restart()
        self.assertFalse(c2.wait_for_connection_open(timeout=3, adjust_timeout=False))
        self.assertFalse(c2.conn_is_active)
        # Wait 12 seconds to have in most fastest case atleast 12 seconds wait that greater
        # than block duration
        time.sleep(12)

        c2.restart()
        # block duration is 2 seconds, thus expect successful connection
        c2.send_request(self.GOOD_REQ, "200")

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets, [c1])
        self.assert_unreset_socks(self.sniffer.packets, [c2, c3])
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)

    def test_off(self):
        self.disable_deproxy_auto_parser()
        self.set_frang_config(frang_config="http_strict_host_checking true;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")

        self.sniffer.start()
        self.start_all_services(client=False)
        c1.start()
        c2.start()

        # Blocking is off: clients with the same IPs
        # handled separately
        c1.send_request(self.BAD_REQ)
        c2.send_request(self.GOOD_REQ, "200")
        self.assertTrue(c2.conn_is_active)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets, [c1])
        self.assert_unreset_socks(self.sniffer.packets, [c2])
        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning="frang: Host header field contains IP address", expected=1)


class FrangIpBlockConn(FrangIpBlockBase):
    """
    Test ip_block with connection level of Frang.
    """

    tempesta = {
        "config": """
frang_limits {
    %(frang_config)s
}
listen 80;
server ${server_ip}:8000;
block_action attack drop;
""",
    }

    warning_msg = "frang: connections max num. exceeded for"

    REQ = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    def test_on(self):
        self.disable_deproxy_auto_parser()
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\nip_block 0;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("another-ip")
        c4 = self.get_client("same-ip3")
        c5 = self.get_client("same-ip4")

        self.sniffer.start()
        self.start_all_services(client=False)
        for cl in [c1, c2, c3]:
            cl.start()
            self.assertTrue(cl.wait_for_connection_open())

        c2.send_request(self.REQ, "200")
        # On connection to c4 client - block expected
        c4.start()
        self.assertFalse(c4.wait_for_connection_open(timeout=2))
        self.assertFalse(c4.conn_is_active)

        # Reset all current clients with the same IPs
        # Client with different IP wasn't blocked
        c3.send_request(self.REQ)
        self.assertEqual(c3.last_response.status, "200")
        self.assertTrue(c3.conn_is_active)

        # New clients with blocked IP won't be accepted
        c5.start()
        # don't adjust timeout. At this moment Tempesta doesn't accepts SYN from blocked client
        # and network not heavy loaded, thus doesn't make sense to wait 60 seconds on tcp
        # segmentation, 5 sec must be enough
        self.assertFalse(c5.wait_for_connection_open(timeout=5, adjust_timeout=False))
        self.assertFalse(c5.conn_is_active)

        self.sniffer.stop()

        self.assert_reset_socks(self.sniffer.packets, [c1, c2, c4])
        self.assert_unreset_socks(self.sniffer.packets, [c3, c5])
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning=self.warning_msg, expected=1)

    def test_blocktime_expired(self):
        self.disable_deproxy_auto_parser()
        self.set_frang_config(frang_config="concurrent_tcp_connections 2;\nip_block 10;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")
        c3 = self.get_client("another-ip")
        c4 = self.get_client("same-ip3")
        c5 = self.get_client("same-ip4")

        self.sniffer.start()
        self.start_all_services(client=False)
        for cl in [c1, c2, c3]:
            cl.start()
            cl.wait_for_connection_open(strict=True)

        # Reset all current clients with the same IPs
        # Client with different IP wasn't blocked
        c3.send_request(self.REQ, "200")
        self.assertEqual(c3.last_response.status, "200")
        self.assertTrue(c3.conn_is_active)
        # New clients with blocked IP won't be accepted
        c4.start()
        # block expected wait 3 seconds timeout
        self.assertFalse(c4.wait_for_connection_open(timeout=3))
        self.assertTrue(c4.wait_for_connection_close(timeout=3))
        self.assertFalse(c4.conn_is_active)

        # "c4" connected when a connection still can be established and after connection of "c4" its
        # ip will be blocked. But we can't be sure that it being blocked or it just disconnected, to
        # be sure that ip is blocked we do this connection attempt. At this moment connection will
        # not be established and SYN from client "c5" will be dropped
        c5.start()
        self.assertFalse(
            c5.wait_for_connection_open(timeout=3, adjust_timeout=False),
            "Client has not been blocked",
        )
        self.assertFalse(c5.conn_is_active, "Client has not been blocked")
        # Wait 11 seconds to have in most fastest case atleast 11 seconds wait that greater
        # than block duration
        time.sleep(11)

        c4.restart()
        c4.send_request(self.REQ, "200")

        self.sniffer.stop()

        self.assert_reset_socks(self.sniffer.packets, [c1, c2])
        self.assert_unreset_socks(self.sniffer.packets, [c3, c4])
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning=self.warning_msg, expected=1)

    def test_off(self):
        self.disable_deproxy_auto_parser()
        self.set_frang_config(frang_config="\nconcurrent_tcp_connections 1;")
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("another-ip")
        c3 = self.get_client("same-ip2")

        self.sniffer.start()
        time.sleep(self.timeout)
        self.start_all_services(client=False)
        for cl in [c1, c2, c3]:
            cl.start()
            # The last connection triggers block by concurrent_tcp_connections.
            cl.wait_for_connection_open()

        # Blocking is off: clients with the same IPs
        # handled separately
        c1.send_request(self.REQ, "200")
        # Client with different IP isn't accounted
        c2.send_request(self.REQ, "200")
        self.assertTrue(c1.conn_is_active)
        self.assertTrue(c2.conn_is_active)
        self.assertFalse(c3.conn_is_active)

        self.sniffer.stop()

        self.assert_reset_socks(self.sniffer.packets, [c3])
        self.assert_unreset_socks(self.sniffer.packets, [c1, c2])
        self.assertFrangWarning(warning="Warning: block client:", expected=0)
        self.assertFrangWarning(warning=self.warning_msg, expected=1)
