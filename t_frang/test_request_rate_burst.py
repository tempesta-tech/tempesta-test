"""Tests for Frang directive `request_rate` and 'request_burst'."""
import time

from helpers import analyzer, asserts, remote
from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_MSG_RATE = "Warning: frang: request rate exceeded"
ERROR_MSG_BURST = "Warning: frang: requests burst exceeded"


class FrangRequestRateTestCase(FrangTestCase, asserts.Sniffer):
    """Tests for 'request_rate' directive."""

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
            "id": "another-ip",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
    ]

    tempesta = {
        "config": """
frang_limits {
    request_rate 4;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack reply;
""",
    }

    def setUp(self):
        super().setUp()
        self.sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5)

    request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

    error_msg = ERROR_MSG_RATE

    def arrange(self, c1, c2, rps_1: int, rps_2: int):
        self.sniffer.start()
        self.start_all_services(client=False)
        c1.set_rps(rps_1)
        c2.set_rps(rps_2)

    def do_requests(self, c1, c2, request_cnt: int):
        c1.start()
        c2.start()
        for _ in range(request_cnt):
            c1.make_request(self.request)
            c2.make_request(self.request)
        c1.wait_for_response(3)
        c2.wait_for_response(3)

    def test_two_clients_two_ip(self):
        """
        Set `request_rate 4;` and make requests for two clients with different ip:
            - 6 requests for client with 4 rps and receive 6 responses with 200 status;
            - 6 requests for client with rps greater than 4 and get ip block;
        """
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("another-ip")

        self.arrange(c1, c2, rps_1=4, rps_2=0)
        self.save_must_reset_socks(c2)
        self.save_must_not_reset_socks(c1)

        self.do_requests(c1, c2, request_cnt=6)

        self.assertEqual(c1.statuses, {200: 6})
        self.assertTrue(c1.conn_is_active)
        self.assertEqual(c2.statuses, {200: 4})

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assert_unreset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning=self.error_msg, expected=1)

    def test_two_clients_one_ip(self):
        """
        Set `request_rate 4;` and make requests concurrently for two clients with same ip.
        Clients will be blocked on 5th request.
        """
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")

        self.arrange(c1, c2, rps_1=0, rps_2=0)
        self.save_must_reset_socks(c1, c2)

        self.do_requests(c1, c2, request_cnt=4)

        self.assertGreater(5, len(c2.responses) + len(c1.responses))
        self.assertGreater(len(c1.responses), 0)
        self.assertGreater(len(c2.responses), 0)

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning=self.error_msg, expected=1)


class FrangRequestBurstTestCase(FrangRequestRateTestCase):
    """Tests for and 'request_burst' directive."""

    tempesta = {
        "config": """
frang_limits {
    request_burst 4;
    ip_block on;
}
listen 80;
server ${server_ip}:8000;
block_action attack reply;
""",
    }

    error_msg = ERROR_MSG_BURST


class FrangRequestRateBurstTestCase(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    tempesta = {
        "config": """
frang_limits {
    request_rate 3;
    request_burst 2;
}

listen 80;
server ${server_ip}:8000;
cache 0;
block_action attack reply;
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
            "id": "curl",
            "type": "curl",
            "headers": {
                "Connection": "keep-alive",
                "Host": "debian",
            },
            "cmd_args": " --verbose",
        },
    ]

    rate_warning = ERROR_MSG_RATE
    burst_warning = ERROR_MSG_BURST

    def _base_burst_scenario(self, requests: int):
        self.start_all_services(client=False)

        client = self.get_client("curl")
        client.uri += f"[1-{requests}]"
        client.parallel = requests

        client.start()
        client.wait_for_finish()
        client.stop()

        time.sleep(self.timeout)

        if requests > 2:  # burst limit 2
            self.assertFrangWarning(warning=self.burst_warning, expected=1)
        else:
            self.assertFrangWarning(warning=self.burst_warning, expected=0)

        self.assertFrangWarning(warning=self.rate_warning, expected=0)

    def _base_rate_scenario(self, requests: int):
        self.start_all_services()

        client = self.get_client("deproxy-1")

        for step in range(requests):
            client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            time.sleep(DELAY)

        if requests < 3:  # rate limit 3
            self.check_response(client, warning_msg=self.rate_warning, status_code="200")
        else:
            # rate limit is reached
            self.assertTrue(client.wait_for_connection_close(self.timeout))
            self.assertFrangWarning(warning=self.rate_warning, expected=1)
            self.assertEqual(client.last_response.status, "403")

        self.assertFrangWarning(warning=self.burst_warning, expected=0)

    def test_request_rate_reached(self):
        self._base_rate_scenario(requests=4)

    def test_request_rate_without_reaching_the_limit(self):
        self._base_rate_scenario(requests=2)

    def test_request_rate_on_the_limit(self):
        self._base_rate_scenario(requests=3)

    def test_request_burst_reached(self):
        self._base_burst_scenario(requests=3)

    def test_request_burst_not_reached_the_limit(self):
        self._base_burst_scenario(requests=1)

    def test_request_burst_on_the_limit(self):
        self._base_burst_scenario(requests=2)
