"""Tests for Frang directive `request_rate` and 'request_burst'."""
import time

from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_MSG_RATE = "Warning: frang: request rate exceeded"
ERROR_MSG_BURST = "Warning: frang: requests burst exceeded"


class FrangRequestRateTestCase(FrangTestCase):
    """Tests for 'request_rate' directive."""

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

    request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

    error_msg = ERROR_MSG_RATE

    def get_responses(self, client_1, client_2, rps_1: int, rps_2: int, request_cnt: int):
        self.start_all_services(client=False)

        client_1.set_rps(rps_1)
        client_2.set_rps(rps_2)

        client_1.start()
        client_2.start()

        for _ in range(request_cnt):
            client_1.make_request(self.request)
            client_2.make_request(self.request)

        client_1.wait_for_response(3)
        client_2.wait_for_response(3)

    def test_two_clients_two_ip(self):
        """
        Set `request_rate 4;` and make requests for two clients with different ip:
            - 6 requests for client with 4 rps and receive 6 responses with 200 status;
            - 6 requests for client with rps greater than 4 and get ip block;
        """
        client_1 = self.get_client("deproxy-interface-1")
        client_2 = self.get_client("deproxy-interface-2")

        self.get_responses(client_1, client_2, rps_1=4, rps_2=0, request_cnt=6)

        self.assertFalse(client_1.connection_is_closed())
        self.assertTrue(client_2.connection_is_closed())

        for response in client_1.responses:
            self.assertEqual(response.status, "200")

        self.assertEqual(4, len(client_2.responses))

        self.assertFrangWarning(warning="Warning: block client:", expected=1)
        self.assertFrangWarning(warning=self.error_msg, expected=1)

    def test_two_clients_one_ip(self):
        """
        Set `request_rate 4;` and make requests concurrently for two clients with same ip.
        Clients will be blocked on 5th request.
        """
        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        self.get_responses(client_1, client_2, rps_1=0, rps_2=0, request_cnt=4)

        self.assertGreater(5, len(client_2.responses) + len(client_1.responses))
        self.assertGreater(len(client_1.responses), 0)
        self.assertGreater(len(client_2.responses), 0)

        self.assertTrue(client_1.connection_is_closed())
        self.assertTrue(client_2.connection_is_closed())

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
            time.sleep(self.timeout)
            self.assertFrangWarning(warning=self.rate_warning, expected=1)
            self.assertEqual(client.last_response.status, "403")
            self.assertTrue(client.connection_is_closed())

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
