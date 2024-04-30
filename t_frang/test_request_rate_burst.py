"""Tests for Frang directive `request_rate` and 'request_burst'."""

import time

from hyperframe.frame import RstStreamFrame

from framework.deproxy_client import DeproxyClient, DeproxyClientH2
from helpers import analyzer, asserts, remote
from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_MSG_RATE = "Warning: frang: request rate exceeded"
ERROR_MSG_BURST = "Warning: frang: requests burst exceeded"

HTTP1_REQUEST = DeproxyClient.create_request(method="GET", uri="/", headers=[])
HTTP2_REQUEST = DeproxyClientH2.create_request(method="GET", uri="/", headers=[])


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
    %(frang_config)s;
    ip_block on;
}
listen 80;
listen 443 proto=h2;
server ${server_ip}:8000;
block_action attack drop;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
""",
    }

    frang_config = "request_rate 4"
    error_msg = ERROR_MSG_RATE
    request = HTTP1_REQUEST

    def setUp(self):
        super().setUp()
        self.sniffer = analyzer.Sniffer(remote.client, "Client", timeout=10, ports=(80, 443))
        self.set_frang_config(self.frang_config)

    def arrange(self, c1, c2, rps_1: int, rps_2: int):
        self.sniffer.start()
        self.start_all_services(client=False)
        c1.set_rps(rps_1)
        c2.set_rps(rps_2)
        c1.start()
        c2.start()

    def do_requests(self, c1, c2, request_cnt: int):
        for _ in range(request_cnt):
            c1.make_request(self.request)
            c2.make_request(self.request)
        c1.wait_for_response(10, strict=True)
        c2.wait_for_response(10, strict=True)

    def test_two_clients_two_ip(self):
        """
        Set `request_rate 4;` and make requests for two clients with different ip:
            - 6 requests for client with 3.8 rps and receive 6 responses with 200 status;
            - 6 requests for client with rps greater than 4 and get ip block;
        """
        self.disable_deproxy_auto_parser()
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("another-ip")

        self.arrange(c1, c2, rps_1=3.8, rps_2=0)
        self.save_must_reset_socks([c2])
        self.save_must_not_reset_socks([c1])

        self.do_requests(c1, c2, request_cnt=6)

        self.assertEqual(c1.statuses, {200: 6})
        self.assertTrue(c1.conn_is_active)
        # For c2: we can't say number of received responses when ip is blocked.
        # See the comment in DeproxyClient.statuses for details.

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
        self.save_must_reset_socks([c1, c2])

        self.do_requests(c1, c2, request_cnt=4)

        # We can't say number of received responses when ip is blocked.
        # See the comment in DeproxyClient.statuses for details.

        self.sniffer.stop()
        self.assert_reset_socks(self.sniffer.packets)
        self.assertFrangWarning(warning="Warning: block client:", expected=range(1, 2))
        self.assertFrangWarning(warning=self.error_msg, expected=range(1, 2))


class FrangRequestBurstTestCase(FrangRequestRateTestCase):
    """Tests for and 'request_burst' directive."""

    clients = FrangRequestRateTestCase.clients
    frang_config = "request_burst 4"
    error_msg = ERROR_MSG_BURST
    request = HTTP1_REQUEST


class FrangRequestRateH2(FrangRequestRateTestCase):
    clients = [
        {
            "id": "same-ip1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "same-ip2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "another-ip",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "interface": True,
            "ssl": True,
        },
    ]
    frang_config = FrangRequestRateTestCase.frang_config
    error_msg = ERROR_MSG_RATE
    request = HTTP2_REQUEST


class FrangRequestBurstH2(FrangRequestRateTestCase):
    clients = FrangRequestRateH2.clients
    frang_config = FrangRequestBurstTestCase.frang_config
    error_msg = ERROR_MSG_BURST
    request = HTTP2_REQUEST


class FrangRequestRateBurstTestCase(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    tempesta = {
        "config": """
frang_limits {
    request_rate 3;
    request_burst 2;
}

listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;
cache 0;
block_action attack reply;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
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
        client.disable_output = True

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
        self.start_all_services(client=False)

        client = self.get_client("deproxy-1")
        client.start()
        for step in range(requests):
            client.make_request(client.create_request(method="GET", uri="/", headers=[]))
            time.sleep(DELAY)

        if requests <= 3:  # rate limit 3
            self.check_response(client, warning_msg=self.rate_warning, status_code="200")
        else:
            # rate limit is reached
            self.assertTrue(client.wait_for_connection_close())
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


class FrangRequestRateBurstH2(FrangRequestRateBurstTestCase):
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "curl",
            "type": "curl",
            "http2": True,
            "headers": {
                "Connection": "keep-alive",
                "Host": "debian",
            },
            "cmd_args": " --verbose",
        },
    ]

    def _test_with_only_headers_frame(self, requests: int, sleep: int, warning: str):
        """
        Open many streams with a Header frame without END_STREAM flag.
        This is not a complete request, but it opens possibility for
        a DDoS attack - "Rapid Reset".
        """
        self.start_all_services(client=False)

        client = self.get_client("deproxy-1")
        client.start()
        for step in range(requests):  # request rate 3
            client.make_request(
                client.create_request(method="GET", uri="/", headers=[]),
                end_stream=False,
            )
            client.send_bytes(RstStreamFrame(stream_id=client.stream_id).serialize())
            client.stream_id += 2
            time.sleep(sleep)

        #  The response status check was removed because sometimes client
        #  receives TCP RST before the HTTP response.
        self.assertTrue(client.wait_for_connection_close())
        self.assertFrangWarning(warning=warning, expected=1)

    def test_request_rate_with_only_headers_frame(self):
        self._test_with_only_headers_frame(requests=4, sleep=DELAY, warning=self.rate_warning)

    def test_request_burst_with_only_headers_frame(self):
        self._test_with_only_headers_frame(requests=3, sleep=0, warning=self.burst_warning)
