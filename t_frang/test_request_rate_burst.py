"""Tests for Frang directive `request_rate` and 'request_burst'."""

import time

from hyperframe.frame import HeadersFrame, RstStreamFrame

from framework.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.parameterize import param, parameterize, parameterize_class
from helpers import analyzer, error, remote, util
from t_frang.frang_test_case import DELAY, FrangTestCase
from test_suite import asserts

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


@parameterize_class(
    [
        {"name": "Http", "client_name": "deproxy-1"},
        {"name": "H2", "client_name": "deproxy-2"},
    ]
)
class TestFrangRequestRateBurst(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    client_name: str

    @parameterize.expand(
        [
            param(name="burst_reached", req_n=10, warns_expected=range(1, 15)),
            param(name="burst_without_reaching_the_limit", req_n=3, warns_expected=0),
            param(name="burst_on_the_limit", req_n=5, warns_expected=0),
        ]
    )
    @util.retry_if_not_conditions
    def test_request(self, name, req_n: int, warns_expected):
        """
        Send several requests, if number of requests
        is more than 5 some of them will be blocked.
        """
        self.set_frang_config("request_burst 5;\n\trequest_rate 10;")
        self.start_all_services(client=False)

        client = self.get_client(self.client_name)
        client.start()

        start_time = time.monotonic()
        for _ in range(req_n):
            client.make_request(client.create_request(method="GET", uri="/", headers=[]))
        self.assertIn(
            client.wait_for_response(),
            [True, None],
            "The client didn't get responses or connection block.",
        )
        end_time = time.monotonic()

        if end_time - start_time > DELAY:
            raise error.TestConditionsAreNotCompleted()

        self.assertFrangWarning(warning=ERROR_MSG_BURST, expected=warns_expected)
        self.assertFrangWarning(warning=ERROR_MSG_RATE, expected=0)
        if warns_expected:
            self.assertTrue(client.connection_is_closed())

    @parameterize.expand(
        [
            param(name="rate_reached", req_n=10, warns_expected=range(1, 15)),
            param(name="rate_without_reaching_the_limit", req_n=3, warns_expected=0),
            param(name="rate_on_the_limit", req_n=5, warns_expected=0),
        ]
    )
    @util.retry_if_not_conditions
    def test_request(self, name, req_n: int, warns_expected):
        """
        Send several requests, if number of requests
        is more than 5 some of them will be blocked.
        """
        self.set_frang_config("request_burst 10;\n\trequest_rate 5;")
        self.start_all_services(client=False)

        client = self.get_client(self.client_name)
        client.start()

        start_time = time.monotonic()
        for _ in range(req_n):
            client.make_request(client.create_request(method="GET", uri="/", headers=[]))
        self.assertIn(
            client.wait_for_response(),
            [True, None],
            "The client didn't get responses or connection block.",
        )
        end_time = time.monotonic()

        if end_time - start_time > 1:
            raise error.TestConditionsAreNotCompleted()

        self.assertFrangWarning(warning=ERROR_MSG_RATE, expected=warns_expected)
        self.assertFrangWarning(warning=ERROR_MSG_BURST, expected=0)
        if warns_expected:
            self.assertTrue(client.connection_is_closed())


class TestFrangRapidDDoSH2(FrangTestCase):
    """
    Open many streams with a Header frame without END_STREAM flag.
    This is not a complete request, but it opens possibility for
    a DDoS attack - "Rapid Reset".
    """

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    @staticmethod
    def _start_and_init_connection(client) -> None:
        client.start()
        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())

    @staticmethod
    def _create_frames_and_init_streams(client, stream_n: int) -> list[bytes]:
        frame_list = []
        for _ in range(stream_n):
            hf = HeadersFrame(
                stream_id=client.stream_id,
                data=client.h2_connection.encoder.encode(
                    [
                        (":authority", "tempesta-tech.com"),
                        (":path", "/"),
                        (":scheme", "https"),
                        (":method", "GET"),
                    ]
                ),
                flags=[],
            ).serialize()
            rf = RstStreamFrame(stream_id=client.stream_id).serialize()
            frame_list.append(hf + rf)
            client.init_stream_for_send(stream_id=client.stream_id)
            client.stream_id += 2
        return frame_list

    @parameterize.expand(
        [
            param(
                name="rate_with_only_headers_frame",
                frang_conf="request_rate 5;",
                warning=ERROR_MSG_RATE,
                delay=1,
            ),
            param(
                name="burst_with_only_headers_frame",
                frang_conf="request_burst 5;",
                warning=ERROR_MSG_BURST,
                delay=DELAY,
            ),
        ]
    )
    @util.retry_if_not_conditions
    def test_request(self, name, frang_conf: str, warning: str, delay: int):
        self.set_frang_config(frang_conf)
        self.start_all_services(client=False)

        client = self.get_client("deproxy-1")
        self._start_and_init_connection(client)
        frame_list = self._create_frames_and_init_streams(client, 10)

        start_time = time.monotonic()
        for frames in frame_list:
            client.send_bytes(frames, expect_response=True)
        self.assertIn(
            client.wait_for_response(),
            [True, None],
            "The client didn't get responses or connection block.",
        )
        end_time = time.monotonic()

        if end_time - start_time > delay:
            raise error.TestConditionsAreNotCompleted()

        self.assertFrangWarning(warning=warning, expected=range(1, 15))
        self.assertTrue(client.connection_is_closed())
