"""Tests for Frang directive `request_rate` and 'request_burst'."""

import time

from framework.deproxy.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.deproxy.deproxy_message import H2Request, Request
from framework.helpers import analyzer, asserts, error, remote
from framework.test_suite import marks
from tests.frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_MSG_RATE = "Warning: frang: request rate exceeded"
ERROR_MSG_BURST = "Warning: frang: requests burst exceeded"

HTTP1_REQUEST = DeproxyClient.create_request(method="GET", uri="/", headers=[])
HTTP2_REQUEST = DeproxyClientH2.create_request(method="GET", uri="/", headers=[])

HTTP1_CLIENTS = [
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

HTTP2_CLIENTS = [
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


@marks.parameterize_class(
    [
        {
            "name": "RateHttp",
            "clients": HTTP1_CLIENTS,
            "frang_config": "request_rate 4",
            "request": HTTP1_REQUEST,
            "error_msg": ERROR_MSG_RATE,
            "delay": 1.0,
        },
        {
            "name": "BurstHttp",
            "clients": HTTP1_CLIENTS,
            "frang_config": "request_burst 4",
            "request": HTTP1_REQUEST,
            "error_msg": ERROR_MSG_BURST,
            "delay": 0.125,
        },
        {
            "name": "RateH2",
            "clients": HTTP2_CLIENTS,
            "request": HTTP2_REQUEST,
            "frang_config": "request_rate 4",
            "error_msg": ERROR_MSG_RATE,
            "delay": 1.0,
        },
        {
            "name": "BurstH2",
            "clients": HTTP2_CLIENTS,
            "request": HTTP2_REQUEST,
            "frang_config": "request_burst 4",
            "error_msg": ERROR_MSG_BURST,
            "delay": 0.125,
        },
    ]
)
class TestFrangRequest(FrangTestCase, asserts.Sniffer):
    tempesta = {
        "config": """
frang_limits {
    %(frang_config)s;
    ip_block 0;
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

    frang_config: str
    error_msg: str
    delay: float
    request: H2Request | Request

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.sniffer = analyzer.Sniffer(remote.client, "Client", timeout=10, ports=(80, 443))
        await self.set_frang_config(self.frang_config)

    async def arrange(self, c1, c2):
        await self.sniffer.start()
        await self.start_all_services(client=False)
        c1.start()
        c2.start()

    async def do_requests(self, c1, c2, request_cnt_1: int, request_cnt_2: int):
        for _ in range(request_cnt_1):
            c1.make_request(self.request)
        for _ in range(request_cnt_2):
            c2.make_request(self.request)
        await c1.wait_for_response(10, strict=True)
        await c2.wait_for_response(10, strict=True)

    @marks.retry_if_not_conditions
    async def test_two_clients_two_ip(self):
        """
        Set `request_rate 4;` and make requests for two clients with different ip:
            - 4 requests for client 1 and receive 4 responses with 200 status;
            - 8 requests for client 2 and get ip block;
        """
        self.disable_deproxy_auto_parser()
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("another-ip")

        await self.arrange(c1, c2)

        start_time = time.monotonic()
        await self.do_requests(c1, c2, request_cnt_1=4, request_cnt_2=8)
        end_time = time.monotonic()

        if end_time - start_time > self.delay:
            raise error.TestConditionsAreNotCompleted(self.id())

        self.assertEqual(c1.statuses, {200: 4})
        self.assertTrue(c1.conn_is_active)
        # For c2: we can't say number of received responses when ip is blocked.
        # See the comment in DeproxyClient.statuses for details.

        self.sniffer.stop()

        await self.assertFrangWarning(
            warning=f"Warning: block client: {c2.bind_addr}", expected=range(1, 3)
        )
        await self.assertFrangWarning(warning=self.error_msg, expected=range(1, 12))
        self.assert_reset_socks(self.sniffer.packets, [c2])
        self.assert_unreset_socks(self.sniffer.packets, [c1])

    @marks.retry_if_not_conditions
    async def test_two_clients_one_ip(self):
        """
        Set `request_rate 4;` and make requests concurrently for two clients with same ip.
        Clients will be blocked on 5th request.
        """
        c1 = self.get_client("same-ip1")
        c2 = self.get_client("same-ip2")

        await self.arrange(c1, c2)

        start_time = time.monotonic()
        await self.do_requests(c1, c2, request_cnt_1=4, request_cnt_2=4)
        end_time = time.monotonic()

        if end_time - start_time > self.delay:
            raise error.TestConditionsAreNotCompleted(self.id())

        # We can't say number of received responses when ip is blocked.
        # See the comment in DeproxyClient.statuses for details.

        self.sniffer.stop()

        await self.assertFrangWarning(warning="Warning: block client:", expected=range(1, 6))
        await self.assertFrangWarning(warning=self.error_msg, expected=range(1, 12))
        self.assert_reset_socks(self.sniffer.packets, [c1, c2])


@marks.parameterize_class(
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="burst_reached", req_n=10, warns_expected=range(1, 15)),
            marks.Param(name="burst_without_reaching_the_limit", req_n=3, warns_expected=0),
            marks.Param(name="burst_on_the_limit", req_n=5, warns_expected=0),
        ]
    )
    @marks.retry_if_not_conditions
    async def test_request(self, name, req_n: int, warns_expected):
        """
        Send several requests, if number of requests
        is more than 5 some of them will be blocked.
        """
        await self.set_frang_config("request_burst 5;\n\trequest_rate 10;")
        await self.start_all_services(client=False)

        client = self.get_client(self.client_name)
        client.start()

        start_time = time.monotonic()
        for _ in range(req_n):
            client.make_request(client.create_request(method="GET", uri="/", headers=[]))
        self.assertIn(
            await client.wait_for_response(),
            [True, None],
            "The client didn't get responses or connection block.",
        )
        end_time = time.monotonic()

        if end_time - start_time > DELAY:
            raise error.TestConditionsAreNotCompleted(self.id())

        await self.assertFrangWarning(warning=ERROR_MSG_BURST, expected=warns_expected)
        await self.assertFrangWarning(warning=ERROR_MSG_RATE, expected=0)
        if warns_expected:
            self.assertTrue(client.connection_is_closed())

    @marks.Parameterize.expand(
        [
            marks.Param(name="rate_reached", req_n=10, warns_expected=range(1, 15)),
            marks.Param(name="rate_without_reaching_the_limit", req_n=3, warns_expected=0),
            marks.Param(name="rate_on_the_limit", req_n=5, warns_expected=0),
        ]
    )
    @marks.retry_if_not_conditions
    async def test_request(self, name, req_n: int, warns_expected):
        """
        Send several requests, if number of requests
        is more than 5 some of them will be blocked.
        """
        await self.set_frang_config("request_burst 10;\n\trequest_rate 5;")
        await self.start_all_services(client=False)

        client = self.get_client(self.client_name)
        client.start()

        start_time = time.monotonic()
        for _ in range(req_n):
            client.make_request(client.create_request(method="GET", uri="/", headers=[]))
        self.assertIn(
            await client.wait_for_response(),
            [True, None],
            "The client didn't get responses or connection block.",
        )
        end_time = time.monotonic()

        if end_time - start_time > 1:
            raise error.TestConditionsAreNotCompleted(self.id())

        await self.assertFrangWarning(warning=ERROR_MSG_RATE, expected=warns_expected)
        await self.assertFrangWarning(warning=ERROR_MSG_BURST, expected=0)
        if warns_expected:
            self.assertTrue(client.connection_is_closed())
