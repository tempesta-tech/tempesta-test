"""Tests for Frang directive `request_rate` and 'request_burst'."""

import asyncio
import ssl
import time
from asyncio import events
from sys import flags

from hpack import Encoder
from hyperframe.frame import HeadersFrame, RstStreamFrame, SettingsFrame

import run_config
from framework.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.parameterize import param, parameterize
from helpers import analyzer, asserts, remote, tf_cfg
from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_MSG_RATE = "Warning: frang: request rate exceeded"
ERROR_MSG_BURST = "Warning: frang: requests burst exceeded"
RATE_TIMEOUT = DELAY + 0.05  # seconds

HTTP1_REQUEST = DeproxyClient.create_request(method="GET", uri="/", headers=[])
HTTP2_REQUEST = DeproxyClientH2.create_request(method="GET", uri="/", headers=[])


class AsyncClient:
    """The client for sending bytes. It does not wait for responses and does not check them."""

    def __init__(self, conn_ip: str, conn_port: int, local_ip: str, ssl_: bool, http2: bool):
        self._conn_ip: str = conn_ip
        self._conn_port: int = conn_port
        self._local_ip: str = local_ip
        self._writer: asyncio.streams.StreamWriter | None = None
        self._reader: asyncio.streams.StreamReader | None = None
        self._ssl: bool = ssl_
        self._http2: bool = http2
        self._context: ssl.SSLContext | None = self._create_context()
        self._tasks: list = []

    def _create_context(self) -> ssl.SSLContext | None:
        if not self._ssl:
            return None
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if run_config.SAVE_SECRETS:
            self._context.keylog_filename = "secrets.txt"
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE
        self._apply_proto_settings()
        return self._context

    def _apply_proto_settings(self):
        if self._context is not None:
            self._context.set_alpn_protocols(["h2"] if self._http2 else ["http/1.1"])
            # Disable old proto
            self._context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            if self._http2:
                # RFC 9113 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
                # compression.
                self._context.options |= ssl.OP_NO_COMPRESSION

    def send_bytes(self, data: bytes) -> None:
        self._tasks.append(asyncio.create_task(self._send_bytes(data)))

    async def run_start(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(
            self._conn_ip, self._conn_port, ssl=self._context, local_addr=(self._local_ip, 0)
        )
        if self._http2:
            # create HTTP/2.0 connection and send preamble
            sf = SettingsFrame(stream_id=0)
            self.send_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + sf.serialize())

    async def _send_bytes(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def wait_for_all_tasks(self) -> None:
        await asyncio.gather(*self._tasks)

    async def aclose(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except ssl.SSLError:
                ...


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


class TestFrangRequestRateBurst(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    tempesta = {
        "config": """
frang_limits {
    request_rate 3;
    request_burst 2;
}

listen 443 proto=h2,https;

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
    http2 = False

    async def make_requests(self, client: AsyncClient, request_n: int, sleep: float) -> None:
        await client.run_start()
        for _ in range(request_n):
            client.send_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await asyncio.sleep(sleep)

        await client.wait_for_all_tasks()
        await client.aclose()

    @parameterize.expand(
        [
            param(
                name="rate_reached",
                request_n=4,
                sleep=RATE_TIMEOUT,
                expected_block=True,
                expected_request_n=3,
                frang_msg=ERROR_MSG_RATE,
            ),
            param(
                name="rate_without_reaching_the_limit",
                request_n=2,
                sleep=RATE_TIMEOUT,
                expected_block=False,
                expected_request_n=2,
                frang_msg=ERROR_MSG_RATE,
            ),
            param(
                name="rate_on_the_limit",
                request_n=3,
                sleep=RATE_TIMEOUT,
                expected_block=False,
                expected_request_n=3,
                frang_msg=ERROR_MSG_RATE,
            ),
            param(
                name="burst_reached",
                request_n=3,
                sleep=0,
                expected_block=True,
                expected_request_n=2,
                frang_msg=ERROR_MSG_BURST,
            ),
            param(
                name="burst_without_reaching_the_limit",
                request_n=1,
                sleep=0,
                expected_block=False,
                expected_request_n=1,
                frang_msg=ERROR_MSG_BURST,
            ),
            param(
                name="burst_on_the_limit",
                request_n=2,
                sleep=0,
                expected_block=False,
                expected_request_n=2,
                frang_msg=ERROR_MSG_BURST,
            ),
        ]
    )
    def test_request(
        self,
        name,
        request_n: int,
        sleep: float,
        expected_block: bool,
        expected_request_n: int,
        frang_msg: str,
    ):
        self.start_all_services(client=False)

        client = AsyncClient(
            conn_ip=tf_cfg.cfg.get("Tempesta", "ip"),
            conn_port=443,
            local_ip=tf_cfg.cfg.get("Client", "ip"),
            ssl_=True,
            http2=self.http2,
        )

        asyncio.run(self.make_requests(client, request_n, sleep))

        server = self.get_server("deproxy")
        self.assertTrue(server.wait_for_requests(expected_request_n))
        if expected_block:
            self.assertTrue(self.klog.find(frang_msg))


class TestFrangRequestRateBurstH2(TestFrangRequestRateBurst):
    http2 = True

    async def make_requests(self, client: AsyncClient, request_n: int, sleep: float) -> None:
        await client.run_start()
        hpack_encoder = Encoder()
        headers = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        stream_id = 1
        for _ in range(request_n):
            client.send_bytes(
                HeadersFrame(
                    stream_id=stream_id,
                    data=hpack_encoder.encode(headers),
                    flags=["END_HEADERS", "END_STREAM"],
                ).serialize()
            )
            stream_id += 2
            await asyncio.sleep(sleep)
        await client.wait_for_all_tasks()
        await client.aclose()
