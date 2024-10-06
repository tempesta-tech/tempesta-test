"""Tests for Frang directive `request_rate` and 'request_burst'."""

import asyncio
import ssl
import time

from hpack import Encoder
from hyperframe.frame import HeadersFrame, SettingsFrame

import run_config
from framework.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.parameterize import param, parameterize, parameterize_class
from helpers import dmesg, tf_cfg
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

    def is_closing(self) -> bool:
        return self._writer.is_closing()

    async def wait_for_connection_close(self, timeout=5.0) -> bool:
        task = asyncio.create_task(self._reader.read(-1))
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except asyncio.TimeoutError:
            task.cancel()
        return self._reader.at_eof()

    async def run_start(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(
            self._conn_ip, self._conn_port, ssl=self._context, local_addr=(self._local_ip, 0)
        )
        if self._http2:
            # create HTTP/2.0 connection and send preamble
            sf = SettingsFrame(stream_id=0)
            await self.send_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + sf.serialize())

    async def send_bytes(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def aclose(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            # TODO: Should be removed after issue #1778. Tempesta sends an unexpected tls alert.
            except ssl.SSLError:
                ...


@parameterize_class(
    [
        {"name": "Http", "http2": False, "request_factory": "create_http1_request"},
        {"name": "H2", "http2": True, "request_factory": "create_h2_request"},
    ]
)
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

    rate_warning = ERROR_MSG_RATE
    burst_warning = ERROR_MSG_BURST
    http2: bool
    request_factory: callable

    stream_id = 1

    @staticmethod
    def create_http1_request():
        return b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    def create_h2_request(self):
        headers = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        request = HeadersFrame(
            stream_id=self.stream_id,
            data=self.hpack_encoder.encode(headers),
            flags=["END_HEADERS", "END_STREAM"],
        )
        self.stream_id += 2
        return request.serialize()

    async def make_requests(
        self, client: AsyncClient, request_n: int, sleep: float, expected_requests_time: float
    ) -> None:
        request_factory = self.__getattribute__(self.request_factory)
        for _ in range(request_n):
            await client.send_bytes(request_factory())
            await asyncio.sleep(sleep)

    async def atest(
        self,
        request_n: int,
        sleep: float,
        expected_block: bool,
        expected_request_n: int,
        frang_msg: str,
        expected_requests_time: float,
    ):
        try:
            for step in range(1, 5):
                tf_cfg.dbg(1, f"Step {step}")
                self.start_all_services(client=False)
                self.hpack_encoder = Encoder()  # only for HTTP/2.0

                client = AsyncClient(
                    conn_ip=tf_cfg.cfg.get("Tempesta", "ip"),
                    conn_port=443,
                    local_ip=tf_cfg.cfg.get("Client", "ip"),
                    ssl_=True,
                    http2=self.http2,
                )
                await client.run_start()
                start_time = time.monotonic()
                await self.make_requests(client, request_n, sleep, expected_requests_time)
                tf_cfg.dbg(1, str(time.monotonic() - start_time))

                server = self.get_server("deproxy")
                self.assertTrue(server.wait_for_requests(expected_request_n))

                end_time = time.monotonic()
                tf_cfg.dbg(1, str(end_time - start_time))
                if end_time - start_time > expected_requests_time:
                    tf_cfg.dbg(1, "Restart test")
                    await client.aclose()
                    for service in self.get_all_services():
                        service.stop()
                    continue
                break

            if expected_block:
                self.assertTrue(await client.wait_for_connection_close())
                self.assertTrue(self.klog.find(frang_msg, cond=dmesg.amount_positive))
            else:
                self.assertFalse(client.is_closing())
                self.assertTrue(self.klog.find(frang_msg, cond=dmesg.amount_zero))

        finally:
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
                expected_requests_time=1,
            ),
            param(
                name="rate_without_reaching_the_limit",
                request_n=2,
                sleep=RATE_TIMEOUT,
                expected_block=False,
                expected_request_n=2,
                frang_msg=ERROR_MSG_RATE,
                expected_requests_time=1,
            ),
            param(
                name="rate_on_the_limit",
                request_n=3,
                sleep=RATE_TIMEOUT,
                expected_block=False,
                expected_request_n=3,
                frang_msg=ERROR_MSG_RATE,
                expected_requests_time=1,
            ),
            param(
                name="burst_reached",
                request_n=3,
                sleep=0,
                expected_block=True,
                expected_request_n=2,
                frang_msg=ERROR_MSG_BURST,
                expected_requests_time=DELAY,
            ),
            param(
                name="burst_without_reaching_the_limit",
                request_n=1,
                sleep=0,
                expected_block=False,
                expected_request_n=1,
                frang_msg=ERROR_MSG_BURST,
                expected_requests_time=DELAY,
            ),
            param(
                name="burst_on_the_limit",
                request_n=2,
                sleep=0,
                expected_block=False,
                expected_request_n=2,
                frang_msg=ERROR_MSG_BURST,
                expected_requests_time=DELAY,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_request(
        self,
        name,
        request_n: int,
        sleep: float,
        expected_block: bool,
        expected_request_n: int,
        frang_msg: str,
        expected_requests_time: float,
    ):
        asyncio.run(
            self.atest(
                request_n,
                sleep,
                expected_block,
                expected_request_n,
                frang_msg,
                expected_requests_time,
            )
        )
