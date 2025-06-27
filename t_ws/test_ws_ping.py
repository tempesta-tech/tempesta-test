import asyncio
import ssl

import requests
import websockets

from helpers import dmesg, tf_cfg
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

TEMPESTA_IP = tf_cfg.cfg.get("Tempesta", "ip")

TEMPESTA_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group default {
    server ${server_ip}:18099;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
"""

TEMPESTA_STRESS_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group default {
    server ${server_ip}:18099;
    server ${server_ip}:18100;
    server ${server_ip}:18101;
    server ${server_ip}:18102;
    server ${server_ip}:18103;
    server ${server_ip}:18104;
    server ${server_ip}:18105;
    server ${server_ip}:18106;
    server ${server_ip}:18107;
    server ${server_ip}:18108;
    server ${server_ip}:18109;
    server ${server_ip}:18110;
    server ${server_ip}:18111;
    server ${server_ip}:18112;
    server ${server_ip}:18113;
    server ${server_ip}:18114;
    server ${server_ip}:18115;
    server ${server_ip}:18116;
    server ${server_ip}:18117;
    server ${server_ip}:18118;
    server ${server_ip}:18119;
    server ${server_ip}:18120;
    server ${server_ip}:18121;
    server ${server_ip}:18122;
    server ${server_ip}:18123;
    server ${server_ip}:18124;
    server ${server_ip}:18125;
    server ${server_ip}:18126;
    server ${server_ip}:18127;
    server ${server_ip}:18128;
    server ${server_ip}:18129;
    server ${server_ip}:18130;
    server ${server_ip}:18131;
    server ${server_ip}:18132;
    server ${server_ip}:18133;
    server ${server_ip}:18134;
    server ${server_ip}:18135;
    server ${server_ip}:18136;
    server ${server_ip}:18137;
    server ${server_ip}:18138;
    server ${server_ip}:18139;
    server ${server_ip}:18140;
    server ${server_ip}:18141;
    server ${server_ip}:18142;
    server ${server_ip}:18143;
    server ${server_ip}:18144;
    server ${server_ip}:18145;
    server ${server_ip}:18146;
    server ${server_ip}:18147;
    server ${server_ip}:18148;
    server ${server_ip}:18149;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
"""

TEMPESTA_NGINX_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group default {
    server ${server_ip}:8000;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
"""

TEMPESTA_CACHE_CONFIG = """
listen 81;
frang_limits {http_strict_host_checking false;}
srv_group default {
    server ${server_ip}:18099;
}

vhost default {
    proxy_pass default;
}

cache 1;
cache_fulfill * *;

http_chain {
    -> default;
}
"""

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    map $$http_upgrade $$connection_upgrade {
        default Upgrade;
        ''      close;
    }

    upstream websocket {
        ip_hash;
        server ${server_ip}:18099;
    }

    upstream wss_websockets {
        ip_hash;
        server ${server_ip}:18099;
    }

    server {
        listen 8000;
        location / {
            proxy_pass http://websocket;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $$http_upgrade;
            proxy_set_header Connection $$connection_upgrade;
            proxy_set_header Host $$host;
        }
    }

    server {
        listen 8001 ssl;
        ssl_protocols TLSv1.2;
        ssl_certificate ${tempesta_workdir}/tempesta.crt;
        ssl_certificate_key ${tempesta_workdir}/tempesta.key;
        location / {
            proxy_pass http://wss_websockets;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $$http_upgrade;
            proxy_set_header Connection $$connection_upgrade;
            proxy_set_header Host $$host;
        }
    }
}
"""


class BaseWsPing(tester.TempestaTest):
    """Ping test for websocket ws scheme"""

    backends = []

    clients = []

    tempesta = {"config": TEMPESTA_CONFIG}

    def setUp(self):
        super().setUp()
        self.ws_servers = []

    # Client

    async def ws_ping_test(self, port: int, is_ssl: bool) -> None:
        proto = "wss" if is_ssl else "ws"
        ssl_context = None
        if is_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        async with websockets.connect(
            f"{proto}://{TEMPESTA_IP}:{port}", ssl=ssl_context
        ) as websocket:
            await websocket.send("request")
            response_body = await websocket.recv()
            self.assertEquals(response_body, "response")

    # Backend

    async def handler(self, websocket, path):
        request_body = await websocket.recv()
        self.assertEquals(request_body, "request")
        await websocket.send("response")

    @staticmethod
    def cleanup_ws_servers(test):
        async def wrapper(self: "BaseWsPing", *args, **kwargs):
            try:
                await test(self, *args, **kwargs)
            finally:
                for server in self.ws_servers:
                    server.close()

        return wrapper

    @cleanup_ws_servers
    async def _test(self, tempesta_port: int, is_ssl: bool):
        self.ws_servers.append(
            await websockets.serve(self.handler, tf_cfg.cfg.get("Server", "ip"), 18099)
        )
        self.start_tempesta()
        for _ in range(4):
            await self.ws_ping_test(tempesta_port, is_ssl)


class TestWsPing(BaseWsPing):
    def test(self):
        asyncio.run(self._test(tempesta_port=81, is_ssl=False))


@marks.parameterize_class(
    [{"name": "HttpsH2", "proto": "https,h2"}, {"name": "H2Https", "proto": "h2,https"}]
)
class TestWssPingMultipleListeners(BaseWsPing):
    """
    The inheritance here is related to legacy code, please do not repeat this
    example in other tests
    """

    tempesta_template = {
        "config": """
listen 81;
listen 82 proto=%s;

srv_group default {
    server ${server_ip}:18099;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
""",
    }

    def setUp(self):
        self.tempesta["config"] = self.tempesta_template["config"] % self.proto
        super().setUp()

    def test(self):
        asyncio.run(self._test(tempesta_port=82, is_ssl=True))


class TestWssPingProxy(BaseWsPing):
    """
    Ping test for websocket wss scheme with nginx proxying TLS
    Scheme: WSClient (TLS)-> Tempesta-fw -> NGINX (TLS)-> wss
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    tempesta = {"config": TEMPESTA_NGINX_CONFIG}

    def test(self):
        self.start_all_servers()
        asyncio.run(self._test(tempesta_port=82, is_ssl=True))


class TestWsCache(BaseWsPing):
    """
    Test case - we never cache 101 responses
    First: Send upgrade HTTP connection and - get 101
    Second: Terminate websocket, call HTTP upgrade again - get 502
    """

    tempesta = {"config": TEMPESTA_CACHE_CONFIG}

    def call_upgrade(self, port, expected_status):
        headers_ = {
            "Host": TEMPESTA_IP,
            "Connection": "Upgrade",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
            "Upgrade": "websocket",
            "Origin": "null",
            "Sec-WebSocket-Version": "13",
            "Accept-Encoding": "gzip, deflate",
            "Sec-WebSocket-Key": "V4wPm2Z/oOIUvp+uaX3CFQ==",
            "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
        }

        r = requests.get(f"http://{TEMPESTA_IP}:{port}", auth=("user", "pass"), headers=headers_)
        self.assertIn(r.status_code, expected_status)

    def test(self):
        asyncio.run(self._test(tempesta_port=81, is_ssl=False))

    @BaseWsPing.cleanup_ws_servers
    async def _test(self, tempesta_port: int, is_ssl: bool):
        server = await websockets.serve(
            self.handler, tf_cfg.cfg.get("Server", "ip"), 18099, open_timeout=3
        )
        self.ws_servers.append(server)
        self.start_tempesta()
        await self.ws_ping_test(tempesta_port, is_ssl)
        server.close(close_connections=True)
        await server.wait_closed()
        self.call_upgrade(81, [502, 504])


class TestWssStress(BaseWsPing):
    """
    Asynchronously make WSS Connections and restart tempesta
    """

    tempesta = {"config": TEMPESTA_STRESS_CONFIG}

    def fibo(self, n):
        fib = [0, 1]
        for i in range(n):
            fib.append(fib[-2] + fib[-1])
            if fib[-1] > n:
                break
        return fib

    @marks.change_ulimit(ulimit=10000)
    def test(self):
        asyncio.run(self._test(tempesta_port=82, is_ssl=True))

    @BaseWsPing.cleanup_ws_servers
    async def _test(self, tempesta_port: int, is_ssl: bool):
        for i in range(50):
            self.ws_servers.append(
                await websockets.serve(self.handler, tf_cfg.cfg.get("Server", "ip"), 18099 + i)
            )
        self.start_tempesta()
        count = 0
        for _ in range(4000):
            count += 1
            await self.ws_ping_test(tempesta_port, is_ssl)
            if (4000 - count) in self.fibo(4000):
                self.get_tempesta().restart()


class TestWssPipelining(BaseWsPing):
    """
    We sent 3 pipelined requests against websocket.
    Expected - Connection closing
    """

    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "81"}]

    tempesta = {"config": TEMPESTA_CONFIG}

    request = [
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n",
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n",
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n",
    ]

    @dmesg.unlimited_rate_on_tempesta_node
    def test(self):
        asyncio.run(self._test())

    @BaseWsPing.cleanup_ws_servers
    async def _test(self):
        self.ws_servers.append(
            await websockets.serve(
                self.handler, tf_cfg.cfg.get("Server", "ip"), 18099, open_timeout=3
            )
        )
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(self.request, pipelined=True)
        deproxy_cl.wait_for_connection_close(timeout=5, strict=True)

        self.assertTrue(
            self.loggers.dmesg.find(
                pattern="Request dropped: Pipelined request received after UPGRADE request",
                cond=dmesg.amount_positive,
            ),
            "Unexpected number of warnings",
        )


class TestWsScheduler(BaseWsPing):
    """
    Create 4 connections against 1 backend ws
    Make 256 async client ws connections
    Expected result - All ping messages recieved
    """

    tempesta = {
        "config": """
            listen 81;

            srv_group default {
                server ${server_ip}:18099 conns_n=16;
            }
            frang_limits {http_strict_host_checking false;}
            vhost default {
                proxy_pass default;
            }

            http_chain {
                -> default;
            }
        """,
    }

    def test(self):
        asyncio.run(self._test(tempesta_port=81, is_ssl=False))

    @BaseWsPing.cleanup_ws_servers
    async def _test(self, tempesta_port: int, is_ssl: bool):
        for i in range(4):
            self.ws_servers.append(
                await websockets.serve(self.handler, tf_cfg.cfg.get("Server", "ip"), 18099 + i)
            )
        self.start_tempesta()
        for _ in range(256):
            await self.ws_ping_test(tempesta_port, is_ssl)


class TestRestartOnUpgrade(BaseWsPing):
    """
    Asyncly create many Upgrade requests
    against WS during tempesta-fw restart.
    Expected - 101 response code
    """

    tempesta = {"config": TEMPESTA_CONFIG}

    def fibo(self, n):
        fib = [0, 1]
        for _ in range(n):
            fib.append(fib[-2] + fib[-1])
            if fib[-1] > n:
                break
        return fib

    def test(self):
        asyncio.run(self._test(tempesta_port=81, is_ssl=False))

    @BaseWsPing.cleanup_ws_servers
    async def _test(self, tempesta_port: int, is_ssl: bool):
        self.ws_servers.append(
            await websockets.serve(
                self.handler, tf_cfg.cfg.get("Server", "ip"), 18099, open_timeout=10
            )
        )
        self.start_tempesta()
        for i in range(1500):
            await self.ws_ping_test(tempesta_port, is_ssl)
            if i in self.fibo(1500):
                self.get_tempesta().restart()
