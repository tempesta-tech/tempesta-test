#! /usr/bin/python3

import asyncio
import ssl
import time
from multiprocessing import Process
from threading import Thread

import requests
import websockets

from helpers import dmesg, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

GENERAL_WORKDIR = tf_cfg.cfg.get("General", "workdir")
CERT_PATH = f"{GENERAL_WORKDIR}/cert.pem"
KEY_PATH = f"{GENERAL_WORKDIR}/key.pem"
TEMPESTA_IP = tf_cfg.cfg.get("Tempesta", "ip")
SERVER_IP = tf_cfg.cfg.get("Server", "ip")
hostname = "localhost"
ping_message = "ping_test"


TEMPESTA_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group default {

    server ${server_ip}:18099;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${general_workdir}/cert.pem;
tls_certificate_key ${general_workdir}/key.pem;
tls_match_any_server_name;
vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
%s
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
tls_certificate ${general_workdir}/cert.pem;
tls_certificate_key ${general_workdir}/key.pem;
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
tls_certificate ${general_workdir}/cert.pem;
tls_certificate_key ${general_workdir}/key.pem;
tls_match_any_server_name;

vhost default {
    proxy_pass default;
}

http_chain {
    -> default;
}
%s
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

access_log dmesg;

cache 1;
cache_fulfill * *;

http_chain {
    -> default;
}
%s
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
        ssl_certificate ${general_workdir}/cert.pem;
        ssl_certificate_key ${general_workdir}/key.pem;
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


def gen_cert(host_name):
    cgen = CertGenerator(CERT_PATH, KEY_PATH)
    cgen.CN = host_name
    cgen.generate()


class BaseWsPing(tester.TempestaTest):
    """Ping test for websocket ws scheme"""

    backends = []

    clients = []

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    # Client

    def run_test(self, port, n):
        for _ in range(n):
            asyncio.run(self.ws_ping_test(port))

    async def ws_ping_test(self, port):
        global ping_message
        async with websockets.connect(f"ws://{TEMPESTA_IP}:{port}") as websocket:
            await websocket.send(ping_message)
            await websocket.recv()
            await websocket.close()

    async def wss_ping_test(self, port):
        global ping_message
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_verify_locations(f"{GENERAL_WORKDIR}/cert.pem")

        async with websockets.connect(f"wss://{TEMPESTA_IP}:{port}", ssl=ssl_context) as websocket:
            await websocket.send(ping_message)
            await websocket.recv()
            await websocket.close()

    def run_ws(self, port, count=1, proxy=False):
        if proxy:
            self.start_all_servers()
        loop = asyncio.get_event_loop()
        for i in range(count):
            asyncio.ensure_future(websockets.serve(self.handler, SERVER_IP, port + i))
        loop.run_forever()

    # Backend

    async def handler(self, websocket, path):
        global ping_message
        data = await websocket.recv()
        reply = f"{data}"
        if f"{data}" != ping_message:
            self.fail("Ping message corrupted")
        await websocket.send(reply)

    def setUp(self):
        self.p1 = None
        self.p2 = None
        super().setUp()
        self.addCleanup(self.cleanup_p1)
        self.addCleanup(self.cleanup_p2)

    def cleanup_p1(self):
        if self.p1:
            self.p1.terminate()
            self.p1 = None

    def cleanup_p2(self):
        if self.p2:
            self.p2.terminate()
            self.p2 = None


class WsPing(BaseWsPing):

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(8099,))
        self.p2 = Process(target=self.run_test, args=(81, 4))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join(timeout=5)


class BaseWssPing(BaseWsPing):
    """Ping test for websocket wss scheme."""

    def run_test(self, port, n):
        for _ in range(n):
            asyncio.run(self.wss_ping_test(port))

    def run_wss(self, port, count=1, proxy=False):
        if proxy:
            self.start_all_servers()
        loop = asyncio.get_event_loop()
        for i in range(count):
            asyncio.ensure_future(websockets.serve(self.handler, SERVER_IP, port + i))
        loop.run_forever()


class WssPing(BaseWssPing):

    def test(self):
        gen_cert(hostname)
        self.p1 = Process(target=self.run_wss, args=(18099,))
        self.p2 = Process(target=self.run_test, args=(82, 4))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()


@marks.parameterize_class(
    [{"name": "HttpsH2", "proto": "https,h2"}, {"name": "H2Https", "proto": "h2,https"}]
)
class WssPingMultipleListeners(BaseWssPing):
    """
        The inheritance here is related to legacy code, please do not repeat this
        example in other tests
    """

    tempesta_template = {
        "config": """
listen 81;
listen 82 proto=%s;

srv_group default {

    server ${server_ip}:8099;
}
frang_limits {http_strict_host_checking false;}
tls_certificate ${general_workdir}/cert.pem;
tls_certificate_key ${general_workdir}/key.pem;
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
        """copy/paste from WssPing.test()"""
        gen_cert(hostname)
        self.p1 = Process(target=self.run_wss, args=(8099,))
        self.p2 = Process(target=self.run_test, args=(82, 4))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()


class WssPingProxy(WssPing):
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

    tempesta = {
        "config": TEMPESTA_NGINX_CONFIG % "",
    }

    def test(self):
        gen_cert(TEMPESTA_IP)
        self.p1 = Process(target=self.run_wss, args=(18099, 1, True))
        self.p2 = Process(target=self.run_test, args=(82, 4))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()
        self.get_server("nginx").stop_nginx()


class CacheTest(WsPing):
    """
    Test case - we never cache 101 responses
    First: Send upgrade HTTP connection and - get 101
    Second: Terminate websocket, call HTTP upgrade again - get 502
    """

    tempesta = {
        "config": TEMPESTA_CACHE_CONFIG % "",
    }

    async def handler(self, websocket, path):
        pass

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
        if r.status_code not in expected_status:
            self.fail(
                f"Test failed cause received invalid status_code: {r.status_code}, expected: {expected_status}"
            )

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(18099,))
        self.p1.start()
        self.start_tempesta()
        self.call_upgrade(81, [101])
        self.p1.terminate()
        self.call_upgrade(81, [502, 504])


class WssStress(WssPing):
    """
    Asynchronously make WSS Connections and restart tempesta
    """

    tempesta = {
        "config": TEMPESTA_STRESS_CONFIG,
    }

    def fibo(self, n):
        fib = [0, 1]
        for i in range(n):
            fib.append(fib[-2] + fib[-1])
            if fib[-1] > n:
                break
        return fib

    def run_test(self, port, n):
        count = 0
        for _ in range(n):
            count += 1
            asyncio.run(self.wss_ping_test(port))
        if (4000 - count) in self.fibo(4000):
            self.get_tempesta().restart()

    def test(self):
        gen_cert(hostname)
        self.p1 = Process(target=self.run_ws, args=(18099, 50))
        self.p2 = Process(target=self.run_test, args=(82, 4000))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()


class WssPipelining(WssPing):
    """
    We sent 3 pipelined requests against websocket.
    Expected - Connection closing
    """

    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "81"}]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    request = [
        "GET / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n"
        "GET / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n"
        "GET / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: V4wPm2Z/oOIUvp+uaX3CFQ==\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        "\r\n"
    ]

    async def handler(self, websocket, path):
        pass

    @dmesg.unlimited_rate_on_tempesta_node
    def test(self):
        self.p1 = Process(target=self.run_ws, args=(18099,))
        self.p1.start()
        self.start_tempesta()
        self.dmesg = dmesg.DmesgFinder(disable_ratelimit=True)
        time.sleep(5)

        self.deproxy_manager.start()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        deproxy_cl.ignore_response = True
        deproxy_cl.start()
        deproxy_cl.make_requests(self.request)
        deproxy_cl.wait_for_connection_close(timeout=5)

        self.assertTrue(
            self.dmesg.find(
                pattern="Request dropped: Pipelined request received after UPGRADE request",
                cond=dmesg.amount_positive,
            ),
            "Unexpected number of warnings",
        )

        for resp in deproxy_cl.responses:
            tf_cfg.dbg(3, resp)


class WsScheduler(WsPing):
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

    async def handler(self, websocket, path):
        global ping_message
        data = await websocket.recv()
        reply = f"{data}"
        if data != ping_message:
            self.fail("Wrong Ping Message")
        await websocket.send(reply)

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(18099, 4))
        self.p2 = Process(target=self.run_test, args=(81, 1500))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()


class RestartOnUpgrade(WsPing):
    """
    Asyncly create many Upgrade requests
    against WS during tempesta-fw restart.
    Expected - 101 response code
    """

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    async def handler(self, websocket, path):
        pass

    async def call_upgrade(self, port, expected_status):
        headers_ = {
            "Host": hostname,
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
        if r.status_code not in expected_status:
            self.fail(f"Received invalid status_code {r.status_code}")

    def fibo(self, n):
        fib = [0, 1]
        for _ in range(n):
            fib.append(fib[-2] + fib[-1])
            if fib[-1] > n:
                break
        return fib

    def run_test(self, port, n):
        for i in range(1500):
            asyncio.run(self.call_upgrade(port, n))
            if i in self.fibo(1500):
                self.get_tempesta().restart()

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(18099,))
        self.p2 = Thread(target=self.run_test, args=(81, [101]))
        self.p1.start()
        self.start_tempesta()
        time.sleep(2)
        self.p2.start()
        self.p2.join(timeout=60)
        self.p2 = None
