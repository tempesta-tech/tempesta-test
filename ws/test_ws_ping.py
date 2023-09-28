#! /usr/bin/python3

import asyncio
import ssl
import time
from multiprocessing import Process
from threading import Thread

import requests
import websockets

from framework import tester
from framework.x509 import CertGenerator
from helpers import tf_cfg

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
%s
"""

TEMPESTA_STRESS_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group default {

    server ${server_ip}:8099;
    server ${server_ip}:8100;
    server ${server_ip}:8101;
    server ${server_ip}:8102;
    server ${server_ip}:8103;
    server ${server_ip}:8104;
    server ${server_ip}:8105;
    server ${server_ip}:8106;
    server ${server_ip}:8107;
    server ${server_ip}:8108;
    server ${server_ip}:8109;
    server ${server_ip}:8110;
    server ${server_ip}:8111;
    server ${server_ip}:8112;
    server ${server_ip}:8113;
    server ${server_ip}:8114;
    server ${server_ip}:8115;
    server ${server_ip}:8116;
    server ${server_ip}:8117;
    server ${server_ip}:8118;
    server ${server_ip}:8119;
    server ${server_ip}:8120;
    server ${server_ip}:8121;
    server ${server_ip}:8122;
    server ${server_ip}:8123;
    server ${server_ip}:8124;
    server ${server_ip}:8125;
    server ${server_ip}:8126;
    server ${server_ip}:8127;
    server ${server_ip}:8128;
    server ${server_ip}:8129;
    server ${server_ip}:8130;
    server ${server_ip}:8131;
    server ${server_ip}:8132;
    server ${server_ip}:8133;
    server ${server_ip}:8134;
    server ${server_ip}:8135;
    server ${server_ip}:8136;
    server ${server_ip}:8137;
    server ${server_ip}:8138;
    server ${server_ip}:8139;
    server ${server_ip}:8140;
    server ${server_ip}:8141;
    server ${server_ip}:8142;
    server ${server_ip}:8143;
    server ${server_ip}:8144;
    server ${server_ip}:8145;
    server ${server_ip}:8146;
    server ${server_ip}:8147;
    server ${server_ip}:8148;
    server ${server_ip}:8149;
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

    server ${server_ip}:8099;
}

vhost default {
    proxy_pass default;
}

access_log on;

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
        server ${server_ip}:8099;
    }

    upstream wss_websockets {
        ip_hash;
        server ${server_ip}:8099;
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


class WsPing(tester.TempestaTest):
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

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(8099,))
        self.p2 = Process(target=self.run_test, args=(81, 4))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join(timeout=5)

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


class WssPing(WsPing):
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

    def test(self):
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
        self.p1 = Process(target=self.run_wss, args=(8099, 1, True))
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
        self.p1 = Process(target=self.run_ws, args=(8099,))
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
        self.p1 = Process(target=self.run_ws, args=(8099, 50))
        self.p2 = Process(target=self.run_test, args=(82, 4000))
        self.p1.start()
        self.start_tempesta()
        self.p2.start()
        self.p2.join()


class WsPipelining(WsPing):
    """
    We sent 3 pipelined requests against websocket.
    Expected - 101, 502, 502 response codes
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

    def test(self):
        self.p1 = Process(target=self.run_ws, args=(8099,))
        self.p1.start()
        self.start_tempesta()
        time.sleep(5)

        self.deproxy_manager.start()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        deproxy_cl.start()
        deproxy_cl.make_requests(self.request)
        deproxy_cl.wait_for_response(timeout=5)

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
                server ${server_ip}:8099 conns_n=16;
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
        self.p1 = Process(target=self.run_ws, args=(8099, 4))
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
        self.p1 = Process(target=self.run_ws, args=(8099,))
        self.p2 = Thread(target=self.run_test, args=(81, [101]))
        self.p1.start()
        self.start_tempesta()
        time.sleep(2)
        self.p2.start()
        self.p2.join(timeout=60)
        self.p2 = None
