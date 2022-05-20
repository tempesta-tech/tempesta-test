#! /usr/bin/python3

from framework import tester

from multiprocessing import Process
from random import randint
import websockets
import asyncio
import ssl
import os
import requests
from framework.x509 import CertGenerator

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

hostname = 'localhost'
ping_message = "ping_test"


TEMPESTA_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group localhost {

    server ${server_ip}:8099;
}

vhost localhost {
    tls_certificate /tmp/cert.pem;
    tls_certificate_key /tmp/key.pem;

    proxy_pass localhost;

}

http_chain {
    -> localhost;
}
%s
"""

TEMPESTA_STRESS_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group localhost {

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

vhost localhost {
    tls_certificate /tmp/cert.pem;
    tls_certificate_key /tmp/key.pem;

    proxy_pass localhost;

}

http_chain {
    -> localhost;
}
"""

TEMPESTA_NGINX_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group localhost {
    server ${server_ip}:8000;
}

vhost localhost {
    tls_certificate /tmp/cert.pem;
    tls_certificate_key /tmp/key.pem;

    proxy_pass localhost;

}

http_chain {
    -> localhost;
}
%s
"""

TEMPESTA_CACHE_CONFIG = """
listen 81;
listen 82 proto=https;

srv_group localhost {

    server ${server_ip}:8099;
}

vhost localhost {
    tls_certificate /tmp/cert.pem;
    tls_certificate_key /tmp/key.pem;

    proxy_pass localhost;

}

access_log on;

cache 1;
cache_fulfill * *;

http_chain {
    -> localhost;
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
        server 0.0.0.0:8099;
    }

    upstream wss_websockets {
        ip_hash;
        server 0.0.0.0:8099;
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
        ssl_certificate /tmp/cert.pem;
        ssl_certificate_key /tmp/key.pem;
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
    cert_path = "/tmp/cert.pem"
    key_path = "/tmp/key.pem"
    cgen = CertGenerator(cert_path, key_path)
    cgen.CN = host_name
    cgen.generate()


def remove_certs(cert_files_):
    for cert in cert_files_:
        os.remove(cert)


class WsPing(tester.TempestaTest):

    """ Ping test for websocket ws scheme """

    backends = []

    clients = []

    tempesta = {
        'config': TEMPESTA_CONFIG % "",
    }

    # Client

    def run_test(self, port, n):
        asyncio.run(self.ws_ping_test(port, n))

    async def ws_ping_test(self, port, n):
        global ping_message
        host = hostname
        for i in range(n):
            async with websockets.connect(f"ws://{host}:{port}") as websocket:
                await websocket.send(ping_message)
                await websocket.recv()
                await websocket.close()

    async def wss_ping_test(self, port, n):
        global ping_message
        host = hostname
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations("/tmp/cert.pem")
        for _ in range(n):
            async with websockets.connect(f"wss://{host}:{port}",
                                          ssl=ssl_context) as websocket:
                await websocket.send(ping_message)
                await websocket.recv()
                await websocket.close()

    def run_ws(self, port, count=1, proxy=False):
        gen_cert(hostname)
        ssl._create_default_https_context = ssl._create_unverified_context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain("/tmp/cert.pem", keyfile="/tmp/key.pem")
        if proxy:
            self.start_all_servers()
        loop = asyncio.get_event_loop()
        for i in range(count):
            asyncio.ensure_future(websockets.serve(self.handler,
                                  hostname, port+i))
        loop.run_forever()

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099,))
        p2 = Process(target=self.run_test, args=(81, 4))
        p1.start()
        self.start_tempesta()
        p2.start()
        p2.join()
        p1.terminate()
        p2.terminate()

    # Backend

    def remove_certs(self, cert_files_):
        for cert in cert_files_:
            os.remove(cert)

    async def handler(self, websocket, path):
        global ping_message
        data = await websocket.recv()
        reply = f"{data}"
        if f"{data}" != ping_message:
            self.fail("Ping message corrupted")
        await websocket.send(reply)


class WssPing(WsPing):

    """ Ping test for websocket wss scheme. """

    def run_test(self, port, n):
        asyncio.run(self.wss_ping_test(port, n))

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099,))
        p2 = Process(target=self.run_test, args=(82, 4))
        p1.start()
        self.start_tempesta()
        p2.start()
        p2.join()
        p1.terminate()
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem'])


class WssPingProxy(WssPing):

    """
    Ping test for websocket wss scheme with nginx proxying TLS
    Scheme: WSClient (TLS)-> Tempesta-fw -> NGINX (TLS)-> wss
    """

    backends = [{
        'id': 'nginx',
        'type': 'nginx',
        'port': '8000',
        'status_uri': 'http://${server_ip}:8000/nginx_status',
        'config': NGINX_CONFIG,
    }]

    tempesta = {
        'config': TEMPESTA_NGINX_CONFIG % "",
    }

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099, 1, True))
        p2 = Process(target=self.run_test, args=(82, 4))
        p1.start()
        self.start_tempesta()
        p2.start()
        p2.join()
        p1.terminate()
        self.get_server('nginx').stop_nginx()
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem'])


class CacheTest(WssPing):

    """
    Test case - we never cache 101 responses
    First: Send upgrade HTTP connection and - get 101
    Second: Terminate websocket, call HTTP upgrade again - get 502
    """

    tempesta = {
        'config': TEMPESTA_CACHE_CONFIG % "",
    }

    async def handler(self, websocket, path):
        pass

    def call_upgrade(self, port, expected_status):
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

        r = requests.get(f'http://{hostname}:{port}', auth=('user', 'pass'),
                         headers=headers_)
        if r.status_code != expected_status:
            self.fail("Test failed cause recieved invalid status_code")

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099,))
        p1.start()
        self.start_tempesta()
        self.call_upgrade(81, 101)
        p1.terminate()
        self.call_upgrade(81, 502)
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem'])


class WssStress(WssPing):

    """
    Asynchronously make WSS Connections and restart tempesta
    """

    tempesta = {
        'config': TEMPESTA_STRESS_CONFIG,
    }

    def fibo(self, n):
        fib = [0, 1]
        for i in range(n):
            fib.append(fib[-2]+fib[-1])
            if fib[-1] > n:
                break
        return fib

    def run_test(self, port, n):
        asyncio.run(self.stress_ping_test(port, n))

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099, 50))
        p2 = Process(target=self.run_test, args=(82, 4000))
        p1.start()
        self.start_tempesta()
        p2.start()
        p2.join()
        p1.terminate()
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem'])

    async def stress_ping_test(self, port, n):
        host = hostname
        global ping_message
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations("/tmp/cert.pem")
        count = 0
        for _ in range(n):
            count += 1
            if (4000-count) in self.fibo(4000):
                self.get_tempesta().restart()
            async with websockets.connect(f"wss://{host}:{port}",
                                          ssl=ssl_context) as websocket:
                await websocket.send(ping_message)
                await websocket.recv()
                await websocket.close()
