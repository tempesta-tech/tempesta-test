#! /usr/bin/python3
from framework import tester, nginx_server

from multiprocessing import Process
from random import randint
import websockets
import asyncio
import time
import ssl
import os
from OpenSSL import crypto
from helpers import tempesta

from sched.test_ratio_static import NGINX_CONFIG


hostname = 'localhost'

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

NGINX_CONFIG = """

map $$http_upgrade $$connection_upgrade {
    default Upgrade;
    ''      close;
}

upstream websocket {
    ip_hash;
    server 127.0.0.1:8099;
}

upstream wss_websockets {
    ip_hash;
    server 127.0.0.1:8099;
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
"""

def cert_gen(
        emailAddress="emailAddress",
        commonName=hostname,
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10*365*24*60*60,
        KEY_FILE="/tmp/key.pem",
        CERT_FILE="/tmp/cert.pem"):
    haproxy_pem = "/tmp/out.pem"
    out_files = []
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode("utf-8"))
        out_files.append(CERT_FILE)
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        out_files.append(KEY_FILE)
    filenames = [CERT_FILE, KEY_FILE]
    with open('/tmp/out.pem', 'w') as outfile:
        for fname in filenames:
            with open(fname) as infile:
                for line in infile:
                    outfile.write(line)
    out_files.append(haproxy_pem)
    return out_files


def remove_certs(cert_files_):
    for cert in cert_files_:
        os.remove(cert)


class Ws_ping(tester.TempestaTest):

    backends = []        

    clients = []

    tempesta = {
        'config': TEMPESTA_CONFIG % "",
    }

    # Client

    def run_test(self, port, n):
        time.sleep(2.0)
        asyncio.run(self.ws_ping_test(port, n))

    async def ws_ping_test(self, port, n):
        host = hostname
        ping_message = "ping_test"
        for i in range(n):
            async with websockets.connect(f"ws://{host}:{port}") as websocket:
                await websocket.send(ping_message)
                await websocket.recv()

    async def wss_ping_test(self, port, n):
        host = hostname
        ping_message = "ping_test"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations("/tmp/cert.pem")
        for _ in range(n):
            async with websockets.connect(f"wss://{host}:{port}",
                                          ssl=ssl_context) as websocket:
                await websocket.send(ping_message)
                await websocket.recv()

    async def run_stress(port, n):
        print("run_stress")
        host = hostname
        ping_message = "ping_test"
        for _ in range(n):
            timeout_ = randint(9, 10)
            async with websockets.connect(f"ws://{host}:{port}",
                                          timeout=timeout_) as websocket:
                await websocket.send(ping_message)

    async def threaded_stress(self, i, port):
        tasks = []
        for _ in range(i):
            tasks.append(self.run_stress(port))
        await asyncio.gather(*tasks, return_exceptions=True)
        return 0

    def run_ws(self, port, count=1, proxy=False):
        cert_gen()
        ssl._create_default_https_context = ssl._create_unverified_context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain("/tmp/cert.pem", keyfile="/tmp/key.pem")

        self.start_tempesta()

        loop = asyncio.get_event_loop()
        for i in range(count):
            asyncio.ensure_future(websockets.serve(self.handler, hostname, port+i))
        loop.run_forever()

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099,))
        p2 = Process(target=self.run_test, args=(81, 4))
        p1.start()
        p2.start()
        p2.join()
        p1.terminate()
        p2.terminate()

    # Backend

    def remove_certs(self, cert_files_):
        for cert in cert_files_:
            os.remove(cert)

    async def handler(self, websocket, path):
        data = await websocket.recv()
        reply = f"{data}"
        await websocket.send(reply)


class Wss_ping(Ws_ping):

    def run_test(self, port, n):
        time.sleep(2.0)
        asyncio.run(self.wss_ping_test(port, n))

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099,))
        p2 = Process(target=self.run_test, args=(82, 4))
        p1.start()
        p2.start()
        p2.join()
        p1.terminate()
        remove_certs(['/tmp/cert.pem', '/tmp/key.pem', '/tmp/out.pem'])


class Wss_ping_with_nginx(Wss_ping):

    tempesta = {
        'config': TEMPESTA_NGINX_CONFIG % "",
    }

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099, 1, True))
        p2 = Process(target=self.run_test, args=(82, 4))
        p1.start()
        p2.start()
        p2.join()
        p1.terminate()


class Wss_stress(Wss_ping):

    tempesta = {
        'config': TEMPESTA_STRESS_CONFIG,
    }

    def run_test(self, port, n):
        time.sleep(2.0)
        asyncio.run(self.wss_ping_test(port, n))

    def test_ping_websockets(self):
        p1 = Process(target=self.run_ws, args=(8099, 8))
        p2 = Process(target=self.run_test, args=(82, 1000))
        p1.start()
        p2.start()
        p2.join()
        p1.terminate()

    async def wss_ping_test(self, port, n):
        host = hostname
        ping_message = "ping_test"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations("/tmp/cert.pem")
        for _ in range(n):
            async with websockets.connect(f"wss://{host}:{port}",
                                          ssl=ssl_context) as websocket:
                await websocket.send(ping_message)
                await websocket.recv()
