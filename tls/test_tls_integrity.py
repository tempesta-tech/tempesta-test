"""test_tls_integrit
Tests for data integrity transferred via Tempesta TLS.
"""

import hashlib
from contextlib import contextmanager

import run_config
from helpers import analyzer, networker, remote
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class H2Base:
    @staticmethod
    def make_req(req_len):
        return (
            [
                (":authority", "example.com"),
                (":path", f"/{req_len}"),
                (":scheme", "https"),
                (":method", "POST"),
            ],
            "x" * req_len,
        )


class TlsIntegrityTester(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    def start_all(self):
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=1), "No connection from Tempesta to backends"
        )

    @staticmethod
    def make_resp(body):
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: " + str(len(body)) + "\r\n"
            "Connection: keep-alive\r\n\r\n" + body
        )

    @staticmethod
    def make_req(req_len):
        return (
            "POST /" + str(req_len) + " HTTP/1.1\r\n"
            "Host: tempesta-tech.com\r\n"
            "Content-Length: " + str(req_len) + "\r\n"
            "\r\n" + ("x" * req_len)
        )

    def common_check(self, req_len, resp_len):
        resp_body = "x" * resp_len
        hash1 = hashlib.md5(resp_body.encode()).digest()

        self.get_server("deproxy").set_response(self.make_resp(resp_body))

        for clnt in self.clients:
            client = self.get_client(clnt["id"])
            client.make_request(self.make_req(req_len))
            res = client.wait_for_response(timeout=5)
            self.assertTrue(
                res, "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len)
            )
            resp = client.responses[-1].body
            hash2 = hashlib.md5(resp.encode()).digest()
            self.assertTrue(hash1 == hash2, "Bad response checksum")

    @contextmanager
    def tcp_flow_check(self, resp_len, mtu=1500):
        """Check how Tempesta generates TCP segments for TLS records."""
        # Run the sniffer first to let it start in separate thread.
        sniffer = analyzer.AnalyzerTCPSegmentation(
            remote.tempesta, "Tempesta", timeout=3, ports=(443, 8000)
        )
        sniffer.start()

        resp_body = "x" * resp_len
        self.get_server("deproxy").set_response(self.make_resp(resp_body))

        client = self.get_client(self.clients[0]["id"])

        with networker.change_and_restore_tso_gro_gso(tso_gro_gso=False, mtu=mtu):
            client.make_request(self.make_req(1))
            self.assertTrue(client.wait_for_response(timeout=1))
            sniffer.stop()
            self.assertTrue(sniffer.check_results(client.addr[0]), "Not optimal TCP flow")


class Proxy(TlsIntegrityTester):
    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
            }
        """
    }

    def test_various_req_resp_sizes(self):
        self.start_all()
        self.common_check(1, 1)
        self.common_check(19, 19)
        self.common_check(567, 567)
        self.common_check(1755, 1755)
        self.common_check(4096, 4096)
        self.common_check(16380, 16380)
        self.common_check(65536, 65536)
        if not run_config.TCP_SEGMENTATION:
            self.common_check(1000000, 1000000)

    def test_tcp_segs(self):
        """
        This is a functional test for tcp_segmentation
        you can run in this example we pass 7020 bytes
        ##############################################
                    7020        7020+overhead
            backend -> tempesta -> client
        ##############################################
        with mtu it will be splitted into segments and
        analyze traffic.
        Set payload and mtu in test like code below and
        run test with -v -v to see what happens
        """
        self.start_all()
        self.tcp_flow_check(7020, mtu=1500)


class ProxyH2(H2Base, Proxy):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=h2;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }


class Cache(TlsIntegrityTester):
    clients = [
        {
            "id": "clnt1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
        {
            "id": "clnt2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
        {
            "id": "clnt3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
        {
            "id": "clnt4",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    tempesta = {
        "config": """
            cache 1;
            cache_fulfill * *;
            cache_methods POST;
            listen 443 proto=https;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
                }
        """
    }

    def test_various_req_resp_sizes(self):
        self.start_all()
        self.common_check(1, 1)
        self.common_check(19, 19)
        self.common_check(567, 567)
        self.common_check(1755, 1755)
        self.common_check(4096, 4096)
        if not run_config.TCP_SEGMENTATION:
            self.common_check(16380, 16380)
            self.common_check(65536, 65536)
            self.common_check(1000000, 1000000)


class CacheH2(H2Base, Cache):
    clients = [
        {
            "id": f"clnt{step}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for step in range(4)
    ]

    tempesta = {
        "config": """
            cache 1;
            cache_fulfill * *;
            cache_methods POST;
            listen 443 proto=h2;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }


class ManyClients(Cache):
    clients_n = 10

    clients = [
        {
            "id": f"clnt{step}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for step in range(clients_n)
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            server ${server_ip}:8000;
        """
    }

    def common_check(self, req_len, resp_len):
        resp_body = "x" * resp_len
        hash1 = hashlib.md5(resp_body.encode()).digest()

        self.get_server("deproxy").set_response(self.make_resp(resp_body))

        clients = self.get_clients()

        reqeust = clients[0].create_request(method="POST", headers=[], body=req_len * "x")
        for client in clients:
            client.make_request(reqeust)

        for client in clients:
            self.assertTrue(
                client.wait_for_response(timeout=25),
                "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len),
            )

        for client in clients:
            hash2 = hashlib.md5(client.last_response.body.encode()).digest()
            self.assertEqual(hash1, hash2, "Bad response checksum")


class ManyClientsH2(H2Base, ManyClients):
    clients = [
        {
            "id": f"clnt{step}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for step in range(ManyClients.clients_n)
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=h2;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            server ${server_ip}:8000;
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
            }
        """
    }


class CloseConnection(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
            }
        """
    }

    def start_all(self):
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=1), "No connection from Tempesta to backends"
        )

    @staticmethod
    def make_resp(body):
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: " + str(len(body)) + "\r\n"
            "Connection: keep-alive\r\n\r\n" + body
        )

    @staticmethod
    def make_req(req_len):
        return (
            "GET /" + str(req_len) + " HTTP/1.1\r\n"
            "Host: tempesta-tech.com\r\n"
            "Connection: close\r\n\r\n"
        )

    def common_check(self, req_len, resp_len):
        resp_body = "x" * resp_len
        hash1 = hashlib.md5(resp_body.encode()).digest()

        self.get_server("deproxy").set_response(self.make_resp(resp_body))

        client = self.get_client(self.clients[0]["id"])
        client.make_request(self.make_req(req_len))
        res = client.wait_for_response(timeout=5)
        self.assertTrue(
            res, "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len)
        )
        resp = client.responses[-1].body
        hash2 = hashlib.md5(resp.encode()).digest()
        self.assertTrue(hash1 == hash2, "Bad response checksum")

    def test1(self):
        self.start_all()
        self.common_check(1, 1)

    def test2(self):
        self.start_all()
        self.common_check(19, 19)

    def test3(self):
        self.start_all()
        self.common_check(567, 567)

    def test4(self):
        self.start_all()
        self.common_check(1755, 1755)

    def test5(self):
        self.start_all()
        self.common_check(4096, 4096)

    def test6(self):
        self.start_all()
        self.common_check(16380, 16380)

    def test7(self):
        self.start_all()
        self.common_check(65536, 65536)

    def test8(self):
        self.start_all()
        self.common_check(1000000, 1000000)
