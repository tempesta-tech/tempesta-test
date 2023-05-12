"""
Tests for data integrity transferred via Tempesta TLS.
"""
import hashlib
from contextlib import contextmanager

from framework import tester
from helpers import analyzer, remote, sysnet, tf_cfg
from helpers.error import Error
from helpers.networker import NetWorker

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2023 Tempesta Technologies, Inc."
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


class TlsIntegrityTester(tester.TempestaTest, NetWorker):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "dummy",
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
            client.server_hostname = "tempesta-tech.com"
            client.make_request(self.make_req(req_len))
            res = client.wait_for_response(timeout=5)
            self.assertTrue(
                res, "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len)
            )
            resp = client.responses[-1].body
            tf_cfg.dbg(4, "\tDeproxy response (len=%d): %s..." % (len(resp), resp[:100]))
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

        try:
            # Deproxy client and server run on the same node and network
            # interface, so, regardless where the Tempesta node resides, we can
            # change MTU on the local interface only to get the same MTU for
            # both the client and server connections.
            dev = sysnet.route_dst_ip(remote.client, client.addr[0])
            prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
        except Error as err:
            self.fail(err)
        try:
            self.get_tso_state(dev)
            self.change_tso(dev, False)
            with self.mtu_ctx(remote.client, dev, prev_mtu):
                client.make_request(self.make_req(1))
                res = client.wait_for_response(timeout=1)
                self.assertTrue(res, "Cannot process response (len=%d)" % resp_len)
                sniffer.stop()
                self.assertTrue(sniffer.check_results(client.addr[0]), "Not optimal TCP flow")
            self.change_tso(dev, self.tso_state)
        finally:
            self.change_tso(dev, self.tso_state)
            sysnet.change_mtu(remote.client, dev, prev_mtu)


class Proxy(TlsIntegrityTester):
    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
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
        # self.common_check(1000000, 1000000)

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
        },
        {
            "id": "clnt2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "clnt3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "clnt4",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
            cache 1;
            cache_fulfill * *;
            cache_methods POST;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
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
        # self.common_check(1000000, 1000000)


class CacheH2(H2Base, Cache):
    clients = [
        {
            "id": f"clnt{step}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
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
        }
        for step in range(clients_n)
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }

    def common_check(self, req_len, resp_len):
        resp_body = "x" * resp_len
        hash1 = hashlib.md5(resp_body.encode()).digest()

        self.get_server("deproxy").set_response(self.make_resp(resp_body))

        clients = [self.get_client(client["id"]) for client in self.clients]

        for client in clients:
            client.responses = []
            client.valid_req_num = 0
            client.make_request(self.make_req(req_len))

        for client in clients:
            self.assertTrue(
                client.wait_for_response(timeout=5),
                "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len),
            )

        for client in clients:
            for response in client.responses:
                hash2 = hashlib.md5(response.body.encode()).digest()
                self.assertTrue(hash1 == hash2, "Bad response checksum")


class ManyClientsH2(H2Base, ManyClients):
    clients = [
        {
            "id": f"clnt{step}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
        for step in range(ManyClients.clients_n)
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


class CloseConnection(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "dummy",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
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
        client.server_hostname = "tempesta-tech.com"
        client.make_request(self.make_req(req_len))
        res = client.wait_for_response(timeout=5)
        self.assertTrue(
            res, "Cannot process request (len=%d) or response" " (len=%d)" % (req_len, resp_len)
        )
        resp = client.responses[-1].body
        tf_cfg.dbg(4, "\tDeproxy response (len=%d): %s..." % (len(resp), resp[:100]))
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

    # def test8(self):
    #     self.start_all()
    #     self.common_check(1000000, 1000000)
