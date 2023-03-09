"""
Tests for data integrity transferred via Tempesta TLS.
"""
import hashlib
from contextlib import contextmanager

from framework import tester
from helpers import analyzer, remote, sysnet, tf_cfg
from helpers.error import Error

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TlsIntegrityTester(tester.TempestaTest):

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
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            "Date: test\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    def start(self):
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=1), "No connection from Tempesta to backends"
        )

    def start_all(self):
        self.start()
        self.start_all_clients()

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
            tf_cfg.dbg(4, "\tDeproxy response (len=%d): %s..." % (len(resp), resp[:100]))
            hash2 = hashlib.md5(resp.encode()).digest()
            self.assertTrue(hash1 == hash2, "Bad response checksum")

    @contextmanager
    def mtu_ctx(self, node, dev, mtu):
        try:
            yield
        finally:
            sysnet.change_mtu(node, dev, mtu)

    def _get_state(self, dev, what):
        cmd = f"ethtool --show-features {dev} | grep {what}"
        out = remote.client.run_cmd(cmd)
        return out[0].decode("utf-8").split(" ")[-1].strip("\n")

    def get_tso_state(self, dev):
        tso_state = self._get_state(dev, "tcp-segmentation-offload")
        if tso_state == "on":
            self.tso_state = True
        else:
            self.tso_state = False

    def get_gro_state(self, dev):
        gro_state = self._get_state(dev, "generic-receive-offload")
        if gro_state == "on":
            self.gro_state = True
        else:
            self.gro_state = False

    def get_gso_state(self, dev):
        gso_state = self._get_state(dev, "generic-segmentation-offload")
        if gso_state == "on":
            self.gso_state = True
        else:
            self.gso_state = False

    def _set_state(self, dev, what, on=True):
        if on:
            cmd = f"ethtool -K {dev} {what} on"
        else:
            cmd = f"ethtool -K {dev} {what} off"
        out = remote.client.run_cmd(cmd)

    def change_tso(self, dev, on=True):
        self._set_state(dev, "tso", on)

    def change_gro(self, dev, on=True):
        self._set_state(dev, "gro", on)

    def change_gso(self, dev, on=True):
        self._set_state(dev, "gso", on)

    def _tcp_off_tso_gro_gso(self, client, addr, funtion, mtu):
        try:
            # Deproxy client and server run on the same node and network
            # interface, so, regardless where the Tempesta node resides, we can
            # change MTU on the local interface only to get the same MTU for
            # both the client and server connections.
            dev = sysnet.route_dst_ip(remote.client, addr)
            prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
        except Error as err:
            self.fail(err)
        try:
            self.get_tso_state(dev)
            self.get_gro_state(dev)
            self.get_gso_state(dev)
            self.change_tso(dev, False)
            self.change_gro(dev, False)
            self.change_gso(dev, False)

            funtion(client)
        finally:
            self.change_tso(dev, self.tso_state)
            self.change_gro(dev, self.gro_state)
            self.change_gso(dev, self.gro_state)
            sysnet.change_mtu(remote.client, dev, prev_mtu)

    def _simple_tcp_off_tso_gro_gso(self, client):
        server = self.get_server("deproxy")

        header = ("qwerty", "x" * 10000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            "Date: test\r\n"
            f"{header[0]}: {header[1]}\r\n"
            "Content-Length: 0\r\n\r\n"
        )

        client.send_settings_frame(header_table_size=2048)
        client.wait_for_ack_settings()

        client.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "POST"),
            ],
            expected_status_code="200",
        )
        self.assertIsNotNone(client.last_response.headers.get(header[0]))
        self.assertEqual(len(client.last_response.headers.get(header[0])), len(header[1]))

    def _stress_tcp_off_tso_gro_gso(self, client):
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def tcp_off_tso_gro_gso(self, client, mtu):
        self._tcp_off_tso_gro_gso(client, client.addr[0], self._simple_tcp_off_tso_gro_gso, mtu)

    def tcp_off_tso_gro_gso_stress(self, client, mtu):
        self._tcp_off_tso_gro_gso(client, "127.0.0.1", self._stress_tcp_off_tso_gro_gso, mtu)

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


class NetSettings(TlsIntegrityTester):

    clients = [
        {
            "id": "deproxy_h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (" https://${tempesta_ip}" " -c100" " -t2" " -m100" " -D10"),
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=h2;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }

    def test_off_tso_gro_gso(self):
        self.start()

        client = self.get_client("deproxy_h2")
        client.start()
        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        self.tcp_off_tso_gro_gso(client, mtu=1500)

    def test_off_tso_gro_gso_stress(self):
        self.start()

        client = self.get_client("h2load")
        client.start()

        self.tcp_off_tso_gro_gso_stress(client, mtu=1500)


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
        self.common_check(1000000, 1000000)


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

    def test8(self):
        self.start_all()
        self.common_check(1000000, 1000000)
