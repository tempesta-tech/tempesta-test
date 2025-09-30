"""Tests for long body in response."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import curl_client, deproxy_server
from helpers import deproxy, tf_cfg
from helpers.networker import NetWorker
from t_long_body import utils
from test_suite import checks_for_tests as checks
from test_suite.tester import TempestaTest
from typing import Callable

BODY_SIZE = 1024**2 * int(tf_cfg.cfg.get("General", "long_body_size"))


class LongBodyInResponse(TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=https;
listen 4433 proto=h2;

server ${server_ip}:8000;

frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
cache 0;
"""
    }

    clients = [
        {
            "id": "curl-http",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "curl-https",
            "type": "curl",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
        },
        {
            "id": "curl-h2",
            "type": "curl",
            "http2": True,
            "addr": "${tempesta_ip}:4433",
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

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def _test(self, client_id: str, header: str, body_func: Callable):
        """
        Send GET request and receive response with long body. Check that Tempesta does not crash.
        """
        self.start_all_services(client=False)
        self.disable_deproxy_auto_parser()

        server: deproxy_server.StaticDeproxyServer = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"{header}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + body_func(BODY_SIZE)
        )

        client: curl_client.CurlClient = self.get_client(client_id)
        client.options = [" --raw"]
        client.start()
        self.assertTrue(client.wait_for_finish(timeout=30))
        client.stop()

        self.assertIsNotNone(client.last_response)
        if client.http2:
            self.assertEqual(client.last_response.stdout, utils.create_simpple_body(BODY_SIZE))
        else:
            self.assertEqual(client.last_response.stdout, body_func(BODY_SIZE))
        checks.check_tempesta_request_and_response_stats(
            self.get_tempesta(),
            cl_msg_received=1,
            cl_msg_forwarded=1,
            srv_msg_received=1,
            srv_msg_forwarded=1,
        )

    def test_http(self):
        self._test(
            client_id="curl-http", header=f"Content-Length: {BODY_SIZE}", body_func=utils.create_simpple_body
        )

    def test_https(self):
        self._test(
            client_id="curl-https", header=f"Content-Length: {BODY_SIZE}", body_func=utils.create_simpple_body
        )

    def test_h2(self):
        self._test(client_id="curl-h2", header=f"Content-Length: {BODY_SIZE}", body_func=utils.create_simpple_body)

    def test_http_one_big_chunk(self):
        self._test(
            client_id="curl-http",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_one_big_chunk,
        )

    def test_https_one_big_chunk(self):
        self._test(
            client_id="curl-https",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_one_big_chunk,
        )

    def test_h2_one_big_chunk(self):
        self._test(
            client_id="curl-h2",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_one_big_chunk,
        )

    def test_http_many_big_chunks(self):
        self._test(
            client_id="curl-http",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_many_big_chunks,
        )

    def test_https_many_big_chunks(self):
        self._test(
            client_id="curl-https",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_many_big_chunks,
        )

    def test_h2_many_big_chunks(self):
        self._test(
            client_id="curl-h2",
            header="Transfer-Encoding: chunked",
            body_func=utils.create_many_big_chunks,
        )
