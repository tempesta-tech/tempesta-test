""""""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import time

from framework import deproxy_server
from helpers import deproxy, remote, tf_cfg
from t_long_body import utils
from test_suite import tester, marks

BODY_SIZE = 1024**2 * 1  # MB


@marks.parameterize_class(
    [
        {"name": "Https", "client_name": "deproxy"},
        {"name": "H2", "client_name": "deproxy-h2"}
    ]
)
class TestFinishConnectionByClient(tester.TempestaTest):
    """ Tests for issue #2284. """

    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=https,h2;

    # srv_group default {
        server ${server_ip}:8000 conns_n=1;
        # server_queue_size 1;
    # }
    frang_limits { http_methods get put post; }
    
    frang_limits {http_strict_host_checking false;}
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    cache 0;
    """
    }

    clients = [
        {
            "id": "deproxy-h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
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

    client_name: str

    def get_used_memory(self) -> int:
        """Get used system memory in <<MB>>."""
        stdout, _ = self.get_tempesta().node.run_cmd("free --mega")
        return int(stdout.decode().split("\n")[1].split()[2])

    def test_reset_connection(self):
        server: deproxy_server.StaticDeproxyServer = self.get_server('deproxy')
        server.conns_n = 1
        self.disable_deproxy_auto_parser()
        self.start_all_services()

        used_memory_before = self.get_used_memory()

        client = self.get_client("deproxy")
        client_2 = self.get_client('deproxy-h2')
        request = client.create_request(
            method='PUT',
            # headers=[],
            headers=[("Content-Length", str(BODY_SIZE))],
            body=BODY_SIZE * 'x'
        )

        client.make_request(request)
        client_2.make_request(
            client_2.create_request(
                method='PUT',
                # headers=[],
                headers=[],
                body=BODY_SIZE * 'x'
            )
        )

        server.wait_for_requests(n=2, timeout=5)
        print(len(server.requests))

        client.stop_client_with_rst()

        used_memory_after = self.get_used_memory()

        self.assertAlmostEqual(first=used_memory_before, second=used_memory_after, delta=used_memory_before // 5)

    def test_reset_connection_by_clients(self):
        server: deproxy_server.StaticDeproxyServer = self.get_server('deproxy')
        server.conns_n = 128
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"Content-Length: {BODY_SIZE}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + utils.create_simpple_body(BODY_SIZE - 10)
        )

        self.disable_deproxy_auto_parser()
        self.start_all_services()

        used_memory_before = self.get_used_memory()

        client = self.get_client(self.client_name)
        for i in range(server.conns_n):
            client.start()
            client.make_request(request=client.create_request(method='GET', headers=[]))

            server.wait_for_requests(n=i+1)

            client.stop_client_with_rst()

        used_memory_after = self.get_used_memory()

        self.assertAlmostEqual(first=used_memory_before, second=used_memory_after, delta=used_memory_before * 0.2)

    def test_close_connection_by_clients(self):
        server: deproxy_server.StaticDeproxyServer = self.get_server('deproxy')
        server.conns_n = 128
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"Content-Length: {BODY_SIZE}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + utils.create_simpple_body(BODY_SIZE - 10)
        )

        self.disable_deproxy_auto_parser()
        self.start_all_services()

        used_memory_before = self.get_used_memory()

        client = self.get_client(self.client_name)
        for i in range(server.conns_n):
            client.start()
            client.make_request(request=client.create_request(method='GET', headers=[]))

            server.wait_for_requests(n=i+1)

            client.stop()

        used_memory_after = self.get_used_memory()
        time.sleep(2)

        self.assertAlmostEqual(first=used_memory_before, second=used_memory_after, delta=used_memory_before * 0.2)
