""""""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from framework import deproxy_server
from helpers import deproxy, tf_cfg
from t_long_body import utils
from test_suite import tester, marks

BODY_SIZE = 1024**2 * 50  # MB
MEMORY_LEAK_THRESHOLD = 128  # MB


@marks.parameterize_class(
    [
        {"name": "Https", "client_prefix": "https"},
        {"name": "H2", "client_prefix": "h2"}
    ]
)
class TestFinishConnectionByClient(tester.TempestaTest):
    """ Tests for issue #2284. """

    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2,https;

    # srv_group default {
        server ${server_ip}:8000 conns_n=1;
        server_queue_size 100;
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
            "id": "h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "https",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "h2-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "https-1",
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
            "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    client_prefix: str

    def get_used_memory(self) -> int:
        """Get used system memory in <<MB>>."""
        stdout, _ = self.get_tempesta().node.run_cmd("free --mega")
        return int(stdout.decode().split("\n")[1].split()[2])

    def test_reset_connection(self):
        self.disable_deproxy_auto_parser()

        server: deproxy_server.StaticDeproxyServer = self.get_server('deproxy')
        client = self.get_client(self.client_prefix)
        bad_client = self.get_client(f"{self.client_prefix}-1")
        request = client.create_request(method='GET',headers=[])
        large_request = bad_client.create_request(
            method='POST',headers=[("Content-Length", BODY_SIZE)],body=BODY_SIZE * 'x'
        )

        server.conns_n = 1
        self.start_all_services()

        used_memory_before = self.get_used_memory()

        client.make_requests([request] * 10)
        self.assertTrue(client.wait_for_client_sends_requests(), "The valid client must send all requests first.")
        bad_client.make_requests([large_request] * 10)
        self.assertTrue(
            bad_client.wait_for_client_sends_requests(timeout=30),
            "The bad client have no time to sending large requests."
        )

        bad_client.stop()
        server.not_send_response = False

        self.assertTrue(client.wait_for_response())

        # time.sleep(20)

        used_memory_after = self.get_used_memory()

        print(f"{used_memory_before = }")
        print(f"{used_memory_after = }")

        self.assertAlmostEqual(first=used_memory_before, second=used_memory_after, delta=64)

    @marks.Parameterize.expand(
        [
            marks.Param(name="reset_connections", stop_func_name="stop_with_rst"),
            marks.Param(name="close_connections", stop_func_name="stop"),
        ]
    )
    def test_large_response_body(self, name, stop_func_name):
        """
        Tempesta FW must close a server connection when a client closes a connection via RST\FIN TCP
        if the server did not have time to send the full response.
        """
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
        server_conn_list_before = set(server.connections)

        client = self.get_client(self.client_name)
        requests = [client.create_request(method='GET', headers=[])] * server.conns_n
        for i in range(server.conns_n):
            client.start()
            # client.make_requests(requests)
            client.make_request(client.create_request(method='GET', headers=[]))
            # server.wait_for_requests(server.conns_n * (i + 1))
            server.wait_for_requests(n=i+1)
            client.stop()

        used_memory_after = self.get_used_memory()

        self.assertWaitUntilFalse(
            lambda : set(server_conn_list_before) & set(server.connections),
            f"Tempesta FW must close all dead connections."
        )
        self.assertAlmostEqual(
            first=used_memory_before, second=used_memory_after, delta=used_memory_before + MEMORY_LEAK_THRESHOLD
        )
