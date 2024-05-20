""" Example tests and checking functionality of services """

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import deproxy_server, external_client, nginx_server, tester, wrk_client
from helpers import deproxy, dmesg, tf_cfg
from helpers.control import Tempesta

# Number of bytes to test external client output
LARGE_OUTPUT_LEN = 1024**2


class ExampleTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: close

""",
        },
        {
            "id": "nginx",
            "type": "nginx",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        0.0.0.0:8000;

        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        },
    ]

    tempesta = {
        "config": """
cache 0;
listen 80;
frang_limits {http_strict_host_checking false;}
server ${server_ip}:8000;
""",
    }

    clients = [
        {
            "id": "wrk_0",
            "type": "wrk",
            "addr": "${server_ip}:8000",
        },
        {
            "id": "wrk_1",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "wrk_2",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
        {"id": "deproxy_direct", "type": "deproxy", "addr": "${server_ip}", "port": "8000"},
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": "-Ikf http://${tempesta_ip}:80/",
        },
        {
            "id": "curl_1",
            "type": "external",
            "binary": "curl",
            "cmd_args": "-Ikf http://${tempesta_ip}:80/",
        },
        # Output large amount of '@' symbol
        {
            "id": "large_output",
            "type": "external",
            "binary": "python3",
            "cmd_args": f"-c 'print(\"@\" * {LARGE_OUTPUT_LEN}, end=str())'",
        },
    ]

    @dmesg.limited_rate_on_tempesta_node
    def test_wrk_client(self):
        """Check results for 'wrk' client"""
        nginx: nginx_server.Nginx = self.get_server("nginx")
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        wrk1: wrk_client.Wrk = self.get_client("wrk_1")
        wrk1.start()
        self.wait_while_busy(wrk1)
        wrk1.stop()

        self.assertNotEqual(
            0,
            wrk1.requests,
            msg='"wrk" client has not sent requests or received results.',
        )

    @dmesg.limited_rate_on_tempesta_node
    def test_double_wrk(self):
        """Check the parallel work of two "wrk" clients"""
        nginx: nginx_server.Nginx = self.get_server("nginx")
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        wrk1: wrk_client.Wrk = self.get_client("wrk_1")
        wrk2: wrk_client.Wrk = self.get_client("wrk_2")

        wrk1.start()
        wrk2.start()
        self.wait_while_busy(wrk1, wrk2)
        wrk1.stop()
        wrk2.stop()

        err_msg = '"wrk" client has not sent requests or received results.'
        self.assertNotEqual(
            0,
            wrk1.requests,
            msg=err_msg,
        )
        self.assertNotEqual(
            0,
            wrk2.requests,
            msg=err_msg,
        )

    def test_deproxy_srv(self):
        """Simple test with deproxy server and check tempesta stats"""
        deproxy: deproxy_server.StaticDeproxyServer = self.get_server("deproxy")
        deproxy.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy.wait_for_connections(timeout=1))

        wrk1: wrk_client.Wrk = self.get_client("wrk_1")
        wrk1.start()
        self.wait_while_busy(wrk1)
        wrk1.stop()

        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()

        self.assertAlmostEqual(
            len(deproxy.requests),
            tempesta.stats.srv_msg_received,
            msg="Count of server request does not match tempesta stats.",
        )

    def test_deproxy_srv_direct(self):
        """Simple test with deproxy server"""
        deproxy = self.get_server("deproxy")
        deproxy.start()
        self.deproxy_manager.start()
        wrk0 = self.get_client("wrk_0")
        wrk0.start()
        self.wait_while_busy(wrk0)
        wrk0.stop()

    def test_deproxy_client(self):
        """Simple test with deproxy client"""
        nginx = self.get_server("nginx")
        nginx.start()
        self.start_tempesta()
        deproxy = self.get_client("deproxy")
        deproxy.start()
        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        deproxy.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        deproxy.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "nginx response:\n%s" % str(deproxy.last_response))

    def test_deproxy_client_direct(self):
        """Simple test with deproxy client"""
        nginx = self.get_server("nginx")
        nginx.start()
        deproxy = self.get_client("deproxy_direct")
        deproxy.start()
        self.deproxy_manager.start()
        deproxy.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        deproxy.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "nginx response:\n%s" % str(deproxy.last_response))

    def test_deproxy_srvclient(self):
        """Simple test with deproxy server"""
        dsrv = self.get_server("deproxy")
        dsrv.start()
        self.start_tempesta()
        cl = self.get_client("deproxy")
        cl.start()
        self.deproxy_manager.start()
        self.assertTrue(dsrv.wait_for_connections(timeout=1))
        cl.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        cl.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "deproxy response:\n%s" % str(cl.last_response))

    def test_deproxy_srvclient_direct(self):
        """Simple test with deproxy server"""
        dsrv = self.get_server("deproxy")
        dsrv.start()
        cl = self.get_client("deproxy_direct")
        cl.start()
        self.deproxy_manager.start()
        self.disable_deproxy_auto_parser()
        cl.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        cl.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "deproxy response:\n%s" % str(cl.last_response))

    def test_deproxy_srvclient_direct_check(self):
        """Simple test with deproxy server"""
        dsrv = self.get_server("deproxy")
        dsrv.start()
        cl = self.get_client("deproxy_direct")
        cl.start()
        self.deproxy_manager.start()
        self.disable_deproxy_auto_parser()
        cl.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        cl.wait_for_response(timeout=5)
        # expected response
        send = deproxy.Response(dsrv.response.decode())
        send.set_expected()
        self.assertEqual(cl.last_response, send)

    def test_curl(self):
        """Check results for 'curl' client"""
        nginx: nginx_server.Nginx = self.get_server("nginx")
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        curl: external_client.ExternalTester = self.get_client("curl")
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        self.assertIn(
            "200",
            curl.response_msg,
            "HTTP response status codes mismatch",
        )

    def test_double_curl(self):
        """Check the parallel work of two "curl" clients"""
        nginx: nginx_server.Nginx = self.get_server("nginx")
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        curl: external_client.ExternalTester = self.get_client("curl")
        curl1: external_client.ExternalTester = self.get_client("curl_1")

        curl.start()
        curl1.start()
        self.wait_while_busy(curl, curl1)
        curl.stop()
        curl1.stop()

        err_msg = '"Curl" client did not response message.'
        self.assertIn(
            "200",
            curl.response_msg,
            err_msg,
        )
        self.assertIn(
            "200",
            curl1.response_msg,
            err_msg,
        )

    def test_client_large_data_output(self):
        """
        Check that a large amount of data from the external client
        does not cause problems.
        Test could stuck in busy loop in case of error.
        The value of `LARGE_OUTPUT_LEN` may need to be changed
        to reproduce on different systems.
        (see issue #307)
        """
        client: external_client.ExternalTester = self.get_client("large_output")

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.response_msg, "@" * LARGE_OUTPUT_LEN)
