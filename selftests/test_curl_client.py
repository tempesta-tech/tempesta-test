import unittest
from unittest.mock import ANY, patch

from framework import tester
from framework.curl_client import CurlArguments, CurlClient, CurlResponse

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


MULTIPLE_RESPONSES = b"""HTTP/1.1 200\r
date: test\r
content-length: 1\r
via: 2.0 tempesta_fw (Tempesta FW pre-0.7.0)\r
server: Tempesta FW/pre-0.7.0\r
\r
HTTP/1.1 200\r
date: test\r
content-length: 2\r
via: 2.0 tempesta_fw (Tempesta FW pre-0.7.0)\r
server: Tempesta FW/pre-0.7.0\r
\r
"""

HTTP_1_0_RESPONSE = b"""HTTP/1.0 200 OK\r
Server: SimpleHTTP/0.6 Python/3.10.8\r
Date: Mon, 24 Oct 2022 10:59:20 GMT\r
Content-type: text/html; charset=utf-8\r
Content-Length: 395\r
\r
"""


class TestCurlArguments(unittest.TestCase):
    def test_kwargs_returned(self):
        kwargs = CurlArguments.get_kwargs()
        self.assertIn("addr", kwargs)
        self.assertFalse([arg for arg in kwargs if arg.startswith("_")])


class TestCurlClientParsing(unittest.TestCase):
    def test_initialized(self):
        client = CurlClient(addr="127.0.0.1")
        self.assertFalse(client.ssl)
        self.assertFalse(client.last_response)
        self.assertEqual(client.uri, "http://127.0.0.1/")

    def test_multiple_responses_parsed(self):
        client = CurlClient(addr="127.0.0.1")
        with patch(
            "framework.curl_client.CurlClient._read_headers_dump",
            return_value=MULTIPLE_RESPONSES,
        ):
            client.dump_headers = True
            client.parse_out(b"", b"")
            self.assertEqual(len(client.responses), 2)
            self.assertEqual(client.responses[0].headers["content-length"], "1")
            self.assertEqual(client.responses[1].headers["content-length"], "2")

    def test_http_1_0_response_parsed(self):
        client = CurlClient(addr="127.0.0.1")
        with patch(
            "framework.curl_client.CurlClient._read_headers_dump",
            return_value=HTTP_1_0_RESPONSE,
        ):
            client.dump_headers = True
            client.parse_out(b"", b"")
            self.assertEqual(len(client.responses), 1)
            self.assertEqual(client.responses[0].proto, "1.0")
            self.assertEqual(client.responses[0].headers["content-length"], "395")


class TestCurlClient(tester.TempestaTest, no_reload=True):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: test\r\n"
                "Date: test\r\n"
                "X-Header: Test-Value-1\r\n"
                "X-Header: Test-Value-2\r\n"
                "Set-Cookie: curl=test\r\n"
                "Content-Length: 4\r\n"
                "\r\n"
                "test"
            ),
        }
    ]

    clients = [
        {
            "id": "default",
            "type": "curl",
        },
        {
            "id": "no_output",
            "type": "curl",
            "disable_output": True,
        },
        {
            "id": "wrong_port",
            "type": "curl",
            "addr": "${tempesta_ip}:443",
        },
        {
            "id": "h2",
            "type": "curl",
            "http2": True,
        },
        {
            "id": "ssl",
            "type": "curl",
            "addr": "${tempesta_ip}:444",
            "ssl": True,
        },
        {
            "id": "cookie",
            "type": "curl",
            "save_cookies": True,
            "load_cookies": True,
        },
        {
            "id": "multi",
            "type": "curl",
            "uri": "/[1-2]",
        },
        {
            "id": "send_headers",
            "type": "curl",
            "headers": {
                "Connection": "close",
                "Header-Sended": "OK",
            },
        },
        {"id": "with_args", "type": "curl", "cmd_args": (" --verbose")},
        {
            "id": "post",
            "type": "curl",
            "data": "param1=1&param2=2",
        },
        {
            "id": "check_cert",
            "type": "curl",
            "ssl": True,
            "insecure": False,
        },
        {
            "id": "parallel",
            "type": "curl",
            "uri": "/[1-10]",
            "parallel": 2,
        },
    ]

    tempesta = {
        "config": """
            listen 80 proto=http;
            listen 443 proto=h2;
            listen 444 proto=https;
            server ${server_ip}:8000;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            tls_match_any_server_name;
        """
    }

    def setUp(self):
        super().setUp()
        self.start_all()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def get_response(self, client) -> CurlResponse:
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def test_check_curl_binary_version(self):
        client = self.get_client("default")
        self.get_response(client)
        client._check_binary_version()

    def test_default_request_completed(self):
        client = self.get_client("default")
        response = self.get_response(client)
        self.assertEqual(len(client.responses), 1)
        self.assertEqual(response.status, 200)
        self.assertFalse(response.stderr)
        self.assertEqual(response.stdout, "test")
        self.assertEqual(response.proto, "1.1")
        with self.subTest("stats parsed"):
            self.assertEqual(len(client.stats), 1)
            self.assertFalse(client.last_stats["errormsg"])
            self.assertGreaterEqual(client.last_stats["time_total"], 0)

    def test_request_completed_with_output_disabled(self):
        client = self.get_client("no_output")
        client.output_path.unlink(missing_ok=True)
        response = self.get_response(client)
        self.assertEqual(len(client.responses), 1)
        self.assertEqual(response.status, 200)
        self.assertFalse(response.stderr)
        self.assertFalse(response.stdout)

    def test_ssl_request_completed(self):
        client = self.get_client("ssl")
        response = self.get_response(client)
        self.assertEqual(response.proto, "1.1")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.stdout, "test")
        self.assertTrue(response.headers["via"].startswith("1.1"))

    def test_http2_request_completed(self):
        client = self.get_client("h2")
        response = self.get_response(client)
        self.assertEqual(response.proto, "2")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.stdout, "test")
        self.assertTrue(response.headers["via"].startswith("2.0"))

    def test_error_on_wrong_port(self):
        client = self.get_client("wrong_port")
        response = self.get_response(client)
        self.assertFalse(response)

    def test_headers_parsed(self):
        client = self.get_client("default")
        response = self.get_response(client)
        headers = response.headers

        with self.subTest("headers"):
            self.assertEqual(headers["content-length"], "4")
            self.assertTrue(headers["via"].startswith("1.1"))
            self.assertEqual(headers["x-header"], "Test-Value-2")

        with self.subTest("multi headers"):
            self.assertEqual(response.multi_headers["content-length"], ["4"])
            self.assertEqual(response.multi_headers["x-header"], ["Test-Value-1", "Test-Value-2"])

    def test_cookies(self):
        client = self.get_client("cookie")
        client.clear_cookies()
        self.assertFalse(client.cookie_jar_path.exists())

        with self.subTest("Cookie saved"):
            response = self.get_response(client)
            request = self.get_server("deproxy").last_request
            self.assertFalse(request.headers["cookie"])
            self.assertTrue(client.cookie_jar_path.exists())

        with self.subTest("Cookie loaded"):
            response = self.get_response(client)
            request = self.get_server("deproxy").last_request
            self.assertEqual(request.headers["cookie"], "curl=test")

    def test_multiple_requests_completed(self):
        client = self.get_client("multi")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        self.assertEqual([r.status for r in client.responses], [200, 200])
        self.assertEqual(client.statuses, {200: 2})

    def test_headers_sended(self):
        client = self.get_client("send_headers")
        response = self.get_response(client)
        request = self.get_server("deproxy").last_request
        self.assertEqual(request.headers["header-sended"], "OK")
        self.assertEqual(response.headers["connection"], "close")

    def test_set_header_after_initialization(self):
        client = self.get_client("default")
        client.headers["New-Header"] = "OK"
        response = self.get_response(client)
        request = self.get_server("deproxy").last_request
        self.assertEqual(request.headers["new-header"], "OK")

    def test_cmd_args_processed(self):
        client = self.get_client("with_args")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        self.assertTrue(response.stderr.startswith("*   Trying"))

    def test_uri_changed(self):
        client = self.get_client("default")
        client.set_uri("/314")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        request = self.get_server("deproxy").last_request
        self.assertEqual(request.uri, "/314")

    def test_options_added(self):
        client = self.get_client("default")
        client.options.append("--head")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        self.assertTrue(response.stdout.startswith("HTTP/1.1 200"))

    def test_certificate_error(self):
        client = self.get_client("check_cert")
        response = self.get_response(client)
        self.assertTrue(client.last_stats["errormsg"])

    def test_data_posted(self):
        client = self.get_client("post")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        request = self.get_server("deproxy").last_request
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.body, "param1=1&param2=2")

    def test_parallel_mod_enabled(self):
        client = self.get_client("parallel")
        server = self.get_server("deproxy")
        response = self.get_response(client)
        self.assertIn("--parallel-max 2", client.form_command())
        self.assertEqual(len(server.requests), 10)
        self.assertEqual(client.requests, 10)
        self.assertEqual(client.results(), (10, 0, ANY, {200: ANY}))

        with self.subTest("multiple stats parsed"):
            self.assertEqual(len(client.stats), 10)
            self.assertGreaterEqual(client.last_stats["time_total"], 0)

    def test_stats_after_multiple_requests(self):
        client = self.get_client("default")
        server = self.get_server("deproxy")
        self.assertEqual(client.requests, 0)
        self.assertEqual(client.results(), (0, 0, 0, {}))
        self.assertEqual(len(server.requests), 0)

        for i in range(2):
            with self.subTest("make request", i=i):
                self.assertEqual(len(server.requests), i)
                self.get_response(client)
                self.assertEqual(client.requests, 1)
                self.assertEqual(len(client.responses), 1)
                results = client.results()
                self.assertEqual(
                    client.results(),
                    # requests, errors, rate, statuses
                    (1, 0, ANY, {200: 1}),
                )

        client.set_uri("/[1-3]")
        response = self.get_response(client)
        self.assertEqual(client.requests, 3)
        self.assertEqual(
            client.results(),
            # requests, errors, rate, statuses
            (3, 0, ANY, {200: 3}),
        )
