from unittest.mock import patch
import unittest

from framework import tester
from framework.curl_client import CurlClient, CurlResponse

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


class TestCurlClientParsing(unittest.TestCase):
    def test_initialized(self):
        client = CurlClient(server_addr="127.0.0.1")
        self.assertFalse(client.ssl)
        self.assertFalse(client.last_response)
        self.assertEqual(client.uri, "http://127.0.0.1/")

    def test_multiple_responses_parsed(self):
        client = CurlClient(server_addr="127.0.0.1")
        with patch(
            "framework.curl_client.CurlClient._read_headers_dump",
            return_value=MULTIPLE_RESPONSES,
        ):
            client.dump_headers = True
            client.parse_out(b"", b"")
            self.assertEqual(len(client.responses), 2)
            self.assertEqual(client.responses[0].headers["content-length"], "1")
            self.assertEqual(client.responses[1].headers["content-length"], "2")


class TestCurlClient(tester.TempestaTest):

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
                "X-Header: Test-Value\r\n"
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
            "id": "wrong_port",
            "type": "curl",
            "addr": "${server_ip}:8001",
        },
        {
            "id": "h2",
            "type": "curl",
            "http2": True,
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
            "uri": f"/[1-2]",
        },
    ]

    tempesta = {
        "config": """
            listen 80 proto=http;
            listen 443 proto=h2;
            server ${server_ip}:8000;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            tls_match_any_server_name;
        """
    }

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

    def test_default_request_completed(self):
        self.start_all()
        client = self.get_client("default")
        response = self.get_response(client)
        self.assertEqual(len(client.responses), 1)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.stdout, "test")

    def test_http2_request_completed(self):
        self.start_all()
        client = self.get_client("h2")
        response = self.get_response(client)
        self.assertEqual(response.proto, "2")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.stdout, "test")
        self.assertTrue(response.headers["via"].startswith("2.0"))

    def test_error_on_wrong_port(self):
        self.start_all()
        client = self.get_client("wrong_port")
        response = self.get_response(client)
        self.assertFalse(response)

    def test_headers_parsed(self):
        self.start_all()
        client = self.get_client("default")
        headers = self.get_response(client).headers
        self.assertEqual(headers["content-length"], "4")
        self.assertEqual(headers["x-header"], "Test-Value")
        self.assertTrue(headers["via"].startswith("1.1"))

    def test_cookies(self):
        self.start_all()
        client = self.get_client("cookie")
        client.clear_cookies()
        self.assertFalse(client.cookie_jar_path.exists())

        with self.subTest("Cookie saved"):
            response = self.get_response(client)
            request = self.get_server("deproxy").last_request
            self.assertFalse(request.headers["Cookie"])
            self.assertTrue(client.cookie_jar_path.exists())

        with self.subTest("Cookie loaded"):
            response = self.get_response(client)
            request = self.get_server("deproxy").last_request
            self.assertEqual(request.headers["Cookie"], "curl=test")

    def test_multiple_requests_completed(self):
        self.start_all()
        client = self.get_client("multi")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        self.assertEqual([r.status for r in client.responses], [200, 200])
