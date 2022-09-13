from dataclasses import dataclass
import email
import io
import re

from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


@dataclass
class CurlResponse:
    """Curl response parser."""

    response_data: bytes  # response data to parse
    status: int = None  # parsed HTTP status code
    headers: dict = None  # parsed headers, with lowercase names

    def __post_init__(self):
        try:
            response_line, headers = self.response_data.decode().split('\r\n', 1)
        except ValueError:
            raise ValueError(f"Unexpected HTTP response: {self.response_data}") from None
        message = email.message_from_file(io.StringIO(headers))
        self.status_code = int(re.match(r"HTTP/1.1 (\d+)", response_line).group(1))
        self.headers = {k.lower(): v for k, v in message.items()}


class TestGetWordpressPages(tester.TempestaTest):

    tempesta = {
        'config':
        """
        listen 80;
        cache 1;
        cache_fulfill * *;
        server ${server_ip}:${server_wordpress_port};
        """
    }

    clients = [
        {
            'id': 'get-page',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': (
                '--silent --head --request GET --fail '
                ' http://${tempesta_ip}'
                '/?page_id=1370'  # TODO: replace with the valid page ID
            )
        },
    ]

    def get_response(self, client):
        self.wait_while_busy(client)
        self.assertEqual(0, client.returncode)
        return CurlResponse(client.resq.get(True, 1)[0])

    def restart_client(self, client):
        if client.is_running():
            client.stop()
        client.start()
        if not client.is_running():
            raise Exception('Can not start client')

    def check_cached_headers(self, headers):
        """Return True if headers are from cached response."""
        self.assertIn(
            'x-powered-by',
            headers.keys(),
            "Unexpected headers (not from WordPress?)"
        )
        return 'age' in headers.keys()

    def test_page_cached(self):
        self.start_tempesta()
        client = self.get_client("get-page")
        self.restart_client(client)

        # first request, expect non-cached response
        response = self.get_response(client)
        self.assertEqual(200, response.status_code)
        self.assertFalse(
            self.check_cached_headers(response.headers),
            f"Response headers: {response.headers}"
        )

        self.restart_client(client)

        # second request, expect cached response
        response = self.get_response(client)
        self.assertEqual(200, response.status_code)
        self.assertTrue(
            self.check_cached_headers(response.headers),
            f"Response headers: {response.headers}"
        )
