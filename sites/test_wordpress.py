from framework import tester
from framework.curl_client import CurlResponse

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


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
            'id': 'get_page',
            'type': 'curl',
            'ssl': False,
            'uri': '/?page_id=1370',  # TODO: replace with the valid page ID
            'disable_output': True,
        },
            'cmd_args': (
                '--silent --head --request GET --fail '
                ' http://${tempesta_ip}'
                '/?page_id=1370'  # TODO: replace with the valid page ID
            )
        },
    ]

    def get_response(self, client) -> CurlResponse:
        self.restart_client(client)
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

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
        client = self.get_client("get_page")

        with self.subTest("First request, expect non-cached response"):
            response = self.get_response(client)
            self.assertEqual(200, response.status_code)
            self.assertFalse(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

        with self.subTest("Second request, expect cached response"):
            response = self.get_response(client)
            self.assertEqual(200, response.status_code)
            self.assertTrue(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

