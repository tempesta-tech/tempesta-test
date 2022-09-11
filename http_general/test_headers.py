"""
Tests for correct handling of HTTP/1.1 headers.
"""

from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class BackendSetCoookie(tester.TempestaTest):

    backends = [
        {
            'id': 'set-cookie-1',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Set-Cookie: c1=test1\r\n'
                'Content-Length: 0\r\n\r\n'
            ),
        },
        {
            'id': 'set-cookie-2',
            'type': 'deproxy',
            'port': '8001',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Set-Cookie: c1=test1\r\n'
                'Set-Cookie: c2=test2\r\n'
                'Content-Length: 0\r\n\r\n'
            ),
        },
    ]

    tempesta = {
        'config':
        """
        listen 80;
        srv_group sg1 { server ${server_ip}:8000; }
        srv_group sg2 { server ${server_ip}:8001; }

        vhost cookie1 { proxy_pass sg1; }  # single cookie
        vhost cookie2 { proxy_pass sg2; }  # two cookie headers

        http_chain {
          uri == "/cookie1" -> cookie1;
          uri == "/cookie2" -> cookie2;
        }
        """
    }

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
        }
    ]

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def test_request_success(self):
        """Test that Tempesta proxies responses with Set-Cookie headers successfully."""
        self.start_all()
        client = self.get_client('deproxy')
        for path in (
                "cookie1",  # single Set-Cookie header
                "cookie2"  # two Set-Cookie headers
        ):
            with self.subTest("GET cookies", path=path):
                client.make_request(f"GET /{path} HTTP/1.1\r\n\r\n")
                self.assertTrue(
                    client.wait_for_response(timeout=1)
                )
                self.assertEqual(client.last_response.status, '200')
