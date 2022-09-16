"""Functional tests of caching different methods."""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import tf_cfg
from helpers.deproxy import HttpMessage


# TODO: Check that all headers that must be present in 304 response are there.
# Not implemented since some of them (at least Vary) affect cache behaviour.


class TestConditional(TempestaTest):
    tempesta = {
        'config': """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

cache 2;
cache_fulfill * *;
cache_methods GET;
"""
    }

    backends = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': '',
        },
    ]

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': '${tempesta_ip}',
            'port': '80',
        },
    ]

    def start_all(self):
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def make_request(self, request: str):
        """"""
        client: DeproxyClient = self.get_client('deproxy')
        curr_responses = len(client.responses)
        client.make_request(request)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses), 'Response is lost.')

    def _test(self, etag: str, expected_status_code: str, if_none_match: str = None,
              if_modified_since: str = None, ):
        """"""
        self.start_all()
        srv: StaticDeproxyServer = self.get_server('deproxy')
        client: DeproxyClient = self.get_client('deproxy')

        srv.set_response(
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Server: Deproxy Server\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + f'Etag: {etag}\r\n'
            + '\r\n'
            + '<html></html>\r\n'
        )

        self.make_request(
            f'GET /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n',
        )
        self.assertIn(etag, str(client.last_response), )

        if if_none_match:
            option_header = f'if-none-match: {if_none_match}\r\n'
        elif if_modified_since:
            option_header = f'if-modified-since: {if_modified_since}\r\n'
        else:
            option_header = ''

        self.make_request(
            f'GET /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + option_header
            + '\r\n'
        )
        self.assertIn(etag, str(client.last_response), )
        self.assertEqual(client.last_response.status, expected_status_code, '')
        self.assertEqual(len(srv.requests), 1, )

    def test_none_match(self):
        """Client have cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='304',
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_weak_srv(self):
        """Same as test_none_match() but server sends weak etag."""
        self._test(
            etag='W/"asdfqwerty"',
            expected_status_code='304',
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_weak_clnt(self):
        """Same as test_none_match() but client sends weak etag."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='304',
            if_none_match='W/"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_weak_all(self):
        """Same as test_none_match() but both server and client send weak etag."""
        self._test(
            etag='W/"asdfqwerty"',
            expected_status_code='304',
            if_none_match='W/"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_list(self):
        """Same as test_none_match() but client has saved copies of several resources."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='304',
            if_none_match='"fsdfds", "asdfqwerty", "sdfrgg"',
            if_modified_since=None,
        )

    def test_none_match_any(self):
        """Same as test_none_match() but client has cached entire world cached."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='304',
            if_none_match='*',
            if_modified_since=None,
        )

    def test_none_match_nc(self):
        """Client have no cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='200',
            if_none_match='"jfgfdgnjdn"',
            if_modified_since=None,
        )

    def test_mod_since(self):
        """Client have cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='304',
            if_none_match=None,
            if_modified_since='Mon, 12 Dec 2016 13:59:39 GMT',
        )

    def test_mod_since_nc(self):
        """Client have no cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code='200',
            if_none_match=None,
            if_modified_since='Mon, 5 Dec 2016 13:59:39 GMT',
        )
