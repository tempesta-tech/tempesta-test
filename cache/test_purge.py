"""Functional tests of caching different methods."""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import checks_for_tests as checks
from helpers import tf_cfg
from helpers.deproxy import HttpMessage


class TestPurge(TempestaTest):
    """This class contains checks for PURGE method operation."""
    tempesta = {
        'config': """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

cache 2;
cache_fulfill * *;
cache_methods GET HEAD;
cache_purge;
cache_purge_acl ${client_ip};
cache_resp_hdr_del set-cookie;
""",
    }

    backends = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                + 'Connection: keep-alive\r\n'
                + 'Content-Length: 13\r\n'
                + 'Content-Type: text/html\r\n'
                + 'Server: Deproxy Server\r\n'
                + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                + f'Date: {HttpMessage.date_time_string()}\r\n'
                + '\r\n'
                + '<html></html>\r\n'
            ),
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

    request_template = (
        '{0} /page.html HTTP/1.1\r\n'
        + 'Host: {0}\r\n'.format(tf_cfg.cfg.get('Client', 'hostname'))
        + 'Connection: keep-alive\r\n'
        + 'Accept: */*\r\n'
        + '\r\n'
    )

    request_template_x_tempesta_cache = (
        '{0} /page.html HTTP/1.1\r\n'
        + 'Host: {0}\r\n'.format(tf_cfg.cfg.get('Client', 'hostname'))
        + 'Connection: keep-alive\r\n'
        + 'Accept: */*\r\n'
        + 'x-tempesta-cache: {1}\r\n'
        + '\r\n'
    )

    def test_purge(self):
        """
        Send a request and cache it. Use PURGE and repeat the request. Check that a response is
        not received from cache, but the request has been cached again.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        # All cacheable method to the resource must be cached
        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertIn('age', client.last_response.headers)

        self.assertEqual(len(srv.requests), 2)
        client.send_request(self.request_template.format('PURGE'), '200')
        self.assertEqual(len(srv.requests), 2)

        # All cached responses was removed, expect re-caching them
        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertIn('age', client.last_response.headers)

        # TODO uncomment after fixing issue #1699
        # checks.check_tempesta_cache_stats(
        #     self.get_tempesta(),
        #     cache_hits=4,
        #     cache_misses=4,
        #     cl_msg_served_from_cache=4
        # )
        self.assertEqual(len(self.get_server('deproxy').requests), 4)

    def test_purge_get_basic(self):
        """
        Send a request and cache it. Use PURGE with "x-tempesta-cache: GET" header and repeat the
        request. Check that tempesta has sent a request to update cache for "GET" method. But cache
        for "HEAD" method has been purged.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        # All cacheable method to the resource must be cached
        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertIn('age', client.last_response.headers)

        # PURGE + GET works like a cache update, so all following requests
        # must be served from the cache.
        self.assertEqual(len(srv.requests), 2)
        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200')
        self.assertEqual(len(srv.requests), 3)

        # Note that due to how Tempesta handles HEAD this doesn't help us
        # with HEAD pre-caching.
        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('HEAD'), '200')
        self.assertIn('age', client.last_response.headers)

        # TODO uncomment after fixing issue #1699
        # checks.check_tempesta_cache_stats(
        #     self.get_tempesta(),
        #     cache_hits=4,
        #     cache_misses=3,
        #     cl_msg_served_from_cache=4,
        # )
        self.assertEqual(len(srv.requests), 4)

    def test_purge_get_update(self):
        """
        Send a request and cache it. Update server response. Use PURGE with "x-tempesta-cache: GET"
        header and repeat the request. Check that cached response has been update.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        new_response_body = 'New text page'
        srv.set_response(
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Server: Deproxy Server\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
            + new_response_body,
        )
        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200')
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        self.assertEqual(new_response_body, client.last_response.body)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_purge_get_update_hdr_del(self):
        """
        Send a request and cache it. Update server response with "Set-Cookie" header. Use PURGE
        with "x-tempesta-cache: GET" header and repeat the request. Check that cached response has
        not "Set-Cookie" header.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)
        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        new_response_body = 'New text page'
        srv.set_response(
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Server: Deproxy Server\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + 'Set-Cookie: somecookie=2\r\n'
            + '\r\n'
            + new_response_body,
        )

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200')
        self.assertIn('set-cookie', client.last_response.headers)
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)
        self.assertEqual(new_response_body, client.last_response.body)
        self.assertNotIn('set-cookie', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_purge_get_update_cc(self):
        """
        And another PURGE-GET test, with Set-Cookie removed due to no-cache="set-cookie" in the
        response.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        new_response_body = 'New text page'
        srv.set_response(
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Server: Deproxy Server\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + 'Set-Cookie: somecookie=2\r\n'
            + 'Cache-Control: no-cache="set-cookie"\r\n'
            + '\r\n'
            + new_response_body,
        )

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200')
        self.assertEqual(len(srv.requests), 2)
        self.assertIn('set-cookie' and 'cache-control', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age' and 'cache-control', client.last_response.headers)
        self.assertNotIn('set-cookie:', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_useless_x_tempesta_cache(self):
        """
        Send an ordinary GET request with an "X-Tempesta-Cache" header, and make sure it doesn't
        affect anything.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')

        client.send_request(self.request_template_x_tempesta_cache.format('GET', 'GET'), '200')

        client.send_request(self.request_template_x_tempesta_cache.format('GET', 'GET'), '200')
        self.assertIn('age', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=1,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(self.get_server('deproxy').requests), 1)

    def test_purge_get_garbage(self):
        """
        Send some garbage in the "X-Tempesta-Cache" header. The entry must be purged, but not
        re-cached. (This works the same way as a plain PURGE, so we're not using the helper
        method here.)
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'FRED'), '200')
        self.assertEqual(len(srv.requests), 1)

        client.send_request(self.request_template.format('GET', ''), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        self.assertEqual(len(srv.requests), 2)
        client.send_request(
            self.request_template_x_tempesta_cache.format('PURGE', 'GETWRONG'), '200',
        )
        self.assertNotIn('age', client.last_response.headers)
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=3,
            cache_misses=1,
            cl_msg_served_from_cache=3,
        )
        self.assertEqual(len(srv.requests), 3)

    def test_purge_get_uncached(self):
        """
        Send a PURGE request with X-Tempesta-Cache for a non-cached entry. Make sure a new cache
        entry is populated after the request.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=1,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(srv.requests), 1)

    def test_purge_get_uncacheable(self):
        """
        Send a PURGE request with "X-Tempesta-Cache" for an existing cache entry, and generate a
        non-cacheable response. Make sure that there is neither the old nor the new response in
        the cache.
        """
        self.start_all_services(deproxy=True)
        client: DeproxyClient = self.get_client('deproxy')
        srv: StaticDeproxyServer = self.get_server('deproxy')

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertIn('age', client.last_response.headers)

        srv.set_response(
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Server: Deproxy Server\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + 'Cache-Control: private\r\n'
            + '\r\n'
            + '<html></html>\r\n',
        )

        client.send_request(
            self.request_template_x_tempesta_cache.format('PURGE', 'GET'), '200',
        )
        self.assertIn('cache-control', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        client.send_request(self.request_template.format('GET'), '200')
        self.assertNotIn('age', client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=1,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(srv.requests), 4, 'Server has lost requests.')
