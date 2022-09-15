"""Functional tests of caching different methods."""
import copy

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import tf_cfg, chains
from helpers.control import Tempesta
from helpers.deproxy import HttpMessage
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TestMultipleMethods(functional.FunctionalTest):
    """TempestaFW must return cached responses to exactly matching request
    methods only. I.e. if we receive HEAD requests, we must not return response
    cached for GET method.
    RFC 7234:
        The primary cache key consists of the request method and target URI.
    """

    config = ('cache 2;\n'
              'cache_fulfill * *;\n'
              'cache_methods GET HEAD;\n')

    def chains(self):
        uri = '/page.html'
        result = [# Populate Cache
                  chains.proxy(method='GET', uri=uri),
                  chains.proxy(method='HEAD', uri=uri),
                  # Serve from cache
                  chains.cache(method='GET', uri=uri),
                  chains.cache(method='HEAD', uri=uri),
                  ]
        return result

    def test_purge(self):
        self.generic_test_routine(self.config, self.chains())


class TestCacheMethods(TempestaTest):
    tempesta_template = {
        'config': """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

cache 2;
cache_fulfill * *;
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

    response_ok_empty = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
    response_no_content = (
        'HTTP/1.1 204 No Content\r\n'
        + 'Connection: keep-alive\r\n'
        + 'Server: Deproxy Server\r\n'
        + f'Date: {HttpMessage.date_time_string()}\r\n'
        + '\r\n'
    )

    messages = 3
    should_be_cached = True

    def start_all(self):
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def setUp(self, **kwargs):
        if not kwargs:
            return
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta['config'] = (
            self.tempesta['config'] + kwargs['config']
        )
        super().setUp()

    def check_tempesta_stats_and_response(self):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()
        srv: StaticDeproxyServer = self.get_server('deproxy')

        if self.should_be_cached:
            self.assertEqual(tempesta.stats.cache_misses, 1, )
            self.assertEqual(tempesta.stats.cl_msg_served_from_cache, self.messages - 1, )
            self.assertEqual(tempesta.stats.cache_hits, self.messages - 1, )
            self.assertEqual(len(srv.requests) and tempesta.stats.srv_msg_received, 1, )
        else:
            self.assertEqual(tempesta.stats.cache_misses, 0, )
            self.assertEqual(tempesta.stats.cl_msg_served_from_cache, 0, )
            self.assertEqual(tempesta.stats.cache_hits, 0, )
            self.assertEqual(len(srv.requests) and tempesta.stats.srv_msg_received, self.messages, )

        client: DeproxyClient = self.get_client('deproxy')

        self.assertNotIn('age', str(client.responses[0]), )
        cache_responses = client.responses[1:]

        for response in cache_responses:
            if self.should_be_cached:
                self.assertIn('age', str(response), )
            else:
                self.assertNotIn('age', str(response), )

    def _test(self, method: str, server_response: str, ):
        if self.should_be_cached:
            cache_method = method
        else:
            cache_method = 'GET' if method != 'GET' else 'HEAD'

        self.setUp(config=f'cache_methods {cache_method};\n')
        self.start_all()

        srv: StaticDeproxyServer = self.get_server('deproxy')
        srv.set_response(server_response)

        client: DeproxyClient = self.get_client('deproxy')
        request = (
            f'{method} /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        for _ in range(self.messages):
            client.make_request(request)
            client.wait_for_response()

        self.check_tempesta_stats_and_response()

    def test_get(self):
        self._test(
            method='GET',
            server_response=self.response_ok_empty,
        )

    def test_post(self):
        self._test(
            method='POST',
            server_response=self.response_no_content,
        )

    def test_copy(self):
        self._test(
            method='COPY',
            server_response=self.response_ok_empty,
        )

    def test_delete(self):
        self._test(
            method='DELETE',
            server_response=self.response_no_content,
        )

    def test_head(self):
        self._test(
            method='HEAD',
            server_response=self.response_ok_empty,
        )

    def test_lock(self):
        self._test(
            method='LOCK',
            server_response=self.response_ok_empty,
        )

    def test_mkcol(self):
        self._test(
            method='MKCOL',
            server_response=self.response_ok_empty,
        )

    def test_move(self):
        self._test(
            method='MOVE',
            server_response=self.response_ok_empty,
        )

    def test_options(self):
        self._test(
            method='OPTIONS',
            server_response=self.response_ok_empty,
        )

    def test_patch(self):
        self._test(
            method='PATCH',
            server_response=self.response_ok_empty,
        )

    def test_propfind(self):
        self._test(
            method='PROPFIND',
            server_response=self.response_ok_empty,
        )

    def test_proppatch(self):
        self._test(
            method='PROPPATCH',
            server_response=self.response_ok_empty,
        )

    def test_put(self):
        self._test(
            method='PUT',
            server_response=self.response_no_content,
        )

    def test_trace(self):
        self._test(
            method='TRACE',
            server_response=self.response_ok_empty,
        )

    def test_unlock(self):
        self._test(
            method='UNLOCK',
            server_response=self.response_ok_empty,
        )


class TestCacheMethodsNoCache(TestCacheMethods):
    should_be_cached = False

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
