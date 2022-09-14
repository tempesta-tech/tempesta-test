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


class TestCacheMethods(functional.FunctionalTest):

    messages = 10

    # Replicated cache mode, no need to test other modes in this test.
    cache_mode = 2

    allow_method_caching = True

    # Methods, that can be cached by TempestaFW.
    cacheable_methods = ['COPY', 'DELETE', 'GET', 'HEAD', 'LOCK', 'MKCOL',
                         'MOVE', 'OPTIONS', 'PATCH', 'POST', 'PROPFIND',
                         'PROPPATCH', 'PUT', 'TRACE', 'UNLOCK']

    def chain(self, method, uri='/page.html', cache_allowed=True):
        if self.cache_mode == 0:
            cache_allowed = False
        if cache_allowed:
            return chains.cache_repeated(self.messages, method=method, uri=uri)
        return chains.proxy_repeated(self.messages, method=method, uri=uri)

    def try_method(self, method):
        tf_cfg.dbg(3, '\tTest method %s.' % method)
        chain = self.chain(method=method,
                           cache_allowed=(method in self.cacheable_methods))
        print(method)
        # print(chain[0].request)
        # print(chain[0].fwd_request)
        # print(chain[0].server_response)
        # print(chain[0].response)

        if self.allow_method_caching:
            cache_method = method
        else:
            cache_method = 'GET' if method != 'GET' else 'HEAD'
        print(cache_method)
        config = ('cache %d;\n'
                  'cache_fulfill * *;\n'
                  'cache_methods %s;\n'
                  % (self.cache_mode, cache_method))
        print(config)
        self.generic_test_routine(config, chain)

    def test_copy(self):
        self.try_method('COPY')

    def test_delete(self):
        self.try_method('DELETE')

    def test_get(self):
        self.try_method('GET')

    def test_head(self):
        self.try_method('HEAD')

    def test_lock(self):
        self.try_method('LOCK')

    def test_mkcol(self):
        self.try_method('MKCOL')

    def test_move(self):
        self.try_method('MOVE')

    def test_options(self):
        self.try_method('OPTIONS')

    def test_patch(self):
        self.try_method('PATCH')

    def test_post(self):
        self.try_method('POST')

    def test_propfind(self):
        self.try_method('PROPFIND')

    def test_proppatch(self):
        self.try_method('PROPPATCH')

    def test_put(self):
        self.try_method('PUT')

    def test_trace(self):
        self.try_method('TRACE')

    def test_unlock(self):
        self.try_method('UNLOCK')


class TestCacheMethodsNC(TestCacheMethods):

    cacheable_methods = []
    allow_method_caching = False


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


class TestCacheMethodsNew(TempestaTest):
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

    messages = 10

    def start_all(self):
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def setUp(self, **kwargs):
        """"""
        if not kwargs:
            return
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta['config'] = (
            self.tempesta['config'] + kwargs['config']
        )
        super().setUp()

    def check_tempesta_stats_and_response(self, should_be_cached: bool):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()
        print(tempesta.get_current_config())
        srv: StaticDeproxyServer = self.get_server('deproxy')
        print(tempesta.stats.__dict__)
        print(len(srv.requests))

        if should_be_cached:
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
            if should_be_cached:
                self.assertIn('age', str(response), )
            else:
                self.assertNotIn('age', str(response), )

    def _test(self, config: str, client_request: str, server_response: str, should_be_cached: bool):
        self.setUp(config=config)
        self.start_all()

        srv: StaticDeproxyServer = self.get_server('deproxy')
        srv.set_response(server_response)

        client: DeproxyClient = self.get_client('deproxy')
        for _ in range(self.messages):
            client.make_request(client_request)
            client.wait_for_response()
        print(client.last_response)

        self.check_tempesta_stats_and_response(should_be_cached)

    def test_get(self):
        request = (
            'GET /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
            + '<html></html>\r\n'
        )
        self._test(
            config='cache_methods GET;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_post(self):
        request = (
            'POST /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 204 No Content\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods POST;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_copy(self):
        request = (
            'COPY /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods COPY;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_delete(self):
        request = (
            'DELETE /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 204 No Content\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods DELETE;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_head(self):
        request = (
            'HEAD /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + 'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods HEAD;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_lock(self):
        request = (
            'LOCK /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods LOCK;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_mkcol(self):
        request = (
            'MKCOL /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods MKCOL;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_move(self):
        request = (
            'MOVE /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods MOVE;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_options(self):
        request = (
            'OPTIONS /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods OPTIONS;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_patch(self):
        request = (
            'PATCH /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods PATCH;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_propfind(self):
        request = (
            'PROPFIND /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods PROPFIND;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_proppatch(self):
        request = (
            'PROPPATCH /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods PROPPATCH;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_put(self):
        request = (
            'PUT /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 204 No Content\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods PUT;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_trace(self):
        request = (
            'TRACE /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods TRACE;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )

    def test_unlock(self):
        request = (
            'UNLOCK /page.html HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )
        response = (
            'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 0\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'Date: {HttpMessage.date_time_string()}\r\n'
            + '\r\n'
        )
        self._test(
            config='cache_methods UNLOCK;\n',
            client_request=request,
            server_response=response,
            should_be_cached=True,
        )



# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
