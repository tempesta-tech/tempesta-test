"""Functional tests of caching responses."""

from __future__ import print_function

import copy

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from testers import functional
from helpers import chains, tf_cfg
from framework.tester import TempestaTest

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# TODO: add tests for RFC compliance

class TestCacheDisabled(functional.FunctionalTest):

    messages = 10

    # Disable caching
    cache_mode = 0

    def chain(self, uri='/', cache_allowed=True, wo_date=False):
        if self.cache_mode == 0:
            cache_allowed = False
        if cache_allowed:
            test_chains = chains.cache_repeated(self.messages, uri=uri)
        else:
            test_chains = chains.proxy_repeated(self.messages, uri=uri)
        if wo_date:
            for chain in test_chains:
                if chain.server_response:
                    del chain.server_response.headers['Date']
                    chain.server_response.update()
        return test_chains

    def test_cache_fulfill_all(self):
        config = ('cache %d;\n'
                  'cache_fulfill * *;\n' % self.cache_mode)
        self.generic_test_routine(config, self.chain(cache_allowed=True))

    def test_cache_bypass_all(self):
        config = ('cache %d;\n'
                  'cache_bypass * *;\n' % self.cache_mode)
        self.generic_test_routine(config, self.chain(cache_allowed=False))

    def mixed_config(self):
        return ('cache %d;\n'
                'cache_fulfill suffix ".jpg" ".png";\n'
                'cache_bypass suffix ".avi";\n'
                'cache_bypass prefix "/static/dynamic_zone/";\n'
                'cache_fulfill prefix "/static/";\n'
                % self.cache_mode)

    def test_cache_fulfill_suffix(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=True, uri='/picts/bear.jpg'))

    def test_cache_fulfill_suffix_2(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=True, uri='/jsnfsjk/jnd.png'))

    def test_cache_bypass_suffix(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=False, uri='/howto/film.avi'))

    def test_cache_bypass_prefix(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=False,
                       uri='/static/dynamic_zone/content.html'))

    def test_cache_fulfill_prefix(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=True, uri='/static/content.html'))

    # If origin response does not provide `date` header, then Tempesta adds it
    # to both responses served from cache and forwarded from origin. Both
    # headers `date` and `age` should be present and has a valid value.
    def test_cache_wo_date(self):
        self.generic_test_routine(
            self.mixed_config(),
            self.chain(cache_allowed=True, uri='/static/content.html', wo_date=True))


class TestCacheSharding(TestCacheDisabled):

    # Sharding mode.
    cache_mode = 1

class TestCacheReplicated(TestCacheDisabled):

    # Replicated mode.
    cache_mode = 2

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4


class TestCacheBase(TempestaTest, base=True):
    """"""
    tempesta_template = {
        'config': """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

%(tempesta_config)s"""
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

    # Disable caching
    tempesta_config: str

    def setUp(self):
        """"""
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta['config'] = (
            self.tempesta['config'] % {'tempesta_config': self.tempesta_config or ''}
        )
        super().setUp()

    def start_all(self):
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def _test(self):
        """"""
        self.start_all()

        srv: StaticDeproxyServer = self.get_server('deproxy')
        response = (
            f'HTTP/1.1 200 OK\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Content-Length: 13\r\n'
            + 'Content-Type: text/html\r\n'
            + '\r\n'
            + '<html></html>\r\n'
        )
        srv.set_response(response)

        client: DeproxyClient = self.get_client('deproxy')
        request = (
            'GET / HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )

        for _ in range(self.messages):
            client.make_request(request)
            client.wait_for_response()

        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cache_hits, 0, )
        self.assertEqual(tempesta.stats.cache_misses, 0, )
        self.assertEqual(tempesta.stats.cl_msg_received, self.messages, )
        self.assertEqual(len(srv.requests), 10, )
        for res in client.responses:
            self.assertNotIn('age', str(res), )
        # print(tempesta.stats.__dict__)
        # print(tempesta.config.get_config())


class TestDisabledCacheFulfillAll(TestCacheBase):
    """"""
    tempesta_config = 'cache 0;\r\ncache_fulfill * *;\r\n'

    def test(self):
        self._test()


class TestDisabledCacheBypassAll(TestCacheBase):
    """"""
    tempesta_config = 'cache 0;\r\ncache_bypass * *;\r\n'

    def test(self):
        self._test()
