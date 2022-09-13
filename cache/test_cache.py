"""Functional tests of caching responses."""

from __future__ import print_function

import copy
import configparser
import pytest

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from helpers.control import Tempesta
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


#------------------------------------------------------------------------------------------------
class CacheBase(TempestaTest, base=True):
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

    cache_mode: int
    messages: int
    uri: str

    # Disable caching
    tempesta_config: str

    # expected values for checking
    expected_cache_hist: int
    expected_cache_misses: int
    expected_requests_to_server: int

    def setUp(self):
        """"""
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta['config'] = (
            self.tempesta['config'] % {
                'tempesta_config': self.tempesta_config.format(self.cache_mode) or ''
            }
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
            f'GET {self.uri} HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )

        # print(request)
        for _ in range(self.messages):
            client.make_request(request)
            client.wait_for_response()

        # print(client.last_response)

        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()
        # print(tempesta.stats.__dict__)

        # print(tempesta.get_current_config())
        self.assertEqual(tempesta.stats.cache_hits, self.expected_cache_hist, )
        self.assertEqual(tempesta.stats.cache_misses, self.expected_cache_misses, )
        self.assertEqual(tempesta.stats.cl_msg_received, self.messages, )
        self.assertEqual(len(srv.requests), self.expected_requests_to_server, )
        # for res in client.responses:
        #     self.assertNotIn('age', str(res), )

        # print(tempesta.config.get_config())


class TestDisabledCacheFulfillAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 0
    tempesta_config = 'cache {0};\r\ncache_fulfill * *;\r\n'
    uri = '/'
    expected_cache_hist = 0
    expected_cache_misses = 0
    expected_requests_to_server = messages

    def test(self):
        self._test()


class TestCacheShardingFulfillAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 1
    tempesta_config = 'cache {0};\r\ncache_fulfill * *;\r\n'
    uri = '/'
    expected_cache_hist = messages - 1
    expected_cache_misses = 1
    expected_requests_to_server = 1

    def test(self):
        self._test()


class TestCacheReplicatedFulfillAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 2
    tempesta_config = 'cache {0};\r\ncache_fulfill * *;\r\n'
    uri = '/'
    expected_cache_hist = messages - 1
    expected_cache_misses = 1
    expected_requests_to_server = 1

    def test(self):
        self._test()


class TestDisabledCacheBypassAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 0
    tempesta_config = 'cache {0};\r\ncache_bypass * *;\r\n'
    uri = '/'
    expected_cache_hist = 0
    expected_cache_misses = 0
    expected_requests_to_server = messages

    def test(self):
        self._test()


class TestCacheShardingBypassAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 1
    tempesta_config = 'cache {0};\r\ncache_bypass * *;\r\n'
    uri = '/'
    expected_cache_hist = 0
    expected_cache_misses = 0
    expected_requests_to_server = messages

    def test(self):
        self._test()


class TestCacheReplicatedBypassAll(CacheBase):
    """"""
    messages = 10
    cache_mode = 2
    tempesta_config = 'cache {0};\r\ncache_bypass * *;\r\n'
    uri = '/'
    expected_cache_hist = 0
    expected_cache_misses = 0
    expected_requests_to_server = messages

    def test(self):
        self._test()


class CacheForMixedConfig(CacheBase, base=True):
    """"""
    messages = 10
    tempesta_config = (
        'cache {0};\r\n'
        + 'cache_fulfill suffix ".jpg" ".png";\r\n'
        + 'cache_bypass suffix ".avi";\r\n'
        + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
        + 'cache_fulfill prefix "/static/";\r\n'
    )
    expected_cache_hist = messages - 1
    expected_cache_misses = 1
    expected_requests_to_server = 1


class NoCacheForMixedConfig(CacheBase, base=True):
    """"""
    messages = 10
    tempesta_config = (
        'cache {0};\r\n'
        + 'cache_fulfill suffix ".jpg" ".png";\r\n'
        + 'cache_bypass suffix ".avi";\r\n'
        + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
        + 'cache_fulfill prefix "/static/";\r\n'
    )
    expected_cache_hist = 0
    expected_cache_misses = 0
    expected_requests_to_server = 10


class TestCacheReplicatedNew(CacheForMixedConfig):
    cache_mode = 2


class TestCacheReplicatedMixedConfig(CacheBase, base=True):
    """"""
    messages = 10
    cache_mode = 2
    tempesta_config = (
        'cache {0};\r\n'
        + 'cache_fulfill suffix ".jpg" ".png";\r\n'
        + 'cache_bypass suffix ".avi";\r\n'
        + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
        + 'cache_fulfill prefix "/static/";\r\n'
    )

    def test_cache_fulfill_suffix(self):
        self.expected_cache_hist = self.messages - 1
        self.expected_cache_misses = 1
        self.expected_requests_to_server = 1
        self.uri = '/picts/bear.jpg'
        self._test()

    def test_cache_fulfill_suffix_2(self):
        self.expected_cache_hist = self.messages - 1
        self.expected_cache_misses = 1
        self.expected_requests_to_server = 1
        self.uri = '/jsnfsjk/jnd.png'
        self._test()

    def test_cache_bypass_suffix(self):
        self.expected_cache_hist = 0
        self.expected_cache_misses = 0
        self.expected_requests_to_server = self.messages
        self.uri = '/howto/film.avi'
        self._test()

    def test_cache_bypass_prefix(self):
        self.expected_cache_hist = 0
        self.expected_cache_misses = 0
        self.expected_requests_to_server = self.messages
        self.uri = '/static/dynamic_zone/content.html'
        self._test()

    def test_cache_fulfill_prefix(self):
        self.expected_cache_hist = self.messages - 1
        self.expected_cache_misses = 1
        self.expected_requests_to_server = 1
        self.uri = '/static/content.html'
        self._test()

    # def test_cache_wo_date(self):
    #     self.expected_cache_hist = 9
    #     self.expected_cache_misses = 1
    #     self.expected_requests_to_server = 1
    #     self.uri = '/static/content.html'
    #     self._test()


# class TestCacheShardingMixedConfig(TestDisabledCacheMixedConfig):
#
#     # Sharding mode.
#     cache_mode = 1
#
#
# class TestCacheReplicatedMixedConfig(TestDisabledCacheMixedConfig):
#
#     # Sharding mode.
#     cache_mode = 2
#     expected_cache_hist = 9
#     expected_cache_misses = 1
#     expected_requests_to_server = 1
