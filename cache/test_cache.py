"""Functional tests of caching config."""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import copy

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers.control import Tempesta
from helpers import tf_cfg

MIXED_CONFIG = (
    'cache {0};\r\n'
    + 'cache_fulfill suffix ".jpg" ".png";\r\n'
    + 'cache_bypass suffix ".avi";\r\n'
    + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
    + 'cache_fulfill prefix "/static/";\r\n'
)


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
    messages = 10
    uri: str
    tempesta_config = ''
    should_be_cached: bool

    def setUp(self):
        """"""
        if self.tempesta_config:
            self.tempesta = copy.deepcopy(self.tempesta_template)
            self.tempesta['config'] = (
                    self.tempesta['config'] % {
                'tempesta_config': self.tempesta_config.format(self.cache_mode)
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

    def test(self):
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

        for _ in range(self.messages):
            client.make_request(request)
            client.wait_for_response()

        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()

        self.assertNotIn('age', str(client.responses[0]), )
        cache_responses = client.responses[1:]

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

        for response in cache_responses:
            if self.should_be_cached:
                self.assertIn('age', str(response), )
            else:
                self.assertNotIn('age', str(response), )


class TestDisabledCacheFulfillAll(CacheBase):
    """"""
    should_be_cached = False
    cache_mode = 0
    tempesta_config = 'cache {0};\r\ncache_fulfill * *;\r\n'
    uri = '/'


class TestCacheShardingFulfillAll(TestDisabledCacheFulfillAll):
    """"""
    should_be_cached = True
    cache_mode = 1


class TestCacheReplicatedFulfillAll(TestDisabledCacheFulfillAll):
    """"""
    should_be_cached = True
    cache_mode = 2


class TestDisabledCacheBypassAll(CacheBase):
    """"""
    should_be_cached = False
    cache_mode = 0
    tempesta_config = 'cache {0};\r\ncache_bypass * *;\r\n'
    uri = '/'


class TestCacheShardingBypassAll(TestDisabledCacheBypassAll):
    """"""
    should_be_cached = False
    cache_mode = 1


class TestCacheReplicatedBypassAll(TestDisabledCacheBypassAll):
    """"""
    should_be_cached = False
    cache_mode = 2


class TestDisabledCacheFulfillSuffix(CacheBase):
    should_be_cached = False
    cache_mode = 0
    tempesta_config = MIXED_CONFIG
    uri = '/picts/bear.jpg'


class TestCacheShardingFulfillSuffix(TestDisabledCacheFulfillSuffix):
    should_be_cached = True
    cache_mode = 1


class TestReplicatedCacheFulfillSuffix(TestDisabledCacheFulfillSuffix):
    should_be_cached = True
    cache_mode = 2


class TestDisabledCacheFulfillSuffix2(CacheBase):
    should_be_cached = False
    cache_mode = 0
    tempesta_config = MIXED_CONFIG
    uri = '/jsnfsjk/jnd.png'


class TestCacheShardingFulfillSuffix2(TestDisabledCacheFulfillSuffix):
    should_be_cached = True
    cache_mode = 1


class TestReplicatedCacheFulfillSuffix2(TestDisabledCacheFulfillSuffix):
    should_be_cached = True
    cache_mode = 2


class TestDisabledCacheBypassSuffix(CacheBase):
    should_be_cached = False
    cache_mode = 0
    tempesta_config = MIXED_CONFIG
    uri = '/howto/film.avi'


class TestShardingCacheBypassSuffix(TestDisabledCacheBypassSuffix):
    should_be_cached = False
    cache_mode = 1


class TestReplicatedCacheBypassSuffix(TestDisabledCacheBypassSuffix):
    should_be_cached = False
    cache_mode = 2


class TestDisabledCacheBypassPrefix(CacheBase):
    should_be_cached = False
    cache_mode = 0
    tempesta_config = MIXED_CONFIG
    uri = '/static/dynamic_zone/content.html'


class TestShardingCacheBypassPrefix(TestDisabledCacheBypassPrefix):
    should_be_cached = False
    cache_mode = 1


class TestReplicatedCacheBypassPrefix(TestDisabledCacheBypassPrefix):
    should_be_cached = False
    cache_mode = 2


class TestDisabledCacheFulfillPrefix(CacheBase):
    should_be_cached = False
    cache_mode = 0
    tempesta_config = MIXED_CONFIG
    uri = '/static/content.html'


class TestShardingCacheFulfillPrefix(TestDisabledCacheFulfillPrefix):
    should_be_cached = True
    cache_mode = 1


class TestReplicatedCacheFulfillPrefix(TestDisabledCacheFulfillPrefix):
    should_be_cached = True
    cache_mode = 2
