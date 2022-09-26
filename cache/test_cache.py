"""Functional tests of caching config."""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers.control import Tempesta
from helpers import tf_cfg
from helpers import checks_for_tests as checks

MIXED_CONFIG = (
    'cache {0};\r\n'
    + 'cache_fulfill suffix ".jpg" ".png";\r\n'
    + 'cache_bypass suffix ".avi";\r\n'
    + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
    + 'cache_fulfill prefix "/static/";\r\n'
)


class TestCache(TempestaTest):
    """"""
    tempesta = {
        'config': """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}
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

    def _test(self, uri: str, cache_mode: int, should_be_cached: bool, tempesta_config: str, ):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_config.format(cache_mode)

        self.start_all_services(deproxy=True)

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
            f'GET {uri} HTTP/1.1\r\n'
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Accept: */*\r\n'
            + '\r\n'
        )

        for _ in range(self.messages):
            client.send_request(request, expected_status_code='200')

        self.assertNotIn('age', client.responses[0].headers, )
        msg = 'Server has received unexpected number of requests.'
        if should_be_cached:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=self.messages - 1,
                cache_misses=1,
                cl_msg_served_from_cache=self.messages - 1,
            )
            self.assertEqual(len(srv.requests), 1, msg)
        else:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=0,
                cache_misses=0,
                cl_msg_served_from_cache=0,
            )
            self.assertEqual(len(srv.requests), self.messages, msg)

        for response in client.responses[1:]:
            if should_be_cached:
                self.assertIn('age', response.headers, msg)
            else:
                self.assertNotIn('age', response.headers, msg)

    def test_disabled_cache_fulfill_all(self):
        self._test(
            uri='/',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config='cache {0};\r\ncache_fulfill * *;\r\n',
        )

    def test_sharding_cache_fulfill_all(self):
        self._test(
            uri='/',
            cache_mode=1,
            should_be_cached=True,
            tempesta_config='cache {0};\r\ncache_fulfill * *;\r\n',
        )

    def test_replicated_cache_fulfill_all(self):
        self._test(
            uri='/',
            cache_mode=2,
            should_be_cached=True,
            tempesta_config='cache {0};\r\ncache_fulfill * *;\r\n',
        )

    def test_disabled_cache_bypass_all(self):
        self._test(
            uri='/',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config='cache {0};\r\ncache_bypass * *;\r\n',
        )

    def test_sharding_cache_bypass_all(self):
        self._test(
            uri='/',
            cache_mode=1,
            should_be_cached=False,
            tempesta_config='cache {0};\r\ncache_bypass * *;\r\n',
        )

    def test_replicated_cache_bypass_all(self):
        self._test(
            uri='/',
            cache_mode=2,
            should_be_cached=False,
            tempesta_config='cache {0};\r\ncache_bypass * *;\r\n',
        )

    def test_disabled_cache_fulfill_suffix(self):
        self._test(
            uri='/picts/bear.jpg',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_sharding_cache_fulfill_suffix(self):
        self._test(
            uri='/picts/bear.jpg',
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_replicated_cache_fulfill_suffix(self):
        self._test(
            uri='/picts/bear.jpg',
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_disabled_cache_fulfill_suffix2(self):
        self._test(
            uri='/jsnfsjk/jnd.png',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_sharding_cache_fulfill_suffix2(self):
        self._test(
            uri='/jsnfsjk/jnd.png',
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_replicated_cache_fulfill_suffix2(self):
        self._test(
            uri='/jsnfsjk/jnd.png',
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_disabled_cache_bypass_suffix(self):
        self._test(
            uri='/howto/film.avi',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_sharding_cache_bypass_suffix(self):
        self._test(
            uri='/howto/film.avi',
            cache_mode=1,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_replicated_cache_bypass_suffix(self):
        self._test(
            uri='/howto/film.avi',
            cache_mode=2,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_disabled_cache_bypass_prefix(self):
        self._test(
            uri='/static/dynamic_zone/content.html',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_sharding_cache_bypass_prefix(self):
        self._test(
            uri='/static/dynamic_zone/content.html',
            cache_mode=1,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_replicated_cache_bypass_prefix(self):
        self._test(
            uri='/static/dynamic_zone/content.html',
            cache_mode=2,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_disabled_cache_fulfill_prefix(self):
        self._test(
            uri='/static/content.html',
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG
        )

    def test_sharding_cache_fulfill_prefix(self):
        self._test(
            uri='/static/content.html',
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_replicated_cache_fulfill_prefix(self):
        self._test(
            uri='/static/content.html',
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )

    def test_cache_date(self):
        self._test(
            uri='/static/content.html',
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG
        )
        client = self.get_client('deproxy')
        for response in client.responses:
            self.assertIn('date', response.headers, )
