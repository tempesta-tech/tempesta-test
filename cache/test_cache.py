"""Functional tests of caching responses."""

from __future__ import print_function
from testers import functional
from helpers import chains
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
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

class H2Cache(tester.TempestaTest):
    clients = [{
        'id': 'deproxy',
        'type': 'deproxy_h2',
        'addr': "${tempesta_ip}",
        'port': '443',
        'ssl': True,
        'ssl_hostname': 'tempesta-tech.com'
    }]

    backends = [{
        'id' : 'deproxy',
        'type' : 'deproxy',
        'port' : '8000',
        'response' : 'static',
        'response_content' :
        'HTTP/1.1 200 OK\r\n'
        'Content-Length: 0\r\n\r\n'
    }]

    tempesta = {
        'config':
        '''
        cache 2;
        cache_fulfill eq /to-be-cached;

        listen 443 proto=h2;
        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            proxy_pass default;
        }

       '''
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.start_all()

        request = [
            (":authority", "tempesta-tech.com"),
            (":path", "/to-be-cached"),
            (":scheme", "https"),
            (":method", "GET")
        ]
        requests = [request, request]

        client = self.get_client("deproxy")
        client.make_requests(requests)

        got_response = client.wait_for_response(timeout=5)

        self.assertTrue(got_response)

        # Only the first request should be forwarded to the backend.
        self.assertEqual(
            len(self.get_server('deproxy').requests),
            1,
            "The second request wasn't served from cache."
        )

#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
