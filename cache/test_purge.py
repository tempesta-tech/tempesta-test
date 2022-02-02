"""Functional tests of caching different methods."""

from __future__ import print_function
import unittest
from helpers import tf_cfg, chains
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# TODO: add tests for 'cache_purge_acl'

class TestPurge(functional.FunctionalTest):

    config = ('cache 2;\n'
              'cache_fulfill * *;\n'
              'cache_methods GET HEAD;\n'
              'cache_purge;\n'
              'cache_purge_acl %s;\n'
              % tf_cfg.cfg.get('Client', 'ip'))

    config_hdr_del = ('cache 2;\n'
              'cache_fulfill * *;\n'
              'cache_methods GET HEAD;\n'
              'cache_purge;\n'
              'cache_purge_acl %s;\n'
              'cache_resp_hdr_del set-cookie;\n'
              % tf_cfg.cfg.get('Client', 'ip'))

    def chains(self):
        uri = '/page.html'
        result = [
            # All cacheable method to the resource must be cached
            chains.proxy(method='GET', uri=uri),
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='GET', uri=uri),
            chains.cache(method='HEAD', uri=uri),

            chains.cache(method='PURGE', uri=uri),
            # All cached responses was removed, expect re-caching them
            chains.proxy(method='GET', uri=uri),
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='GET', uri=uri),
            chains.cache(method='HEAD', uri=uri)
        ]
        return result

    def test_purge(self):
        self.generic_test_routine(self.config, self.chains())

    def purge_get(self, uri, method='GET'):
        c = chains.proxy(uri=uri)
        c.request.method = 'PURGE'
        c.request.headers['X-Tempesta-Cache'] = method
        c.request.update()
        # A response body must be empty
        c.response.headers['Content-Length'] = '0'
        c.response.body = ''
        c.response.update()
        # Our X-header goes to an upstream
        c.fwd_request.headers['X-Tempesta-Cache'] = method
        return c

    def test_purge_get_basic(self):
        # Basic PURGE use.
        uri = '/page.html'
        ch = [
            # All cacheable method to the resource must be cached
            chains.proxy(method='GET', uri=uri),
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='GET', uri=uri),
            chains.cache(method='HEAD', uri=uri),
            # PURGE + GET works like a cache update, so all following requests
            # must be served from the cache.
            self.purge_get(uri),
            chains.cache(method='GET', uri=uri),
            # Note that due to how Tempesta handles HEAD this doesn't help us
            # with HEAD pre-caching.
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='HEAD', uri=uri),
        ]
        self.generic_test_routine(self.config, ch)

    def test_purge_get_update(self):
        # Return a new response from the upstream to the PURGE+GET request
        # pair, make sure we receive this new response from subsequent
        # requests.
        uri = '/page.html'
        page = 'New page text!\n'
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            self.purge_get(uri),
            chains.cache(method='GET', uri=uri),
        ]
        for c in (ch[2].server_response, ch[3].response):
            c.body = page
            c.headers['Content-Length'] = len(page)
            c.update()
        self.generic_test_routine(self.config, ch)

    def test_purge_get_update_hdr_del(self):
        # Similar PURGE-GET test, but with Set-Cookie header removed via config
        uri = '/page.html'
        page = 'Another page text!\n'
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            self.purge_get(uri),
            chains.cache(method='GET', uri=uri),
        ]

        # purge_get
        c = ch[2].server_response
        c.body = page
        c.headers['Content-Length'] = len(page)
        c.headers['Set-Cookie'] = 'somecookie=2'
        c.update()
        c = ch[2].response
        c.headers['Set-Cookie'] = 'somecookie=2'
        c.update()

        c = ch[3].response
        c.body = page
        c.headers['Content-Length'] = len(page)
        c.update()

        self.generic_test_routine(self.config_hdr_del, ch)

    def test_purge_get_update_cc(self):
        # And another PURGE-GET test, with Set-Cookie removed due to
        # no-cache="set-cookie" in the response
        uri = '/page.html'
        page = 'Another page text!\n'
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            self.purge_get(uri),
            chains.cache(method='GET', uri=uri),
        ]

        # purge_get
        c = ch[2].server_response
        c.body = page
        c.headers['Content-Length'] = len(page)
        c.headers['Set-Cookie'] = 'somecookie=2'
        c.headers['Cache-control'] = 'no-cache="set-cookie"'
        c.update()
        c = ch[2].response
        c.headers['Set-Cookie'] = 'somecookie=2'
        c.headers['Cache-control'] = 'no-cache="set-cookie"'
        c.update()

        c = ch[3].response
        c.body = page
        c.headers['Content-Length'] = len(page)
        c.headers['Cache-control'] = 'no-cache="set-cookie"'
        c.update()

        self.generic_test_routine(self.config_hdr_del, ch)

    def test_useless_x_tempesta_cache(self):
        # Send an ordinary GET request with an "X-Tempesta-Cache" header, and
        # make sure it doesn't affect anything.
        uri = '/page.html'
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
        ]
        for c in ch:
            c.request.headers['X-Tempesta-Cache'] = 'GET'
            c.request.update()
            if c.fwd_request:
                c.fwd_request.headers['X-Tempesta-Cache'] = 'GET'
                c.fwd_request.update()
        self.generic_test_routine(self.config, ch)

    def test_purge_get_garbage(self):
        # Send some garbage in the "X-Tempesta-Cache" header. The entry must
        # be purged, but not re-cached. (This works the same way as a plain
        # PURGE, so we're not using the helper method here.)
        uri = '/page.html'
        def purge(method):
            p = chains.cache(method='PURGE', uri=uri)
            p.request.headers['X-Tempesta-Cache'] = method
            p.request.update()
            return p
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            purge('FRED'),
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            purge('GETWRONG'),
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
        ]
        self.generic_test_routine(self.config, ch)

    def test_purge_get_uncached(self):
        # Send a PURGE request with X-Tempesta-Cache for a non-cached
        # entry. Make sure a new cache entry is populated after the request.
        uri = '/page.html'
        ch = [
            self.purge_get(uri),
            chains.cache(method='GET', uri=uri),
        ]
        self.generic_test_routine(self.config, ch)

    def test_purge_get_uncacheable(self):
        # Send a PURGE request with "X-Tempesta-Cache" for an existing cache
        # entry, and generate a non-cacheable response. Make sure that there
        # is neither the old nor the new response in the cache.
        uri = '/page.html'
        purge = self.purge_get(uri)
        for c in (purge.server_response, purge.response):
            c.headers['Cache-Control'] = 'private'
            c.update()
        ch = [
            chains.proxy(method='GET', uri=uri),
            chains.cache(method='GET', uri=uri),
            purge,
            chains.proxy(method='GET', uri=uri),
        ]
        self.generic_test_routine(self.config, ch)
