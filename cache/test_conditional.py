"""Functional tests of caching different methods."""

from __future__ import print_function
from helpers import chains
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# TODO: Check that all headers that must be present in 304 response are there.
# Not implemented since some of them (at least Vary) affect cache behaviour.

class TestConditional(functional.FunctionalTest):

    config = ('cache 2;\n'
              'cache_fulfill * *;\n'
              'cache_methods GET;\n')

    @staticmethod
    def make_304(response):
        # Connection is added since tempesta send 'Connection: keep-alive' or
        # 'Connection: close'
        hdrs_304 = ['cache-control', 'content-location', 'date', 'etag',
                    'expires', 'vary', 'connection']
        hdrs = response.headers.keys()
        for hdr in hdrs:
            if not hdr in hdrs_304:
                del response.headers[hdr]
        response.status = '304'
        response.body = ''
        response.body_void = True
        response.update()

    @staticmethod
    def chains(etag=None, last_modified=None):
        uri = '/page.html'
        # Tests uses castom ETag and Last-Modified, so remove predefined
        remove_hdrs = ['ETag', 'Last-Modified']
        test_chains = [chains.proxy(method='GET', uri=uri),
                       chains.cache(method='GET', uri=uri)]
        for resp in [test_chains[0].response, test_chains[0].server_response,
                     test_chains[1].response]:
            for hdr in remove_hdrs:
                del resp.headers[hdr]
            if etag:
                resp.headers['ETag'] = etag
            if last_modified:
                resp.headers['Last-Modified'] = last_modified
            resp.update()
        return test_chains

    def chains_200(self, cond_hdr, etag=None, last_modified=None):
        msg_chains = self.chains(etag, last_modified)

        hdr, val = cond_hdr
        msg_chains[1].request.headers[hdr] = val
        msg_chains[1].request.update()

        return msg_chains

    def chains_304(self, cond_hdr, etag=None, last_modified=None):
        msg_chains = self.chains_200(cond_hdr, etag, last_modified)
        self.make_304(msg_chains[1].response)
        return msg_chains

    # If-None-Match. Client has cached resource.

    def test_none_match(self):
        "Client have cached resource, send 304"
        etag = '"asdfqwerty"'
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', etag)
        msg_chains = self.chains_304(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_none_match_weak_srv(self):
        "Same as test_none_match() but server sends weak etag"
        etag = '"asdfqwerty"'
        w_etag = 'W/%s' % etag
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', etag)
        msg_chains = self.chains_304(cond_hdr, w_etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_none_match_weak_clnt(self):
        "Same as test_none_match() but client sends weak etag"
        etag = '"asdfqwerty"'
        w_etag = 'W/%s' % etag
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', w_etag)
        msg_chains = self.chains_304(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_none_match_weak_all(self):
        "Same as test_none_match() but both server and client send weak etag"
        etag = '"asdfqwerty"'
        w_etag = 'W/%s' % etag
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', w_etag)
        msg_chains = self.chains_304(cond_hdr, w_etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_none_match_list(self):
        """Same as test_none_match() but client has saved copies of several
        resources"""
        etag = '"asdfqwerty"'
        etag_list = '"fsdfds", %s, "sdfrgg"' % etag
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', etag_list)
        msg_chains = self.chains_304(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_none_match_any(self):
        """Same as test_none_match() but client has cached entire world
        cached"""
        etag = '"asdfqwerty"'
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', '*')
        msg_chains = self.chains_304(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    # If-None-Match. Client has no cached resource.

    def test_none_match_nc(self):
        "Client have no cached resource, send full response"
        etag = '"asdfqwerty"'
        etag_other = '"jfgfdgnjdn"'
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-None-Match', etag_other)
        msg_chains = self.chains_200(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    # If-Modified-Since

    def test_mod_since(self):
        "Client have cached resource, send 304"
        etag = '"asdfqwerty"'
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        after_lm = " Mon, 19 Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-Modified-Since', after_lm)
        msg_chains = self.chains_304(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)

    def test_mod_since_nc(self):
        "Client have no cached resource, send full response"
        etag = '"asdfqwerty"'
        lm_date = " Mon, 12 Dec 2016 13:59:39 GMT"
        before_lm = " Mon, 5  Dec 2016 13:59:39 GMT"
        cond_hdr = ('If-Modified-Since', before_lm)
        msg_chains = self.chains_200(cond_hdr, etag, lm_date)
        self.generic_test_routine(self.config, msg_chains)
