"""Functional tests for custom processing of cached responses."""

from __future__ import print_function
from testers import functional
from helpers import chains

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2021 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestCacheControl(functional.FunctionalTest):
    messages = 2
    # Replicated
    cache_mode = 2

    def chain(self, uri='/', cache_allowed=True):
        if self.cache_mode == 0:
            cache_allowed = False
        # cache_allowed = True when caching is forbidden would lead to umbiguous
        # error with empty received "response".
        if cache_allowed:
            test_chains = chains.cache_repeated(self.messages, uri=uri)
        else:
            test_chains = chains.proxy_repeated(self.messages, uri=uri)
        return test_chains

    # cache_resp_hdr_del option
    def common_cache_hdr_del(self, cache_allowed, hdr_val, hdr_del=''):
        cache_allowed_options = { False: 'cache_bypass', True: 'cache_fulfill' }
        hdr_kept = hdr_del == ''
        config = ('cache %d;\n' % self.cache_mode +
                  '%s * *;\n' % cache_allowed_options[cache_allowed] +
                  hdr_del)

        chains = self.chain(cache_allowed=cache_allowed)
        for chain in chains:
            # chains.cache() has neither server_response nor fwd_request
            if hdr_kept or chain.server_response:
                chain.response.headers['Remove-me-2'] = hdr_val
                chain.response.headers['Remove-me'] = hdr_val
                chain.response.update()

            if chain.server_response:
                chain.server_response.headers['Remove-me'] = hdr_val
                chain.server_response.headers['remove-me-2'] = hdr_val
                chain.server_response.update()

        self.generic_test_routine(config, chains)

    def test_cache_hdr_del_bypass(self):
        self.common_cache_hdr_del(cache_allowed=False, \
            hdr_del='cache_resp_hdr_del remove-me Remove-me-2;\n', hdr_val='2 ')

    def test_cache_hdr_del_fulfill(self):
        self.common_cache_hdr_del(cache_allowed=True, \
            hdr_del='cache_resp_hdr_del remove-me Remove-me-2;\n', hdr_val='2 ')

    def test_cache_hdr_del_fulfill2(self):
        self.common_cache_hdr_del(cache_allowed=True, \
            hdr_del='cache_resp_hdr_del remove-me Remove-me-2;\n', hdr_val='2')

    # This test does a regular caching without additional processing,
    # however, the regular caching might not work correctly for
    # empty 'Remove-me' header value due to a bug in message fixups (see #530).
    def test_cache_bypass(self):
        self.common_cache_hdr_del(cache_allowed=False, hdr_val='')

    def test_cache_fulfill(self):
        self.common_cache_hdr_del(cache_allowed=True, hdr_val='')

    def test_cache_fulfill2(self):
        self.common_cache_hdr_del(cache_allowed=True, hdr_val='2')


    #######################################################
    # cache_control_ignore
    def common_no_cache(self, cache_allowed=True, force_cache=None,
                        cache_dir='', req_cache_dir='', cache_config=''):
        cache_allowed_options = { False: 'cache_bypass', True: 'cache_fulfill' }
        config = ('cache %d;\n' % self.cache_mode + 
                  '%s * *;\n' % (cache_allowed_options[cache_allowed]) +
                  cache_config)

        if force_cache is not None:
            cache_allowed = force_cache
        chains = self.chain(cache_allowed=cache_allowed)
        for chain in chains:
            if req_cache_dir != '':
                chain.request.headers['Cache-Control'] = req_cache_dir
                chain.request.update()
                if chain.fwd_request:
                    chain.fwd_request.headers['Cache-Control'] = req_cache_dir
                    chain.fwd_request.update()

            # do we pass the original Cache-Control directives downstream?
            if cache_dir != '':
                chain.response.headers['Cache-Control'] = cache_dir
                chain.response.update()

            if chain.server_response:
                if cache_dir != '':
                    chain.server_response.headers['Cache-Control'] = cache_dir
                chain.server_response.update()

        self.generic_test_routine(config, chains)

    def test_req_no_store_fulfill(self):
        self.common_no_cache(req_cache_dir='no-store', force_cache=False)

    def test_private_fulfill(self):
        self.common_no_cache(cache_dir='private', force_cache=False)
 
    def test_no_cache_fulfill(self):
        self.common_no_cache(cache_dir='no-cache', force_cache=False)

    def test_no_store_fulfill(self):
        self.common_no_cache(cache_dir='no-store', force_cache=False)

    def test_no_cache_ignore_fulfill(self):
        self.common_no_cache(cache_dir='no-cache', force_cache=True, \
            cache_config='cache_control_ignore no-cache;\n')

    def test_no_cache_ignore_fulfill(self):
        self.common_no_cache(cache_dir='no-cache, private, no-store',
            force_cache=True, \
            cache_config='cache_control_ignore no-cache private no-store;\n')

    #######################################################
    # Cache-Control: no-cache and private with arguments
    def common_no_cache_argument(self, cache_allowed, hdr_val, cache_dir='',
                                 hdr_kept=True, hdr2_kept=True):
        cache_allowed_options = { False: 'cache_bypass', True: 'cache_fulfill' }
        config = ('cache %d;\n' % self.cache_mode + 
                  '%s * *;\n' % cache_allowed_options[cache_allowed])

        chains = self.chain(cache_allowed=cache_allowed)
        for chain in chains:
            # chains.cache() has neither server_response nor fwd_request
            if hdr_kept or chain.server_response:
                chain.response.headers['Remove-me'] = hdr_val
                chain.response.update()
            if hdr2_kept or chain.server_response:
                chain.response.headers['Remove-me-2'] = '"'
                chain.response.update()
            if cache_dir != '':
                chain.response.headers['Cache-Control'] = cache_dir
                chain.response.update()

            if chain.server_response:
                chain.server_response.headers['Remove-me'] = hdr_val
                chain.server_response.headers['Remove-me-2'] = '"'
                if cache_dir != '':
                    chain.server_response.headers['Cache-Control'] = cache_dir
                chain.server_response.update()

        self.generic_test_routine(config, chains)

    def test_no_cache_arg_bypass(self):
        self.common_no_cache_argument(cache_allowed=False, \
            cache_dir='no-cache="remove-me"', hdr_kept=False, hdr_val='')

    def test_no_cache_arg_fulfill(self):
        self.common_no_cache_argument(cache_allowed=True, \
            cache_dir='no-cache="remove-me"', hdr_kept=False, hdr_val='')

    def test_no_cache_arg_fulfill2(self):
        self.common_no_cache_argument(cache_allowed=True, \
            cache_dir='no-cache="remove-me"', hdr_kept=False, hdr_val='"arg"')

    def test_private_arg_bypass(self):
        self.common_no_cache_argument(cache_allowed=False, \
            cache_dir='private="remove-me"', hdr_kept=False, hdr_val='')

    def test_private_arg_fulfill(self):
        self.common_no_cache_argument(cache_allowed=True, \
            cache_dir='private="remove-me"', hdr_kept=False, hdr_val='')

    def test_private_arg_fulfill2(self):
        self.common_no_cache_argument(cache_allowed=True, \
            cache_dir='private="remove-me"', hdr_kept=False, hdr_val='=')

    def test_private_arg_fulfill2(self):
        self.common_no_cache_argument(cache_allowed=True, \
            cache_dir='no-cache="remove-me, Remove-me-2"', hdr_val='=', \
            hdr_kept=False, hdr2_kept=False)