"""Functional tests for adding user difined headers."""

from __future__ import print_function
from testers import functional
from helpers import chains

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestReqAddHeader(functional.FunctionalTest):

    location = '/'
    directive = 'req_hdr_add'

    def make_def_config(self):
        self.config = ''

    def config_append_directive(self, hdrs, location=None):
        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)
        for (name, val) in hdrs:
            self.config = self.config + ('%s %s "%s";\n' % (self.directive, name, val))
        if location is not None:
            self.config = self.config + '}\n'

    def make_chain(self, hdrs):
        chain = chains.proxy()
        for (name, val) in hdrs:
            chain.fwd_request.headers[name] = val
        chain.fwd_request.update()
        self.msg_chain = [chain]

    def add_hdrs(self, hdrs, location=None):
        self.make_def_config()
        self.config_append_directive(hdrs, location)
        self.make_chain(hdrs)

    def test_add_one_hdr(self):
        hdrs = [('X-My-Hdr', 'some text')]
        self.add_hdrs(hdrs)
        self.generic_test_routine(self.config, self.msg_chain)

    def test_add_some_hdrs(self):
        hdrs = [('X-My-Hdr', 'some text'),
                ('X-My-Hdr-2', 'some other text')]
        self.add_hdrs(hdrs)
        self.generic_test_routine(self.config, self.msg_chain)

    def test_add_some_hdrs_custom_location(self):
        hdrs = [('X-My-Hdr', 'some text'),
                ('X-My-Hdr-2', 'some other text')]
        self.add_hdrs(hdrs, self.location)
        self.generic_test_routine(self.config, self.msg_chain)

    def test_add_hdrs_derive_config(self):
        '''Derive general settings to custom location.'''
        hdrs = [('X-My-Hdr', 'some text')]
        self.make_def_config()
        self.config_append_directive(hdrs)
        self.config_append_directive([], self.location)
        self.make_chain(hdrs)
        self.generic_test_routine(self.config, self.msg_chain)

    def test_add_hdrs_override_config(self):
        '''Override general settings to custom location.'''
        hdrs = [('X-My-Hdr', 'some text')]
        o_hdrs = [('X-My-Hdr-2', 'some other text')]
        self.make_def_config()
        self.config_append_directive(hdrs)
        self.config_append_directive(o_hdrs, self.location)
        self.make_chain(o_hdrs)
        self.generic_test_routine(self.config, self.msg_chain)


class TestRespAddHeader(TestReqAddHeader):

    directive = 'resp_hdr_add'

    def make_chain(self, hdrs):
        chain = chains.proxy()
        for (name, val) in hdrs:
            chain.response.headers[name] = val
        chain.response.update()
        self.msg_chain = [chain]


class TestCachedRespAddHeader(TestRespAddHeader):
    """ Response is served from cache. """

    def make_def_config(self):
        self.config = ('cache 2;\n'
                       'cache_fulfill * *;\n')

    def make_chain(self, hdrs):
        chain_p = chains.proxy()
        chain_c = chains.cache()
        for (name, val) in hdrs:
            chain_p.response.headers[name] = val
            chain_c.response.headers[name] = val
        chain_p.response.update()
        chain_c.response.update()
        self.msg_chain = [chain_p, chain_c]


class TestReqSetHeader(TestReqAddHeader):

    directive = 'req_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain = chains.proxy()
        for (name, val) in orig_hdrs:
            chain.request.headers[name] = val
            chain.fwd_request.headers[name] = val
        for (name, val) in hdrs:
            chain.fwd_request.headers[name] = val
        chain.request.update()
        chain.fwd_request.update()
        self.msg_chain = [chain]


class TestRespSetHeader(TestReqSetHeader):

    directive = 'resp_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain = chains.proxy()
        for (name, val) in orig_hdrs:
            chain.server_response.headers[name] = val
            chain.response.headers[name] = val
        for (name, val) in hdrs:
                chain.response.headers[name] = val
        chain.server_response.update()
        chain.response.update()
        self.msg_chain = [chain]


class TestCachedRespSetHeader(TestRespSetHeader):
    """ Response is served from cache. """

    def make_def_config(self):
        self.config = ('cache 2;\n'
                       'cache_fulfill * *;\n')

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain_p = chains.proxy()
        chain_c = chains.cache()
        for (name, val) in orig_hdrs:
            chain_p.server_response.headers[name] = val
            chain_p.response.headers[name] = val
            chain_c.response.headers[name] = val
        for (name, val) in hdrs:
                chain_p.response.headers[name] = val
                chain_c.response.headers[name] = val
        chain_p.server_response.update()
        chain_p.response.update()
        chain_c.response.update()
        self.msg_chain = [chain_p, chain_c]


class TestReqDelHeader(TestReqAddHeader):

    directive = 'req_hdr_set'

    def config_append_directive(self, hdrs, location=None):
        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)
        for (name, val) in hdrs:
            self.config = self.config + ('%s %s;\n' % (self.directive, name))
        if location is not None:
            self.config = self.config + '}\n'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain = chains.proxy()
        for (name, val) in orig_hdrs:
            chain.request.headers[name] = val
            chain.fwd_request.headers[name] = val
        for (name, val) in hdrs:
            del chain.fwd_request.headers[name]
        chain.request.update()
        chain.fwd_request.update()
        self.msg_chain = [chain]


class TestRespDelHeader(TestReqDelHeader):

    directive = 'resp_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain = chains.proxy()
        for (name, val) in orig_hdrs:
            chain.server_response.headers[name] = val
            chain.response.headers[name] = val
        for (name, val) in hdrs:
            del chain.response.headers[name]
        chain.server_response.update()
        chain.response.update()
        self.msg_chain = [chain]


class TestCachedRespDelHeader(TestRespDelHeader):
    """ Response is served from cache. """

    def make_def_config(self):
        self.config = ('cache 2;\n'
                       'cache_fulfill * *;\n')

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        chain_p = chains.proxy()
        chain_c = chains.cache()
        for (name, val) in orig_hdrs:
            chain_p.server_response.headers[name] = val
            chain_p.response.headers[name] = val
            chain_c.response.headers[name] = val
        for (name, val) in hdrs:
            del chain_p.response.headers[name]
            del chain_c.response.headers[name]
        chain_p.server_response.update()
        chain_p.response.update()
        chain_c.response.update()
        self.msg_chain = [chain_p, chain_c]

# TODO: add tests for different vhosts, when vhosts will be implemented.
