from __future__ import print_function
import re
from helpers import deproxy, tf_cfg, chains
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CHAIN_LENGTH = 20

def make_302(request):
    response = deproxy.Response(
        'HTTP/1.1 302 Found\r\n'
        'Content-Length: 0\r\n'
        'Location: http://%s%s\r\n'
        'Connection: keep-alive\r\n'
        '\r\n'
        % (tf_cfg.cfg.get('Tempesta', 'ip'), request.uri))
    return response

def make_502():
    response = deproxy.Response(
        'HTTP/1.1 502 Bad Gateway\r\n'
        'Content-Length: 0\r\n'
        'Connection: keep-alive\r\n'
        '\r\n')
    return response

class TesterCookies(deproxy.Deproxy):

    def verify_adjust_header(self, response, name, rexp):
        gen_rexp = ''.join([r'^(.*)', rexp, r'([a-f0-9]+)(.*)$'])
        m = re.search(gen_rexp, response.headers[name])
        assert m, '%s header not found!' % (name)
        head = m.group(1)
        val = m.group(2)
        tail = m.group(3)

        exp_resp = self.current_chain.response
        exp_resp.headers.delete_all(name)
        exp_resp.headers.add(name, response.headers[name])
        exp_resp.update()

        return head, val, tail

class TesterIgnoreCookies(TesterCookies):
    """Tester helper. Emulate client that does not support cookies."""

    def __init__(self, *args, **kwargs):
        TesterCookies.__init__(self, *args, **kwargs)
        self.message_chains = chains.base_repeated(CHAIN_LENGTH)
        self.cookies = []

    def received_response(self, response):
        _, cookie, _ = self.verify_adjust_header(response, 'Set-Cookie', r'__tfw=')

        # Client doesn't support cookies: Tempesta will generate new cookie for
        # each request.
        assert cookie not in self.cookies, \
            'Received non-unique cookie!'

        exp_resp = self.current_chain.response
        if exp_resp.status != '200':
            exp_resp.headers.delete_all('Date')
            exp_resp.headers.add('Date', response.headers['Date'])
            exp_resp.update()

        TesterCookies.received_response(self, response)


class TesterIgnoreEnforcedCookies(TesterIgnoreCookies):
    """Tester helper. Emulate client that does not support cookies, but
    Tempesta enforces cookies.
    """

    def __init__(self, *args, **kwargs):
        TesterIgnoreCookies.__init__(self, *args, **kwargs)
        self.message_chains[0].response = make_302(
            self.message_chains[0].request)
        self.message_chains[0].server_response = deproxy.Response()
        self.message_chains[0].fwd_request = deproxy.Request()


class TesterUseCookies(TesterCookies):
    """Tester helper. Emulate client that support cookies."""

    def __init__(self, *args, **kwargs):
        TesterCookies.__init__(self, *args, **kwargs)
        # The first message chain is unique.
        self.message_chains = [chains.base()] + chains.base_repeated(CHAIN_LENGTH)
        self.cookie_parsed = False

    def received_response(self, response):
        if not self.cookie_parsed:
            _, cookie, _ = self.verify_adjust_header(response, 'Set-Cookie', r'__tfw=')

            # All following requests must contain Cookie header
            for req in [self.message_chains[1].request,
                        self.message_chains[1].fwd_request]:
                req.headers.add('Cookie', ''.join(['__tfw=', cookie]))
                req.update()

            self.cookie_parsed = True

        exp_resp = self.current_chain.response
        if exp_resp.status != '200':
            exp_resp.headers.delete_all('Date')
            exp_resp.headers.add('Date', response.headers['Date'])
            exp_resp.update()

        TesterCookies.received_response(self, response)


class TesterUseEnforcedCookies(TesterUseCookies):
    """Tester helper. Emulate client that support cookies."""

    def __init__(self, *args, **kwargs):
        TesterUseCookies.__init__(self, *args, **kwargs)
        self.message_chains[0].response = make_302(
            self.message_chains[0].request)
        self.message_chains[0].server_response = deproxy.Response()
        self.message_chains[0].fwd_request = deproxy.Request()


class TesterIgnoreEnforcedExtCookies(TesterIgnoreEnforcedCookies):
    """Tester helper. Client that does not support cookies and does not
    follow redirection mark, but Tempesta enforces cookies in extended
    mode.
    """

    def received_response(self, response):
        self.verify_adjust_header(response, 'Location', r'/__tfw=')
        TesterIgnoreEnforcedCookies.received_response(self, response)


class TesterIgnoreEnforcedExtCookiesRmark(TesterIgnoreEnforcedCookies):
    """Tester helper. Client does not support cookies, but follows
    redirection mark. Tempesta enforces cookies in extended mode.
    """

    def received_response(self, response):
        auth, rmark, uri = self.verify_adjust_header(response, 'Location', r'/__tfw=')

        # Every request must contain received mark before URI path
        req = self.message_chains[0].request
        req.uri = ''.join([auth, '/__tfw=', rmark, uri])
        req.update()

        TesterIgnoreEnforcedCookies.received_response(self, response)


class TesterInvalidEnforcedExtCookiesRmark(TesterIgnoreEnforcedExtCookiesRmark):
    """Tester helper. Client follows redirection mark, but insert invalid
    cookies into requests. Tempesta enforces cookies in extended mode.
    """

    def received_response(self, response):
        # Insert into requests invalid cookie with arbitrary timestamp
        # and HMAC generated for zero timestamp (in order to violate
        # cookie verification)
        tstamp = '0000000123456789'
        hmac = 'c40fa58c59f09c8ea81223e627c9de12cfa53679'
        req =  self.message_chains[0].request
        req.headers.delete_all('Cookie')
        req.headers.add('Cookie', ''.join(['__tfw=', tstamp, hmac]))
        req.update()

        TesterIgnoreEnforcedExtCookiesRmark.received_response(self, response)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
