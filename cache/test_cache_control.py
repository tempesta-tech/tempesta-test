"""Functional tests for custom processing of cached responses."""

from __future__ import print_function
from framework import tester
import copy
import time

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestCacheControl(tester.TempestaTest):
    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        }
    ]

    tempesta_template = {
        'config' :
            """
            server ${general_ip}:8000;
            cache 2;
            %(tempesta_config)s
            """
    }

    backends_template = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Server-id: deproxy\r\n'
                'Content-Length: 0\r\n'
                '%(response_headers)s\r\n'
        },
    ]
    
    tempesta_config = '''
        cache_fulfill * *;
        '''

    request_headers = {}
    response_headers = {}
    response_status = '200'
    should_be_cached = False # True means Tempesta Fw should make no forward the
                             # request upstream and serve it from cache only.
    sleep_interval = None # between the first and second request.
    second_request_headers = None # When the two requests differ.
    cached_headers = None # Reference headers to compare with actual cached
                          # response. Empty if cached/second response is same as
                          # first one.
    cached_status = '200'

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def setUp(self):
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta['config'] = self.tempesta['config'] % \
                        {'tempesta_config': self.tempesta_config or ''}

        self.backends = copy.deepcopy(self.backends_template)
        headers = ''
        for name, val in self.response_headers.iteritems():
            headers += '%s: %s\r\n' % (name, '' if val is None else val)
        self.backends[0]['response_content'] = \
            self.backends[0]['response_content'] % {'response_headers': headers}
        # apply default values for optional fields
        if getattr(self, 'cached_headers', None) is None:
            self.cached_headers = self.response_headers
        if getattr(self, 'second_request_headers', None) is None:
            self.second_request_headers = self.request_headers

        super(TestCacheControl, self).setUp()

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.last_response

    def check_response_headers(self, response):
        for name, val in self.response_headers.iteritems():
            actual_val = response.headers.get(name, None)
            if actual_val is None:
                self.assertIsNone(actual_val,
                    "{} header is missing in the response".format(name))
            else:
                self.assertIsNotNone(actual_val,
                    "{} header is present in the response".format(name))

    def check_cached_response_headers(self, response):
        for name, val in self.cached_headers.iteritems():
            actual_val = response.headers.get(name, None)
            if actual_val is None:
                self.assertIsNone(actual_val,
                    "{} header is missing in the cached response". \
                        format(name))
            else:
                self.assertIsNotNone(actual_val,
                    "{} header is present in the cached response". \
                        format(name))

    def _test(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        req_headers = ''
        if self.request_headers:
            for name, val in self.request_headers.iteritems():
                req_headers += '%s: %s\r\n' % (name, '' if val is None else val)
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "%s\r\n" % req_headers)

        response = self.client_send_req(client, req)
        self.assertEqual(response.status, self.response_status,
                         "request failed: {}, expected {}" \
                         .format(response.status, self.response_status))
        self.check_response_headers(response)

        if self.sleep_interval:
            time.sleep(self.sleep_interval)

        req_headers2 = ''
        if self.request_headers:
            for name, val in self.second_request_headers.iteritems():
                req_headers2 += '%s: %s\r\n' % (name, '' if val is None else val)
        req2 = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "%s\r\n" % req_headers2)
        cached_response = self.client_send_req(client, req2)
        self.assertEqual(cached_response.status, self.cached_status,
                         "request for cache failed: {}, expected {}" \
                         .format(response.status, self.cached_status))

        self.assertEqual(2, len(client.responses), "response lost")
        if self.should_be_cached:
            self.assertEqual(1, len(srv.requests),
                             "response not cached as expected")
        else:
            self.assertEqual(2, len(srv.requests),
                             "response is cached while it should not be")
 
        if self.should_be_cached:
            self.check_cached_response_headers(cached_response)
        else:
            self.check_response_headers(cached_response)

class SingleTest(object):
    def test(self):
        self._test()

# Naming convension for test class name:
#   NameSuffix
# where "Name" is the name of the feature being tested e.g.
# "RequestMaxAge" - max-age directive in the request,
# and "Suffix" is either:
# - "Bypass" - cache_bypass is enabled and the response is never cached.
# - "Cached" - response is normally cached;
# - "NotCached" - response is normally not cached (forwarded upstream);
# - "Ignore" - the directive is disabled by cache_control_ignore, default
#              behaviour ensues.
# - empty value for default behaviour, 
# For example, ResponseMustRevalidateIgnore - testing "must-revalidate"
# in the request, which should be ignored due to cache_control_ignore.

#########################################################
#  cache_resp_hdr_del
class CacheHdrDelBypass(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': ''}
    should_be_cached = False

class CacheHdrDelCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': ''}
    cached_headers = {'Set-Cookie': None, 'Remove-me-2': None}
    should_be_cached = True

class CacheHdrDelCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': '2'}
    cached_headers = {'Set-Cookie': None, 'Remove-me-2': None}
    should_be_cached = True

# This test does a regular caching without additional processing,
# however, the regular caching might not work correctly for
# empty 'Remove-me' header value due to a bug in message fixups (see #530).
class TestCacheBypass(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': ''}
    should_be_cached = False

class TestCache(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': ''}
    should_be_cached = True

class TestCache2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '2', 'Remove-me-2': '2'}
    should_be_cached = True

#########################################################
#  cache_control_ignore
#########
# request
# max-age
class RequestMaxAgeNoCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=3'}
    sleep_interval = 1.5
    should_be_cached = False

class RequestMaxAgeCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=3'}
    sleep_interval = None
    should_be_cached = True

# max-age, max-stale
class RequestMaxAgeMaxStaleNotCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=5, max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 3
    should_be_cached = False

class RequestMaxAgeMaxStaleCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=3, max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_be_cached = True

class RequestMaxStaleCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-stale'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_be_cached = True

# min-fresh
class RequestMinFreshNotCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'min-fresh=2'}
    response_headers = {'Cache-control': 'max-age=3'}
    sleep_interval = 1.5
    should_be_cached = False

class RequestMinFreshCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'min-fresh=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = None
    should_be_cached = True

# max-age
class RequestOnlyIfCachedCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = None
    second_request_headers = {'Cache-control': 'max-age=1, only-if-cached'}
    cached_status = '200'
    should_be_cached = True

class RequestOnlyIfCached504(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = 2.5
    second_request_headers = {'Cache-control': 'max-age=1, only-if-cached'}
    cached_status = '504'
    should_be_cached = True


class RequestNoStoreNotCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'no-store'}
    should_be_cached = False

class RequestNoStoreNotCached(TestCacheControl, SingleTest):
    request_headers = {'Cache-control': 'no-cache'}
    should_be_cached = False

##########
# response
#
# must-revalidate
#
# Per RFC 7234 "Cache-Control: max-age=0, must-revalidate" has exactly same
# semantic as "no-cache". See section 4.2.4:
# "A cache MUST NOT generate a stale response if it is prohibited by an
#  explicit in-protocol directive (e.g., by a "no-store" or "no-cache"
#  cache directive, a "must-revalidate" cache-response-directive, or an
#  applicable "s-maxage" or "proxy-revalidate" cache-response-directive;
#  see Section 5.2.2)."
# Here we test the cache behaviour for stale responses with
# "max-age=1, must-revalidate", which mandates revalidation after 1 second.
class ResponseMustRevalidateNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseMustRevalidateNotCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

# RFC 7234 Sections 3.2, 4.2.4:
# "cached responses that contain the "must-revalidate" and/or
#  "s-maxage" response directives are not allowed to be served stale
#  by shared caches"
class ResponseMustRevalidateCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    should_be_cached = True
    sleep_interval = None

class ResponseMustRevalidateCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = None
    should_be_cached = True

class ResponseMustRevalidateIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore must-revalidate;
        '''
    # Although must-revalidate is ignored, max-age=1 remains active.
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseMustRevalidateIgnore2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore must-revalidate;
        '''
    request_headers = {}
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = True

# proxy-revalidate
class ResponseProxyRevalidateNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseProxyRevalidateNotCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseProxyRevalidateIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseCached3(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_be_cached = True

class ResponseProxyRevalidateIgnore3(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_be_cached = True

# Support for "max-stale" + "max-age=1, proxy-revalidate" is questionable and
# already tested above. So we test multiple directives with a more reliable
# logic of "Authorizarion" caching.
class ResponseMustRevalidateNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control':
                        'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseMustRevalidateHalfIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control':
                        'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = True

class ResponseMustRevalidateMultiIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age must-revalidate;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control':
                        'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_be_cached = False

# max-age/s-maxage
class ResponseMaxAgeNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseMaxAgeCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = None
    should_be_cached = True

class ResponseMaxAgeIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_be_cached = True

class ResponseSMaxageNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = 1.5
    should_be_cached = False

# s-maxage forbids serving stale responses (implies proxy-revalidate)
class ResponseSMaxageNotCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=2'}
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseSMaxageCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = None
    should_be_cached = True

# Authorization interacts with s-maxage, but not with max-age.
# See RFC 7234 Section 3.2.
class ResponseMaxAgeNotCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 's-maxage=0'}
    sleep_interval = None
    should_be_cached = False

class ResponseMaxAgeCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = None
    should_be_cached = True

class ResponseSMaxageIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore s-maxage;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = 1.5
    should_be_cached = True

class ResponseSMaxageMaxAgeNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    response_headers = {'Cache-control': 'max-age=1, s-maxage=1'}
    sleep_interval = 1.5
    should_be_cached = False

class ResponseSMaxageMaxAgeIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age s-maxage;
        '''
    response_headers = {'Cache-control': 'max-age=1, s-maxage=1'}
    sleep_interval = 1.5
    should_be_cached = True

# private/no-cache/no-store
class ResponsePrivate(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'private'}
    should_be_cached = False

class ResponseNoCache(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_be_cached = False

class ResponseNoStore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'no-store'}
    should_be_cached = False

class ResponseNoCacheIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore no-cache;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_be_cached = True

# multiple cache_control_ignore directives
class ResponseNoCacheIgnoreMulti(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age no-cache;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_be_cached = True

class ResponseMultipleNoCacheIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore no-cache private no-store;
        '''
    response_headers = {'Cache-control': 'no-cache, private, no-store'}
    should_be_cached = True

# public directive and Authorization header
class ResponsePublicNotCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {}
    should_be_cached = False

class ResponsePublicCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_be_cached = True

class ResponsePublicCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {}
    # Interestingly enough, RFC 7234 does not forbid serving cached response for
    # subsequent requests with "Authorization" header.
    second_request_headers = {'Authorization': 'asd'}
    should_be_cached = True

class ResponsePublicIgnore(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore public;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_be_cached = False

# multiple cache_control_ignore directives
class ResponsePublicIgnore2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore must-revalidate public;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_be_cached = False

#########################################################
#  Cache-Control: no-cache and private with arguments
#############
# no-cache
class CCArgNoCacheBypass(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    should_be_cached = False

class CCArgNoCacheCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    cached_headers = {'Remove-me': None, 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    should_be_cached = True

class CCArgNoCacheCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '"arg"', 'Remove-me-2': '"arg"',
        'Cache-control': 'no-cache="remove-me"'}
    cached_headers = {'Remove-me': None, 'Remove-me-2': '"arg"',
        'Cache-control': 'no-cache="remove-me"'}
    should_be_cached = True
    
class CCArgNoCacheCached3(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-Control':
        'public, no-cache="Set-Cookie", must-revalidate, max-age=120',
        'Set-Cookie': 'some=cookie'}
    cached_headers = {
        'Cache-Control':
            'public, no-cache="Set-Cookie", must-revalidate, max-age=120',
        'Set-Cookie': None
    }
    should_be_cached = True

#############
# private
class CCArgPrivateBypass(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    should_be_cached = False

class CCArgPrivateCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    should_be_cached = True

class CCArgPrivateCached2(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '=',
        'Cache-control': 'private="set-cookie"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': '=',
        'Cache-control': 'private="set-cookie"'}
    should_be_cached = True

# erase two headers
class CCArgBothNoCacheCached(TestCacheControl, SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '"',
        'Cache-control': 'no-cache="set-cookie, Remove-me-2"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': None,
        'Cache-control': 'no-cache="set-cookie, Remove-me-2"'}
    should_be_cached = True
