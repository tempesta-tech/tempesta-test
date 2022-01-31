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
    should_cache = False # True means Tempesta Fw should make no forward the
                         # request upstream
    sleep_interval = None
    second_request_headers = None
    cached_headers = None
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

        return client.responses[-1]

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

        cached_response = self.client_send_req(client, req)
        self.assertEqual(response.status, self.cached_status,
                         "request for cache failed: {}, expected {}" \
                         .format(response.status, self.cached_status))

        self.assertEqual(2, len(client.responses), "response lost")
        if self.should_cache:
            self.assertEqual(1, len(srv.requests),
                             "response not cached as expected")
        else:
            self.assertEqual(2, len(srv.requests),
                             "response is cached while it should not")
 
        if self.should_cache:
            self.check_cached_response_headers(cached_response)
        else:
            self.check_response_headers(cached_response)

#########################################################
#  cache_resp_hdr_del
class CacheHdrDelBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': ''}
    should_cache = False

class CacheHdrDelFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': ''}
    cached_headers = {'Set-Cookie': None, 'Remove-me-2': None}
    should_cache = True

class CacheHdrDelFulfill2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_resp_hdr_del set-cookie Remove-me-2;
        '''
    response_headers = {'Set-Cookie': 'cookie=2; a=b', 'Remove-me-2': '2'}
    cached_headers = {'Set-Cookie': None, 'Remove-me-2': None}
    should_cache = True

# This test does a regular caching without additional processing,
# however, the regular caching might not work correctly for
# empty 'Remove-me' header value due to a bug in message fixups (see #530).
class TestCacheBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': ''}
    should_cache = False

class TestCacheFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': ''}
    should_cache = True

class TestCacheFulfill2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '2', 'Remove-me-2': '2'}
    should_cache = True

#########################################################
#  cache_control_ignore
#########
# request
class RequestMaxAgeBypass(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = 1.5
    should_cache = False

class RequestMaxAgeFulfill(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = None
    should_cache = True

class RequestMaxAgeMaxStaleBypass(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=3, max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 2.5
    should_cache = False

class RequestMaxAgeMaxStaleFulfill(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=3, max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_cache = True
    
class RequestMaxStaleFulfill(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-stale'}
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_cache = True

# min-fresh
class RequestMinFreshBypass(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'min-fresh=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = 1.5
    should_cache = False

class RequestMinFreshFulfill(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'min-fresh=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = None
    should_cache = True

class RequestOnlyIfCached(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = None
    second_request_headers = {'Cache-control': 'max-age=1, only-if-cached'}
    cached_status = '200'
    should_cache = True

class RequestOnlyIfCached504(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'max-age=1'}
    response_headers = {'Cache-control': 'max-age=2'}
    sleep_interval = 1.5
    second_request_headers = {'Cache-control': 'max-age=1, only-if-cached'}
    cached_status = '504'
    should_cache = True

class RequestNoStore(TestCacheControl, tester.SingleTest):
    request_headers = {'Cache-control': 'no-store'}
    should_cache = False

##########
# response
# must-revalidate
class ResponseMustRevalidateBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMustRevalidateBypass2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMustRevalidateFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    should_cache = True
    sleep_interval = None

class ResponseMustRevalidateFulfill2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = None
    should_cache = True

class ResponseMustRevalidateIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore must-revalidate;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, must-revalidate'}
    sleep_interval = 1.5
    should_cache = True

# proxy-revalidate
class ResponseMustRevalidateBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMustRevalidateBypass2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Cache-control': 'max-stale=1'}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMustRevalidateIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        '''
    request_headers = {}
    response_headers = {'Cache-control': 'max-age=1, proxy-revalidate'}
    sleep_interval = 1.5
    should_cache = True

# multiple directives
class ResponseMustRevalidateHalfIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        '''
    request_headers = {}
    response_headers = {'Cache-control':
                        'max-age=1, must-revalidate, proxy-revalidate'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMustRevalidateMultiIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate must-revalidate;
        '''
    request_headers = {}
    response_headers = {'Cache-control':
                        'max-age=1, must-revalidate, proxy-revalidate'}
    sleep_interval = 1.5
    should_cache = True

# max-age/s-maxage
class ResponseMaxAgeBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_cache = False

class ResponseMaxAgeFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = None
    should_cache = True

class ResponseMaxAgeIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    response_headers = {'Cache-control': 'max-age=1'}
    sleep_interval = 1.5
    should_cache = True

class ResponseMaxageBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = 1.5
    should_cache = False

class ResponseSMaxageFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = None
    should_cache = True

class ResponseSMaxageIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    response_headers = {'Cache-control': 's-maxage=1'}
    sleep_interval = 1.5
    should_cache = True

class ResponseSMaxageMaxAgeBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age;
        '''
    response_headers = {'Cache-control': 'max-age=1, s-maxage=1'}
    sleep_interval = 1.5
    should_cache = False

class ResponseSMaxageMaxAgeIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age s-maxage;
        '''
    response_headers = {'Cache-control': 'max-age=1, s-maxage=1'}
    sleep_interval = 1.5
    should_cache = True

# private/no-cache/no-store
class ResponsePrivate(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'private'}
    should_cache = False

class ResponseNoCache(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_cache = False

class ResponseNoStore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Cache-control': 'no-store'}
    should_cache = False

class ResponseNoCacheIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore no-cache;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_cache = True

# multiple cache_control_ignore directives
class ResponseNoCacheIgnoreMulti(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore max-age no-cache;
        '''
    response_headers = {'Cache-control': 'no-cache'}
    should_cache = True

class ResponseMultipleNoCacheIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore no-cache private no-store;
        '''
    response_headers = {'Cache-control': 'no-cache, private, no-store'}
    should_cache = True

#public
class ResponsePublicBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {}
    should_cache = False

class ResponsePublicFullfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_cache = True

class ResponsePublicIgnore(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore public;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_cache = False

# multiple cache_control_ignore directives
class ResponsePublicIgnore2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        cache_control_ignore must-revalidate public;
        '''
    request_headers = {'Authorization': 'asd'}
    response_headers = {'Cache-control': 'public'}
    should_cache = False

#########################################################
#  Cache-Control: no-cache and private with arguments
#############
# no-cache
class ArgNoCacheBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    should_cache = False

class ArgNoCacheFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '', 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    cached_headers = {'Remove-me': None, 'Remove-me-2': '',
        'Cache-control': 'no-cache="remove-me"'}
    should_cache = True

class ArgNoCacheFulfill2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Remove-me': '"arg"', 'Remove-me-2': '"arg"',
        'Cache-control': 'no-cache="remove-me"'}
    cached_headers = {'Remove-me': None, 'Remove-me-2': '"arg"',
        'Cache-control': 'no-cache="remove-me"'}
    should_cache = True
    
class ArgNoCacheFulfill3(TestCacheControl, tester.SingleTest):
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
    should_cache = True

#############
# private
class ArgPrivateBypass(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_bypass * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    should_cache = False

class ArgPrivateFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': '',
        'Cache-control': 'private="set-cookie"'}
    should_cache = True

class ArgPrivateFulfill2(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '=',
        'Cache-control': 'private="set-cookie"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': '=',
        'Cache-control': 'private="set-cookie"'}
    should_cache = True

# erase two headers
class ArgBothNoCacheFulfill(TestCacheControl, tester.SingleTest):
    tempesta_config = '''
        cache_fulfill * *;
        '''
    response_headers = {'Set-cookie': 'some=cookie', 'remove-me-2': '"',
        'Cache-control': 'no-cache="set-cookie, Remove-me-2"'}
    cached_headers = {'Set-cookie': None, 'remove-me-2': None,
        'Cache-control': 'no-cache="set-cookie, Remove-me-2"'}
    should_cache = True
