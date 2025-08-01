"""Functional tests for custom processing of cached responses."""

import abc
import copy
import time

from framework import deproxy_server
from framework.deproxy_client import DeproxyClient
from helpers import deproxy, tf_cfg
from helpers.deproxy import HttpMessage
from helpers.util import fill_template
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

TEMPESTA_CONFIG = """
cache 2;

srv_group default {
    server ${server_ip}:8000;
}
frang_limits {http_strict_host_checking false;}
vhost vh1 {
    proxy_pass default;
}

%(tempesta_config)s"""


class TestCacheControl(tester.TempestaTest, base=True):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta_template = {"config": TEMPESTA_CONFIG}

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]

    tempesta_config = """
        cache_fulfill * *;
        """

    uri = "/"
    request_headers = {}
    request_method = "GET"
    response_headers = {}
    response_status = "200"
    should_be_cached = False  # True means Tempesta Fw should make no forward the
    # request upstream and serve it from cache only.
    sleep_interval = None  # between the first and second request.
    second_request_headers = None  # When the two requests differ.
    cached_headers = None  # Reference headers to compare with actual cached response.
    # Empty if cached/second response is same as first one.
    cached_status = "200"

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def setUp(self):
        self.tempesta = copy.deepcopy(self.tempesta_template)
        self.tempesta["config"] = self.tempesta["config"] % {
            "tempesta_config": self.tempesta_config or ""
        }
        # apply default values for optional fields
        if getattr(self, "cached_headers", None) is None:
            self.cached_headers = self.response_headers
        if getattr(self, "second_request_headers", None) is None:
            self.second_request_headers = self.request_headers

        super().setUp()

    def client_send_req(self, client, headers: dict):
        req_headers = "".join(
            "{0}: {1}\r\n".format(header, header_value if header_value else "")
            for header, header_value in headers.items()
        )
        req = (
            f"{self.request_method} {self.uri} HTTP/1.1\r\n"
            + f'Host: {tf_cfg.cfg.get("Tempesta", "hostname")}\r\n'
            + f"{req_headers}\r\n"
        )
        curr_responses = len(client.responses)
        client.make_request(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses), "response lost")

        return client.last_response

    def check_response_headers(self, response):
        for name, value in self.response_headers.items():
            actual_val = response.headers.get(name, None)
            if value is None:
                self.assertIsNone(
                    actual_val,
                    "{0} header is present in the response".format(name),
                )
            else:
                self.assertIsNotNone(
                    actual_val,
                    "{0} header is missing in the response".format(name),
                )

    def check_cached_response_headers(self, response):
        for name, value in self.cached_headers.items():
            actual_val = response.headers.get(name, None)
            if value is None:
                self.assertIsNone(
                    actual_val,
                    "{0} header is present in the cached response".format(name),
                )
            else:
                self.assertIsNotNone(
                    actual_val,
                    "{0} header is missing in the cached response".format(name),
                )

    def _test(self):
        self.start_all()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        response_template = (
            "HTTP/1.1 200 OK\r\n"
            + "Server-id: deproxy\r\n"
            + "Content-Length: 0\r\n"
            + "".join(
                "{0}: {1}\r\n".format(header, "" if header_value is None else header_value)
                for header, header_value in self.response_headers.items()
            )
        )

        srv.set_response(
            response_template + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n\r\n"
        )

        response = self.client_send_req(client, self.request_headers)
        self.assertEqual(
            response.status,
            self.response_status,
            "The client's first request did not receive the expected response."
            + "The caching function cannot be checked.",
        )
        self.check_response_headers(response)

        if self.sleep_interval:
            time.sleep(self.sleep_interval)

        srv.set_response(
            response_template + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n\r\n"
        )

        cached_response = self.client_send_req(client, self.second_request_headers)
        self.assertEqual(
            cached_response.status,
            self.cached_status,
            "The client's second request did not receive the expected response."
            + "The caching function cannot be checked.",
        )
        if self.should_be_cached:
            self.assertEqual(1, len(srv.requests), "response not cached as expected")
        else:
            self.assertEqual(2, len(srv.requests), "response is cached while it should not be")
        if self.should_be_cached:
            self.check_cached_response_headers(cached_response)
        else:
            self.check_response_headers(cached_response)


class SingleTest(abc.ABC):
    """This abstract class for run one test"""

    def test(self):
        self._test()

    @abc.abstractmethod
    def _test(self):
        pass


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
    tempesta_config = """
        cache_bypass * *;
        cache_resp_hdr_del content-encoding Remove-me-2;
        """
    response_headers = {"content-encoding": "gzip", "Remove-me-2": ""}
    should_be_cached = False


class CacheHdrDelCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_resp_hdr_del content-encoding Remove-me-2;
        """
    response_headers = {"content-encoding": "gzip", "Remove-me-2": ""}
    cached_headers = {"content-encoding": None, "Remove-me-2": None}
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


class CacheHdrDelCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_resp_hdr_del content-encoding Remove-me-2;
        """
    response_headers = {"content-encoding": "gzip", "Remove-me-2": "2"}
    cached_headers = {"content-encoding": None, "Remove-me-2": None}
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


# This test does a regular caching without additional processing,
# however, the regular caching might not work correctly for
# empty 'Remove-me' header value due to a bug in message fixups (see #530).
class TestCacheBypass(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_bypass * *;
        """
    response_headers = {"Remove-me": "", "Remove-me-2": ""}
    should_be_cached = False


class TestCache(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Remove-me": "", "Remove-me-2": ""}
    should_be_cached = True


class TestCache2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Remove-me": "2", "Remove-me-2": "2"}
    should_be_cached = True


#########################################################
#  cache_control_ignore
#########
# request
# max-age
class RequestMaxAge0NoCache(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=0"}
    should_be_cached = False


class RequestMaxAge0NoCache2(TestCacheControl, SingleTest):
    second_request_headers = {"Cache-control": "max-age=0"}
    should_be_cached = False


class RequestMaxAgeNoCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=1"}
    response_headers = {"Cache-control": "max-age=3"}
    sleep_interval = 2
    should_be_cached = False


class RequestMaxAgeCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=1"}
    response_headers = {"Cache-control": "max-age=3"}
    sleep_interval = None
    should_be_cached = True


# max-age, max-stale
class RequestMaxAgeMaxStaleNotCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=5, max-stale=1"}
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 3
    should_be_cached = False


class RequestMaxAgeMaxStaleCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=3, max-stale=2"}
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 1.5
    should_be_cached = True


class RequestMaxStaleCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-stale"}
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 1.5
    should_be_cached = True


# min-fresh
class RequestMinFreshNotCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "min-fresh=2"}
    response_headers = {"Cache-control": "max-age=3"}
    sleep_interval = 2
    should_be_cached = False


class RequestMinFreshCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "min-fresh=1"}
    response_headers = {"Cache-control": "max-age=2"}
    sleep_interval = None
    should_be_cached = True


# max-age
class RequestOnlyIfCachedCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=1"}
    response_headers = {"Cache-control": "max-age=2"}
    sleep_interval = None
    second_request_headers = {"Cache-control": "max-age=1, only-if-cached"}
    cached_status = "200"
    should_be_cached = True


class RequestOnlyIfCached504(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "max-age=1"}
    response_headers = {"Cache-control": "max-age=2"}
    sleep_interval = 2.5
    second_request_headers = {"Cache-control": "max-age=1, only-if-cached"}
    cached_headers = {"Cache-control": None}
    cached_status = "504"
    should_be_cached = True


class RequestNoStoreNotCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "no-store"}
    should_be_cached = False


class RequestNoChacheNotCached(TestCacheControl, SingleTest):
    request_headers = {"Cache-control": "no-cache"}
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
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseMustRevalidateStaleNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 2
    should_be_cached = False


# RFC 7234 Sections 3.2, 4.2.4:
# "cached responses that contain the "must-revalidate" and/or
#  "s-maxage" response directives are not allowed to be served stale
#  by shared caches"
class ResponseMustRevalidateStaleCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    should_be_cached = True
    sleep_interval = None


class ResponseMustRevalidateCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = None
    should_be_cached = True


class ResponseMustRevalidateIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore must-revalidate;
        """
    # Although must-revalidate is ignored, max-age=1 remains active.
    request_headers = {}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseMustRevalidateStaleIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore must-revalidate;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 1.5
    should_be_cached = True


# proxy-revalidate
class ResponseProxyRevalidateNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {}
    response_headers = {"Cache-control": "max-age=1, proxy-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseProxyRevalidateStaleNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1, proxy-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseProxyRevalidateIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        """
    request_headers = {}
    response_headers = {"Cache-control": "max-age=1, proxy-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseStaleCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 1.5
    should_be_cached = True


class ResponseProxyRevalidateStaleIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore proxy-revalidate;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "max-age=1, proxy-revalidate"}
    sleep_interval = 2
    should_be_cached = True


# Support for "max-stale" + "max-age=1, proxy-revalidate" is questionable and
# already tested above. So we test multiple directives with a more reliable
# logic of "Authorizarion" caching.
class ResponseForAuthorizationUserMustRevalidateNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 2
    should_be_cached = False


class ResponseMustRevalidateHalfIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 1.5
    should_be_cached = True


class ResponseMustRevalidateMultiIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age must-revalidate;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "max-age=1, must-revalidate"}
    sleep_interval = 1.5
    should_be_cached = False


# max-age/s-maxage
class ResponseMaxAgeNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 2
    should_be_cached = False


class ResponseMaxAgeCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = None
    should_be_cached = True


class ResponseMaxAgeIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age;
        """
    response_headers = {"Cache-control": "max-age=1"}
    sleep_interval = 1.5
    should_be_cached = True


class ResponseSMaxageNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "s-maxage=1"}
    sleep_interval = 2
    should_be_cached = False


# s-maxage forbids serving stale responses (implies proxy-revalidate)
class ResponseSMaxageNotCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Cache-control": "max-stale=2"}
    response_headers = {"Cache-control": "s-maxage=1"}
    sleep_interval = 2
    should_be_cached = False


class ResponseSMaxageCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "s-maxage=1"}
    sleep_interval = None
    should_be_cached = True


# Authorization interacts with s-maxage, but not with max-age.
# See RFC 7234 Section 3.2.
class ResponseMaxAgeNotCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "s-maxage=0"}
    sleep_interval = None
    should_be_cached = False


class ResponseMaxAgeCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "s-maxage=1"}
    sleep_interval = None
    should_be_cached = True


class ResponseSMaxageIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore s-maxage;
        """
    response_headers = {"Cache-control": "s-maxage=1"}
    sleep_interval = 1.5
    should_be_cached = True


class ResponseSMaxageMaxAgeNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age;
        """
    response_headers = {"Cache-control": "max-age=1, s-maxage=1"}
    sleep_interval = 2
    should_be_cached = False


class ResponseSMaxageMaxAgeIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age s-maxage;
        """
    response_headers = {"Cache-control": "max-age=1, s-maxage=1"}
    sleep_interval = 1.5
    should_be_cached = True


# private/no-cache/no-store
class ResponsePrivate(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "private"}
    should_be_cached = False


class ResponseNoCache(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "no-cache"}
    should_be_cached = False


class ResponseNoStore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {"Cache-control": "no-store"}
    should_be_cached = False


class ResponseNoCacheIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore no-cache;
        """
    response_headers = {"Cache-control": "no-cache"}
    should_be_cached = True


# multiple cache_control_ignore directives
class ResponseNoCacheIgnoreMulti(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore max-age no-cache;
        """
    response_headers = {"Cache-control": "no-cache"}
    should_be_cached = True


class ResponseMultipleNoCacheIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore no-cache private no-store;
        """
    response_headers = {"Cache-control": "no-cache, private, no-store"}
    should_be_cached = True


# public directive and Authorization header
class ResponsePublicNotCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {}
    should_be_cached = False


class ResponsePublicCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "public"}
    should_be_cached = True


class ResponsePublicCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {}
    response_headers = {}
    # Interestingly enough, RFC 7234 does not forbid serving cached response for
    # subsequent requests with "Authorization" header.
    second_request_headers = {"Authorization": "asd"}
    should_be_cached = True


class ResponsePublicIgnore(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore public;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "public"}
    should_be_cached = False


# multiple cache_control_ignore directives
class ResponsePublicIgnore2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        cache_control_ignore must-revalidate public;
        """
    request_headers = {"Authorization": "asd"}
    response_headers = {"Cache-control": "public"}
    should_be_cached = False


#########################################################
#  Cache-Control: no-cache and private with arguments
#############
# no-cache
class CCArgNoCacheBypass(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_bypass * *;
        """
    response_headers = {
        "Remove-me": "",
        "Remove-me-2": "",
        "Cache-control": 'no-cache="remove-me"',
    }
    should_be_cached = False


class CCArgNoCacheCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "Remove-me": "",
        "Remove-me-2": "",
        "Cache-control": 'no-cache="remove-me"',
    }
    cached_headers = {
        "Remove-me": None,
        "Remove-me-2": "",
        "Cache-control": 'no-cache="remove-me"',
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


class CCArgNoCacheCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "Remove-me": '"arg"',
        "Remove-me-2": '"arg"',
        "Cache-control": 'no-cache="remove-me"',
    }
    cached_headers = {
        "Remove-me": None,
        "Remove-me-2": '"arg"',
        "Cache-control": 'no-cache="remove-me"',
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


class CCArgNoCacheCached3(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "Cache-Control": 'public, no-cache="content-encoding", must-revalidate, max-age=120',
        "content-encoding": "gzip",
    }
    cached_headers = {
        "Cache-Control": 'public, no-cache="content-encoding", must-revalidate, max-age=120',
        "content-encoding": None,
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


#############
# private
class CCArgPrivateBypass(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_bypass * *;
        """
    response_headers = {
        "content-encoding": "gzip",
        "remove-me-2": "",
        "Cache-control": 'private="content-encoding"',
    }
    should_be_cached = False


class CCArgPrivateCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "content-encoding": "gzip",
        "remove-me-2": "",
        "Cache-control": 'private="content-encoding"',
    }
    cached_headers = {
        "content-encoding": None,
        "remove-me-2": "",
        "Cache-control": 'private="content-encoding"',
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


class CCArgPrivateCached2(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "content-encoding": "gzip",
        "remove-me-2": "=",
        "Cache-control": 'private="content-encoding"',
    }
    cached_headers = {
        "content-encoding": None,
        "remove-me-2": "=",
        "Cache-control": 'private="content-encoding"',
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


# erase two headers
class CCArgBothNoCacheCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        """
    response_headers = {
        "content-encoding": "gzip",
        "remove-me-2": '"',
        "Cache-control": 'no-cache="content-encoding, Remove-me-2"',
    }
    cached_headers = {
        "content-encoding": None,
        "remove-me-2": None,
        "Cache-control": 'no-cache="content-encoding, Remove-me-2"',
    }
    should_be_cached = True

    def test(self):
        self.disable_deproxy_auto_parser()
        super().test()


#########################################################
#  Http chain cache action test
#########################################################
# bypass cache
class HttpChainCacheActionBypass(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        http_chain {
            cookie "foo_items_in_cart" == "*" -> cache_disable;
            cookie "comment_author_*" == "*" -> cache_disable;
            cookie "wordpress_logged_in*" == "*" -> cache_disable;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "foo_items_in_cart="}
    response_headers = {}
    should_be_cached = False


# bypass cache due to override later
class HttpChainCacheActionOverrideBypass(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        http_chain {
            cookie "foo_items_in_cart" == "*" -> cache_disable;
            cookie "comment_author_*" == "*" -> cache_disable = 0;
            cookie "wordpress_logged_in*" == "*" -> cache_disable;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "comment_author_name=john; wordpress_logged_in=true"}
    response_headers = {}
    should_be_cached = False


#  honour cache due to override later
class HttpChainCacheActionOverrideCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        http_chain {
            cookie "foo_items_in_cart" == "*" -> cache_disable;
            cookie "comment_author_*" == "*" -> cache_disable = 0;
            cookie "wordpress_logged_in*" == "*" -> cache_disable;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "foo_items_in_cart=; comment_author_name=john"}
    response_headers = {}
    should_be_cached = True


# honour cache
class HttpChainCacheActionCached(TestCacheControl, SingleTest):
    tempesta_config = """
        cache_fulfill * *;
        http_chain {
            cookie "foo_items_in_cart" == "*" -> cache_disable;
            cookie "comment_author_*" == "*" -> cache_disable = 0;
            cookie "wordpress_logged_in*" == "*" -> cache_disable;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "comment_author_name=john"}
    response_headers = {}
    should_be_cached = True


# cache_ttl related tests
class CacheTtlGlobalApplied(TestCacheControl, SingleTest):
    """
    This test ensures that global cache_ttl setting is working
    by setting it to the value above sleep interval and ensuring that
    the response had been cached.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 3;
        """
    request_headers = {}
    response_headers = {}
    sleep_interval = 2
    should_be_cached = True


# ensure that global cache_ttl is applied part 2:
#   wait for a longer period than global cache_ttl
class CacheTtlGlobalApplied2(TestCacheControl, SingleTest):
    """
    This test ensures that global cache_ttl setting is working
    by setting it to the value below sleep interval and ensuring that
    the response had not been cached.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 2;
        """
    request_headers = {}
    response_headers = {}
    sleep_interval = 3
    should_be_cached = False


class CacheTtlGlobalHonourMaxAge(TestCacheControl, SingleTest):
    """
    This test ensures that Cache-Control: max-age is preferred over
    cache_ttl directive by setting max-age above sleep_interval and
    checking that response had been cached.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 2;
        """
    request_headers = {}
    response_headers = {"Cache-Control": "max-age=10"}
    sleep_interval = 3
    should_be_cached = True


class CacheTtlGlobalHonourMaxAge2(TestCacheControl, SingleTest):
    """
    This test ensures that Cache-Control: max-age is preferred over
    cache_ttl directive by setting max-age below sleep_interval and
    checking that response had not been cached.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 10;
        """
    request_headers = {}
    response_headers = {"Cache-Control": "max-age=2"}
    sleep_interval = 3
    should_be_cached = False


class CacheTtlHttpChainOverride(TestCacheControl, SingleTest):
    """
    This test ensures cache_ttl action from HTTP tables overrides global
    cache_ttl value assuming that these two parameters are working correctly
    on their own.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 5;
        http_chain {
            cookie "comment_author_*" == "*" -> cache_ttl = 1;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "comment_author_name=john"}
    response_headers = {}
    sleep_interval = 2
    should_be_cached = False


class CacheTtlHttpChainHonourMaxAge(TestCacheControl, SingleTest):
    """
    This test ensures that cache ttl supplied by client (by max-age for example)
    takes precedence over HTTP-tables cache_ttl, assuming that
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 2;
        http_chain {
            cookie "comment_author_*" == "*" -> cache_ttl = 1;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "comment_author_name=john"}
    response_headers = {"Cache-Control": "max-age=10"}
    sleep_interval = 4
    should_be_cached = True


class CacheTtlHonourNoCache(TestCacheControl, SingleTest):
    """
    This test ensures that no-cache from upstream efficiently ignores
    both global and HTTP tables cache_ttl, assuming both these settings
    are working correctly on their own.
    """

    tempesta_config = """
        cache_fulfill * *;
        cache_ttl 10;
        http_chain {
            cookie "comment_author_*" == "*" -> cache_ttl = 10;
            -> vh1;
        }
        """
    request_headers = {"Cookie": "comment_author_name=john"}
    response_headers = {"Cache-Control": "no-cache"}
    sleep_interval = 2
    should_be_cached = False


#########################################################
# 3.2 Storing Responses to Authenticated Requests. RFC 7234
#########################################################
class StoringResponsesToAuthenticatedRequestsDefaultCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and without
    cache-control header to the same resource and check that the second one wasn't serviced
    from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False


class StoringResponsesToAuthenticatedRequestsPublicCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control: public to the same resource and check that the second one was serviced
    from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = True
    response_headers = {"Cache-control": "public"}


class StoringResponsesToAuthenticatedRequestsMustRevalidateCache2(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control must-revalidate to the same resource and check that the second one was
    serviced from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = True
    response_headers = {"Cache-control": "must-revalidate, max-age=1"}


class StoringResponsesToAuthenticatedRequestsNoCacheCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control no-cache to the same resource and check that the second one wasn't
    serviced from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False
    response_headers = {"Cache-control": "no-cache"}


class StoringResponsesToAuthenticatedRequestsNoStoreCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control no-store to the same resource and check that the second one wasn't
    serviced from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False
    response_headers = {"Cache-control": "no-store"}


class StoringResponsesToAuthenticatedRequestsNoTransformCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control no-transform to the same resource and check that the second one wasn't
    serviced from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False
    response_headers = {"Cache-control": "no-transform"}


class StoringResponsesToAuthenticatedRequestsPrivateCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control private to the same resource and check that the second one wasn't serviced
    from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False
    response_headers = {"Cache-control": "private"}


class StoringResponsesToAuthenticatedRequestsProxyRevalidateCache(TestCacheControl, SingleTest):
    """
    Response must not be cached if:
        - authorization header is present in request;
        - proxy-revalidate is present in response;
    RFC 9111 3.5

    This is analogous to must-revalidate, except that
    proxy-revalidate does not apply to private caches.
    RFC 9111 5.2.2.8
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {}
    should_be_cached = False
    sleep_interval = None
    response_headers = {"Cache-control": "proxy-revalidate"}


class StoringResponsesToAuthenticatedRequestsMaxAgeCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control max-age to the same resource and check that the second one wasn't serviced
    from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = False
    response_headers = {"Cache-control": "max-age=1"}


class StoringResponsesToAuthenticatedRequestsSMaxAgeCache(TestCacheControl, SingleTest):
    """
    This test sends two requests with different basic authentication headers and with
    cache-control s-maxage to the same resource and check that the second one was serviced
    from the cache.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    request_headers = {"Authorization": "Basic dXNlcjE6cGFzc3dvcmQx"}
    second_request_headers = {"Authorization": "Basic dXNlcjI6cGFzc3dvcmQy"}
    should_be_cached = True
    sleep_interval = None
    response_headers = {"Cache-control": "s-maxage=1"}


class StoringResponsesWithSetCookieHeaderDefaultCache(TestCacheControl, SingleTest):
    """
    Don't cache set-cookie header by security reasons. It may lead to sharing sensetive information.
    """

    tempesta_config = """
        cache_fulfill * *;
        """
    should_be_cached = True
    response_headers = {"Set-Cookie": "session=1"}
    request_headers = {}
    second_request_headers = {}
    cached_headers = {"Set-Cookie": None}


class HttpChainVhostCacheKeyStability(TestCacheControl, SingleTest):
    """
    Test that cache works correctly when HTTP chains redirect to different vhost.
    This test verifies that the cache key is based on vhost name when using HTTP chains.

    The test uses two vhosts (vh1 and vh2) that both proxy to the same backend.
    Requests to '/redirect' are routed to vh2 via HTTP chains, while other requests go to vh1.
    Both should be cached correctly, demonstrating that the cache key incorporates the vhost name.
    """

    tempesta_config = """
        cache_fulfill * *;
        
        vhost vh2 {
            proxy_pass default;
        }
        
        http_chain {
            uri == "/redirect" -> vh2;
            -> vh1;
        }
        """

    uri = "/redirect"
    request_headers = {}
    should_be_cached = True
