__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from helpers import deproxy
from test_suite import marks, tester


class TestH2CacheBase(tester.TempestaTest):
    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2;

    server ${server_ip}:8000;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;

    cache 2;
    cache_fulfill * *;
    """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]


class TestH2CacheType(TestH2CacheBase):
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy-2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def test_cache_is_shared(self):
        """Check that tempesta works as a shared cache"""
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy-1")
        client.send_request(
            client.create_request(method="GET", uri="/", headers=[]),
            "200",
        )

        time.sleep(2)

        client = self.get_client("deproxy-2")
        client.send_request(
            client.create_request(method="GET", uri="/", headers=[]),
            "200",
        )

        self.assertEqual(1, len(server.requests))


class TestH2CacheControl(TestH2CacheBase):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    def base_scenario(
        self,
        response_headers: list,
        request_headers: list,
        second_request_headers: list,
        expected_cached_status: str,
        sleep_interval: float,
        should_be_cached: bool,
    ):
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=request_headers,
            ),
            "200",
        )

        time.sleep(sleep_interval)

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=second_request_headers,
            ),
            expected_cached_status,
        )
        self.assertEqual(1 if should_be_cached else 2, len(server.requests))

    # MAX-AGE -------------------------------------------------------------------------------------
    def test_max_age_0_in_request(self):
        """Response must not be from cache if max-age=0."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "max-age=0")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_max_age_1_in_request_sleep_2(self):
        """Response must not be from cache if sleep > max-age."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "max-age=1")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_max_age_1_in_request_sleep_2_from_hpack_dynamic_table(self):
        """
        Same as previous but second cache-control header is loaded
        from hpack dynamic table.
        """
        self.base_scenario(
            response_headers=[],
            request_headers=[("cache-control", "max-age=1")],
            second_request_headers=[("cache-control", "max-age=1")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_max_age_2_in_request_sleep_0(self):
        """Response must be from cache if sleep < max-age."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "max-age=2")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_max_age_0_in_response(self):
        """Response must not be from cache if max-age=0."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=0")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_max_age_1_in_response_sleep_2(self):
        """Response must not be from cache if sleep > max-age."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_max_age_2_in_response_sleep_0(self):
        """Response must be from cache if sleep < max-age."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=2")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    # S-MAXAGE ------------------------------------------------------------------------------------
    def test_s_maxage_in_request(self):
        """s-maxage is response directive. Response must be from cache."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "s-maxage=0")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_s_maxage_0_in_response(self):
        """Response must not be from cache if s-maxage=0."""
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=0")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_s_maxage_1_in_response_sleep_2(self):
        """Response must not be from cache if sleep > s-maxage."""
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=1")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_s_maxage_2_in_response_sleep_0(self):
        """Response must be from cache if sleep < s-maxage."""
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=2")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_s_maxage_in_response_and_max_stale_in_request(self):
        """
        Response must not be from cache if:
            - max-stale is present in request;
            - sleep > s-maxage;
        The s-maxage directive also implies the semantics
        of the proxy-revalidate response directive.
        RFC 9111 5.2.2.10
        """
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_s_maxage_1_max_age_5_in_response_sleep_2(self):
        """Response must not be from cache because s-maxage overrides max-age."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=5, s-maxage=1")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    # MAX-STALE -----------------------------------------------------------------------------------
    def test_max_stale_1_in_request_sleep_3(self):
        """Response must not be from cache if sleep > max-age + max-stale."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale=1")],
            expected_cached_status="200",
            sleep_interval=3,
            should_be_cached=False,
        )

    def test_max_stale_5_in_request_sleep_2(self):
        """Response must be from cache if sleep < max-age + max-stale."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale=5")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=True,
        )

    def test_max_stale_5_in_request_sleep_2_from_dynamic_table(self):
        """
        Same as previous but second max-stale header is loaded
        from hpack dynamic table.
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[("cache-control", "max-stale=5")],
            second_request_headers=[("cache-control", "max-stale=5")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=True,
        )

    def test_max_stale_in_request_sleep_2(self):
        """Response must be from cache if request contains max-stale and age expired."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=True,
        )

    # MIN-FRESH -----------------------------------------------------------------------------------
    def test_min_fresh_2_in_request_sleep_2(self):
        """Response must not be from cache if sleep + min-fresh > max-age."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=3")],
            request_headers=[],
            second_request_headers=[("cache-control", "min-fresh=2")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_min_fresh_1_in_request_sleep_0(self):
        """Response must be from cache if sleep + min-fresh < max-age."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=2")],
            request_headers=[],
            second_request_headers=[("cache-control", "min-fresh=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_min_fresh_1_in_request_sleep_0_from_dynamic_table(self):
        """
        Same as previous but second min-fresh header is loaded
        from hpack dynamic table.
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=2")],
            request_headers=[("cache-control", "min-fresh=1")],
            second_request_headers=[("cache-control", "min-fresh=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    # ONLY-IF-CACHED ------------------------------------------------------------------------------
    def test_only_if_cached_in_request_from_cache(self):
        """Tempesta must return a 504 status code if response is not from cache."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "only-if-cached")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_only_if_cached_in_request_from_cache_from_dynamic_table(self):
        """
        Same as previous but second only-if-cache header is loaded
        from hpack dynamic table.
        """
        self.test_only_if_cached_in_request_from_cache()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[("cache-control", "only-if-cached")],
            ),
            "200",
        )
        self.assertEqual(1, len(server.requests))

    def test_only_if_cached_in_request_not_from_cache(self):
        """Tempesta must return a 504 status code if response is not from cache."""
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "only-if-cached")],
            expected_cached_status="504",
            sleep_interval=2,
            should_be_cached=True,
        )

    # NO-STORE ------------------------------------------------------------------------------------
    def test_no_store_in_first_request(self):
        """Tempesta must not cache response if no-store is present in first request."""
        self.base_scenario(
            response_headers=[],
            request_headers=[("cache-control", "no-store")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_no_store_in_first_and_second_request_from_dynamic_table(self):
        """
        Same as previous but second no-store header is loaded
        from hpack dynamic table.
        """
        self.base_scenario(
            response_headers=[],
            request_headers=[("cache-control", "no-store")],
            second_request_headers=[("cache-control", "no-store")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            "200",
        )
        self.assertEqual(3, len(server.requests))

    def test_no_store_in_second_request(self):
        """
        Response must be from cache if no-store is present in second request.

        Note that if a request containing this directive is satisfied from a cache,
        the no-store request directive does not apply to the already stored response.
        RFC 9111 5.2.1.5
        """
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "no-store")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_no_store_in_response(self):
        """Response must not be from cache if no-store is present in response."""
        self.base_scenario(
            response_headers=[("cache-control", "no-store")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    # NO-CACHE ------------------------------------------------------------------------------------
    def test_no_cache_in_first_request(self):
        """Tempesta must save response in cache if first request contains no-cache."""
        self.base_scenario(
            response_headers=[],
            request_headers=[("cache-control", "no-cache")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_no_cache_in_second_request(self):
        """Response must not be from cache if no-cache is present in request."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("cache-control", "no-cache")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_no_cache_in_response(self):
        """Tempesta must not save response in cache if response contains no-cache."""
        self.base_scenario(
            response_headers=[("cache-control", "no-cache")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    # MUST-REVALIDATE -----------------------------------------------------------------------------
    def test_must_revalidate_in_response_not_from_cache(self):
        """
        Response must not be from cache if:
            - must-revalidate is present in response;
            - sleep > max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, must-revalidate")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_must_revalidate_in_response_from_cache(self):
        """
        Response must be from cache if:
            - must-revalidate is present in response;
            - sleep < max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, must-revalidate")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_must_revalidate_in_response_max_stale_in_request_not_from_cache(self):
        """
        Response must not be from cache if:
            - must-revalidate is present in response;
            - max-stale is present in request;
            - sleep > max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, must-revalidate")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_must_revalidate_in_response_max_stale_in_request_from_cache(self):
        """
        Response must be from cache if:
            - must-revalidate is present in response;
            - max-stale is present in request;
            - sleep < max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, must-revalidate")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    # PROXY-REVALIDATE ----------------------------------------------------------------------------
    def test_proxy_revalidate_in_response_not_from_cache(self):
        """
        Response must not be from cache if:
            - must-revalidate is present in response;
            - sleep > max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, proxy-revalidate")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_proxy_revalidate_in_response_from_cache(self):
        """
        Response must be from cache if:
            - proxy-revalidate is present in response;
            - sleep < max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, proxy-revalidate")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_proxy_revalidate_in_response_max_stale_in_request_not_from_cache(self):
        """
        Response must not be from cache if:
            - proxy-revalidate is present in response;
            - max-stale is present in request;
            - sleep > max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, proxy-revalidate")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_proxy_revalidate_in_response_max_stale_in_request_from_cache(self):
        """
        Response must be from cache if:
            - proxy-revalidate is present in response;
            - max-stale is present in request;
            - sleep < max-age;
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1, proxy-revalidate")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    # PRIVATE -------------------------------------------------------------------------------------
    def test_private_in_response(self):
        """Response must not be from cache if private is present in response."""
        self.base_scenario(
            response_headers=[("cache-control", "private")],
            request_headers=[],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    # AUTHORIZATION -------------------------------------------------------------------------------
    def test_authorization_in_first_request_s_maxage_in_response(self):
        """
        Response must be cached if:
            - authorization header is present in request;
            - s-maxage is present in response;
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=1")],
            request_headers=[("authorization", "token")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_authorization_in_first_request_public_in_response(self):
        """
        Response must be cached if:
            - authorization header is present in request;
            - public is present in response;
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[("cache-control", "public")],
            request_headers=[("authorization", "token")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_authorization_in_first_request_must_revalidate_in_response(self):
        """
        Response must be cached if:
            - authorization header is present in request;
            - must-revalidate is present in response;
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[("cache-control", "must-revalidate")],
            request_headers=[("authorization", "token")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_authorization_in_first_request_proxy_revalidate_in_response(self):
        """
        Response must not be cached if:
            - authorization header is present in request;
            - proxy-revalidate is present in response;
        RFC 9111 3.5

        This is analogous to must-revalidate, except that
        proxy-revalidate does not apply to private caches.
        RFC 9111 5.2.2.8
        """
        self.base_scenario(
            response_headers=[("cache-control", "proxy-revalidate")],
            request_headers=[("authorization", "token")],
            second_request_headers=[],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_same_authorization_in_requests_max_age_in_response(self):
        """
        Response must not be cached if same authorization header is present in request.
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=5")],
            request_headers=[("authorization", "token")],
            second_request_headers=[("authorization", "token")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_same_authorization_in_requests_no_transform_in_response(self):
        """
        Response must not be cached if same authorization header is present in request.
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[("cache-control", "no_transform")],
            request_headers=[("authorization", "token")],
            second_request_headers=[("authorization", "token")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_same_authorization_in_requests(self):
        """
        Response must not be cached if same authorization header is present in request.
        RFC 9111 3.5
        """
        self.base_scenario(
            response_headers=[],
            request_headers=[("authorization", "token")],
            second_request_headers=[("authorization", "token")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_same_authorization_in_requests_from_dynamic_table(self):
        """
        Same as previous but second authorization header is loaded
        from hpack dynamic table.
        """
        self.test_same_authorization_in_requests()
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[("authorization", "token")],
            ),
            "200",
        )
        self.assertEqual(3, len(server.requests))

    def test_authorization_in_second_request(self):
        """
        RFC 9111 does not forbid serving cached response for
        subsequent requests with "Authorization" header.
        """
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[("authorization", "token")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    # COOKIE --------------------------------------------------------------------------------------
    def test_cookie_from_response_in_second_request(self):
        """
        Note that the Set-Cookie response header field [COOKIE] does not inhibit caching.
        RFC 9111 7.3
        """
        self.base_scenario(
            response_headers=[("set-cookie", "session=1")],
            request_headers=[],
            second_request_headers=[("cookie", "session=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_set_cookie_and_no_cache_in_response(self):
        """
        Note that the Set-Cookie response header field [COOKIE] does not inhibit caching.
        Servers that wish to control caching of these responses are encouraged to emit
        appropriate Cache-Control response header fields.
        RFC 9111 7.3
        """
        self.base_scenario(
            response_headers=[("set-cookie", "session=1"), ("cache-control", "no-cache")],
            request_headers=[],
            second_request_headers=[("cookie", "session=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_set_cookie_and_no_store_in_response(self):
        """
        Note that the Set-Cookie response header field [COOKIE] does not inhibit caching.
        Servers that wish to control caching of these responses are encouraged to emit
        appropriate Cache-Control response header fields.
        RFC 9111 7.3
        """
        self.base_scenario(
            response_headers=[("set-cookie", "session=1"), ("cache-control", "no-store")],
            request_headers=[],
            second_request_headers=[("cookie", "session=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_set_cookie_and_private_in_response(self):
        """
        Note that the Set-Cookie response header field [COOKIE] does not inhibit caching.
        Servers that wish to control caching of these responses are encouraged to emit
        appropriate Cache-Control response header fields.
        RFC 9111 7.3
        """
        self.base_scenario(
            response_headers=[("set-cookie", "session=1"), ("cache-control", "private")],
            request_headers=[],
            second_request_headers=[("cookie", "session=1")],
            expected_cached_status="200",
            sleep_interval=0,
            should_be_cached=False,
        )


class TestH2CacheControlIgnore(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
cache 2;
"""
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]

    def base_scenario(
        self,
        tempesta_config: str,
        response_headers: list,
        request_headers: list,
        second_request_headers: list,
        sleep_interval: float,
        should_be_cached: bool,
    ):
        tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_config
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=request_headers,
            ),
            "200",
        )

        time.sleep(sleep_interval)

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=second_request_headers,
            ),
            "200",
        )

        self.assertEqual(1 if should_be_cached else 2, len(server.requests))

    def test_ignore_must_revalidate(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore must-revalidate;\n",
            response_headers=[("cache-control", "max-age=1, must-revalidate")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            sleep_interval=2,
            should_be_cached=True,
        )

    def test_multi_ignore_private_no_cache_no_store(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore no-cache private no-store;\n",
            response_headers=[("cache-control", "no-cache, private, no-store")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_ignore_public_with_authorization(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore public;\n",
            response_headers=[("cache-control", "public")],
            request_headers=[("authorization", "token")],
            second_request_headers=[("authorization", "token")],
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_ignore_max_age_s_maxage(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore max-age s-maxage;\n",
            response_headers=[("cache-control", "max-age=1, s-maxage=1")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=2,
            should_be_cached=True,
        )

    def test_ignore_max_age_not_ignore_s_maxage(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore max-age;\n",
            response_headers=[("cache-control", "max-age=1, s-maxage=1")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_ignore_max_stale_in_request(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_control_ignore max-stale;\n",
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[("cache-control", "max-stale")],
            sleep_interval=2,
            should_be_cached=True,
        )


class TestH2CacheUseStaleBase(tester.TempestaTest, base=True):
    """
    Base class for testing "cache_use_stale" configuration directive
    and "cache-use-stale" cache-control parameter.
    """

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    proxy_pass default;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
}
cache 2;
cache_fulfill * *;
"""
    }

    def use_stale_base(
        self, resp_status, use_stale, r1_headers, r2_headers, expect_status, expect_stale
    ):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(tempesta.config.defconfig + f"cache_use_stale {use_stale};\n")
        server = self.get_server("deproxy")
        self.start_all_services(False)
        self.disable_deproxy_auto_parser()

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("cache-control", "max-age=1")] + r1_headers,
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.start()
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            "200",
            3,
        )

        # Wait while response become stale
        time.sleep(3)

        server.set_response(
            deproxy.Response.create(
                status=resp_status,
                headers=[("Content-Length", "0")] + r2_headers,
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            expect_status,
            3,
        )

        resp_age = client.last_response.headers.get("age", -1)

        if expect_stale:
            # expect stale response
            self.assertTrue(int(resp_age) >= 3)

            stale_warn = client.last_response.headers.get("warning")
            self.assertTrue(stale_warn == "110 - Response is stale")
        else:
            # expect not cached response
            self.assertTrue(resp_age == -1)


class TestH2CacheUseStaleTimeout(TestH2CacheUseStaleBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_unreliable",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    def test_use_stale_timeout(self):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request, at this time upstream is broken, it just disconnects without any
        responses. After few tries Tempesta responds to client with stale cached
        response.

        We expect stale response, because set "cache_use_stale 504", without
        this directive we would expect 504 response from Tempesta, due to forwarding
        timeout.
        """
        server = self.get_server("deproxy")
        server.hang_on_req_num = 2
        self.use_stale_base(302, "504", [], [], "200", True)

    def test_timeout_no_stale(self):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request, at this time upstream is broken, it just disconnects without any
        responses. After few tries Tempesta responds to client with 504 status code.

        Stale response is not expected.
        """
        server = self.get_server("deproxy")
        server.hang_on_req_num = 2
        self.use_stale_base(302, "500", [], [], "504", False)


class TestH2CacheUseStale(TestH2CacheUseStaleBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(name="500", status=500, use_stale="500", r2_hdrs=[]),
            marks.Param(name="400", status=400, use_stale="400", r2_hdrs=[]),
            marks.Param(name="5xx_500", status=500, use_stale="5*", r2_hdrs=[]),
            marks.Param(name="5xx_502", status=502, use_stale="5*", r2_hdrs=[]),
            marks.Param(name="4xx_400", status=400, use_stale="4*", r2_hdrs=[]),
            marks.Param(name="4xx_403", status=403, use_stale="4*", r2_hdrs=[]),
            marks.Param(name="4xx&5xx", status=404, use_stale="4* 5*", r2_hdrs=[]),
            marks.Param(
                name="invalid_response", status=403, use_stale="5*", r2_hdrs=[("hd>r", "v")]
            ),
        ]
    )
    def test_use_stale(self, name, status, use_stale, r2_hdrs):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request, if upstream responds with status-code specified in "cache_use_stale"
        directive or with response that can't be parserd Tempesta drops this response
        and respond with cached stale response.

        This test always expect stale response.
        """
        self.use_stale_base(status, use_stale, [], r2_hdrs, "200", True)

    def test_use_fresh(self):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request and receive response with status code 200 that NOT cached.

        This test expect non stale response, because received status code not
        specified in "cache_use_stale".
        """
        self.use_stale_base("200", "4* 5*", [], [], "200", False)

    @marks.Parameterize.expand(
        [
            marks.Param(name="s_maxage", status="400", r1_hdrs=[("cache-control", "s-maxage=1")]),
            marks.Param(
                name="must_revalidate", status="400", r1_hdrs=[("cache-control", "must-revalidate")]
            ),
            marks.Param(
                name="proxy_revalidate",
                status="400",
                r1_hdrs=[("cache-control", "proxy-revalidate")],
            ),
        ]
    )
    def test_use_fresh_on_error(self, name, status, r1_hdrs):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request and receive non stale response, because one of following cache-control
        parameters is present in message: s-maxage, must-revalidate, proxy-revalidate.
        """
        self.use_stale_base("400", "4* 5*", r1_hdrs, [], status, False)

    def test_max_stale(self):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request and receive stale response with status code 200. Wait while
        mas-stale will expire send another request, receive non stale response.
        """
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(tempesta.config.defconfig + f"cache_use_stale 4* 5*;\n")
        server = self.get_server("deproxy")
        self.start_all_services(False)

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("cache-control", "max-age=1")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.start()
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            "200",
            3,
        )

        # Wait while response become stale
        time.sleep(3)

        server.set_response(
            deproxy.Response.create(
                status="400",
                headers=[("Content-Length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[("cache-control", "max-stale=8")],
            ),
            "200",
            3,
        )

        resp_age = client.last_response.headers.get("age", -1)
        # expect stale response
        self.assertTrue(int(resp_age) >= 0)

        stale_warn = client.last_response.headers.get("warning")
        self.assertTrue(stale_warn == "110 - Response is stale")

        # Wait while age become greater than max-stale
        time.sleep(8)

        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[("cache-control", "max-stale=8")],
            ),
            "400",
            3,
        )

        resp_age = client.last_response.headers.get("age", -1)

        # expect non stale response
        self.assertFalse(int(resp_age) >= 0)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="req", resp_headers=[], req_headers=[("cache-control", "stale-if-error=20")]
            ),
            marks.Param(
                name="resp", resp_headers=[("cache-control", "stale-if-error=20")], req_headers=[]
            ),
        ]
    )
    def test_use_stale_if_error_derective(self, name, req_headers, resp_headers):
        """
        In this tests we don't use "cache_use_stale" configuration directive.
        Here we test "stale-if-error" cache-control parameter. See RFC 5861.

        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request and receive non stale response with status code 200, because upstream
        server responds with 200 status code. Send few request, upstream responds
        with "500", "502", "503", "504" status-codes, therefore Tempesta responds
        with 200 stale responses from cache, because stale-if-error is specified
        and time is not expired. Wait while time specified in stale-if-eror will
        expire, send another request receive non stale response with 504 status code.
        """
        resp_codes = ["500", "502", "503", "504"]
        server = self.get_server("deproxy")
        self.start_all_services(False)
        self.disable_deproxy_auto_parser()

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("cache-control", "max-age=1")] + resp_headers,
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.start()
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=req_headers,
            ),
            "200",
            3,
        )

        # Wait while response become stale
        time.sleep(3)

        # Stale-if-error must be ignored, no error occured
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=req_headers,
            ),
            "200",
            3,
        )

        # expect non stale
        resp_age = int(client.last_response.headers.get("age", -1))
        self.assertTrue(resp_age == -1)

        for status in resp_codes:
            server.set_response(
                deproxy.Response.create(
                    status=status,
                    headers=[("Content-Length", "0")] + resp_headers,
                    date=deproxy.HttpMessage.date_time_string(),
                )
            )

            client.send_request(
                client.create_request(
                    method="GET",
                    uri="/",
                    headers=req_headers,
                ),
                "200",
                3,
            )

            resp_age = int(client.last_response.headers.get("age", -1))
            # expect stale response
            self.assertTrue(resp_age >= 0)

            stale_warn = client.last_response.headers.get("warning")
            self.assertTrue(stale_warn == "110 - Response is stale")

        # wait more than stale-if-error time
        time.sleep(21)

        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=req_headers,
            ),
            "504",
            3,
        )

        # expect non stale response
        resp_age = int(client.last_response.headers.get("age", -1))
        self.assertTrue(resp_age == -1)
