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
    def test_set_cookie_no_cached(self):
        """
        Don't cache set-cookie header by security reasons. It may lead to sharing sensetive
        information.
        """
        self.start_all_services()
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("set-cookie", "session=1")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                headers=[],
                uri="/",
            ),
            "200",
        )

        client.send_request(
            client.create_request(
                method="GET",
                headers=[],
                uri="/",
            ),
            "200",
        )

        self.assertEqual(2, len(client.responses))
        self.assertEqual(1, len(server.requests))
        self.assertIsNone(client.last_response.headers.get("set-cookie"))


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
