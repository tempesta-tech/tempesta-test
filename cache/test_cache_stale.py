__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from helpers import deproxy
from helpers.deproxy import HttpMessage
from test_suite import marks, tester


class TestCacheUseStaleBase(tester.TempestaTest, base=True):
    """
    Base class for testing "cache_use_stale" configuration directive
    and "stale-if-error" cache-control parameter.
    """

    proto = "https"

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta_tmpl = {
        "config": """
listen 443 proto=%(proto)s;

srv_group default {
    server ${server_ip}:8000;
}
tls_match_any_server_name;
vhost default {
    proxy_pass default;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
}
cache 2;
cache_fulfill * *;
"""
    }

    def setUp(self):
        self.tempesta["config"] = self.tempesta_tmpl["config"] % {
            "proto": self.proto,
        }
        if self.proto == "h2":
            self.clients = [{**client, "type": "deproxy_h2"} for client in self.clients]
        tester.TempestaTest.setUp(self)

    def use_stale_base(
        self, resp_status, use_stale, resp1_headers, resp2_headers, expect_status, expect_stale
    ):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(tempesta.config.defconfig + f"cache_use_stale {use_stale};\n")
        server = self.get_server("deproxy")
        self.start_all_services(False)
        self.disable_deproxy_auto_parser()

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("cache-control", "max-age=1")] + resp1_headers,
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
                headers=[("Content-Length", "0")] + resp2_headers,
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

        resp_age = int(client.last_response.headers.get("age", -1))

        if expect_stale:
            # expect stale response
            self.assertGreaterEqual(resp_age, 3)
            self.assertEqual(client.last_response.headers.get("warning"), "110 - Response is stale")
        else:
            # expect not cached response
            self.assertEqual(resp_age, -1)


@marks.parameterize_class(
    [
        {"name": "Http", "proto": "https"},
        {"name": "H2", "proto": "h2"},
    ]
)
class TestCacheUseStaleTimeout(TestCacheUseStaleBase):
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
        self.use_stale_base(
            resp_status=302,
            use_stale="504",
            resp1_headers=[],
            resp2_headers=[],
            expect_status="200",
            expect_stale=True,
        )

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
        self.use_stale_base(
            resp_status=302,
            use_stale="500",
            resp1_headers=[],
            resp2_headers=[],
            expect_status="504",
            expect_stale=False,
        )


@marks.parameterize_class(
    [
        {"name": "Http", "proto": "https"},
        {"name": "H2", "proto": "h2"},
    ]
)
class TestCacheUseStale(TestCacheUseStaleBase):
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
        self.use_stale_base(
            resp_status=status,
            use_stale=use_stale,
            resp1_headers=[],
            resp2_headers=r2_hdrs,
            expect_status="200",
            expect_stale=True,
        )

    def test_use_fresh(self):
        """
        Send first request, this request forwarded to upstream and processed with status
        code 200, Tempesta cache it. Wait while response become stale. Send second
        request and receive response with status code 200 that NOT cached.

        This test expect non stale response, because received status code not
        specified in "cache_use_stale".
        """
        self.use_stale_base(
            resp_status="200",
            use_stale="4* 5*",
            resp1_headers=[],
            resp2_headers=[],
            expect_status="200",
            expect_stale=False,
        )

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
        self.use_stale_base(
            resp_status="400",
            use_stale="4* 5*",
            resp1_headers=r1_hdrs,
            resp2_headers=[],
            expect_status=status,
            expect_stale=False,
        )

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
        self.assertGreaterEqual(int(client.last_response.headers.get("age", -1)), 0)
        self.assertEqual(client.last_response.headers.get("warning"), "110 - Response is stale")

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
        self.assertIsNone(client.last_response.headers.get("age", None))

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
    def test_use_stale_if_error_param(self, name, req_headers, resp_headers):
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
        self.assertIsNone(client.last_response.headers.get("age", None))

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

            # expect stale response
            self.assertGreaterEqual(int(client.last_response.headers.get("age", -1)), 0)
            self.assertEqual(client.last_response.headers.get("warning"), "110 - Response is stale")

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
        self.assertIsNone(client.last_response.headers.get("age", None))

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="req",
                resp_headers=[],
                req_headers=[("cache-control", "stale-if-error=20, stale-if-error=19")],
                expected_code="200",
            ),
            marks.Param(
                name="resp",
                resp_headers=[("cache-control", "stale-if-error=20, stale-if-error=19")],
                req_headers=[],
                expected_code="502",
            ),
        ]
    )
    def test_use_stale_if_error_duplicated(self, name, req_headers, resp_headers, expected_code):
        self.disable_deproxy_auto_parser()
        server = self.get_server("deproxy")
        self.start_all_services(False)

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0")] + resp_headers,
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
            expected_code,
            3,
        )

    def test_stale_if_error_not_use_304(self):
        """
        Test ensures Tempesta doesn't return stale response with 304.
        """
        self.start_all_services()
        srv = self.get_server("deproxy")
        client = self.get_client("deproxy")

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 0\r\n"
            + "Server: Deproxy Server\r\n"
            + "Date: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "\r\n"
        )

        client.send_request(
            request=client.create_request(method="GET", uri="/page.html", headers=[]),
            expected_status_code="200",
        )

        time.sleep(2)
        client.send_request(
            request=client.create_request(
                method="GET",
                uri="/page.html",
                headers=[
                    ("If-Modified-Since", HttpMessage.date_time_string()),
                    ("Cache-control", "max-age=1, stale-if-error=10"),
                ],
            ),
            expected_status_code="200",
        )

        # Response is stale, 304 not expected
        self.assertEqual(len(srv.requests), 2, "Server has received unexpected number of requests.")

        client.send_request(
            request=client.create_request(
                method="GET",
                uri="/page.html",
                headers=[
                    ("If-Modified-Since", HttpMessage.date_time_string()),
                ],
            ),
            expected_status_code="304",
        )

        self.assertEqual(len(srv.requests), 2, "Server has received unexpected number of requests.")
