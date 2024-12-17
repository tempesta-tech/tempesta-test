"""
Tests for correct parsing of some parts of http2 messages, such as headers.
For now tests run curl as external program capable to generate h2 messages and
analises its return code.
"""

import string

from h2.errors import ErrorCodes
from hpack import HeaderTuple
from hyperframe import frame

from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        location / {
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}
%s
"""

TEMPESTA_DEPROXY_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}
%s
"""

DEPROXY_CLIENT_HTTP = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}


class HeadersParsing(H2Base):
    def test_small_header_in_request(self):
        """Request with small header name length completes successfully."""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        for length in range(1, 5):
            header = "x" * length
            client.send_request(
                self.get_request + [(header, "test")],
                "200",
            )

    def test_transfer_encoding_header_in_request(self):
        """
        The only exception to this is the TE header field, which MAY be present in an HTTP/2
        request; when it is, it MUST NOT contain any value other than "trailers".
        RFC 9113 8.2.2
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            (
                self.post_request + [("transfer-encoding", "chunked")],
                "123",
            ),
            "400",
        )

    def test_long_header_name_in_request(self):
        """Max length for header name - 1024. See fw/http_parser.c HTTP_MAX_HDR_NAME_LEN"""
        for length, status_code in ((1023, "200"), (1024, "200"), (1025, "400")):
            with self.subTest(length=length, status_code=status_code):
                self.start_all_services()

                client = self.get_client("deproxy")
                client.send_request(self.post_request + [("a" * length, "text")], status_code)

    def test_long_header_name_in_response(self):
        """Max length for header name - 1024. See fw/http_parser.c HTTP_MAX_HDR_NAME_LEN"""
        for length, status_code in ((1023, "200"), (1024, "200"), (1025, "502")):
            with self.subTest(length=length, status_code=status_code):
                self.start_all_services()

                client = self.get_client("deproxy")
                server = self.get_server("deproxy")
                server.set_response(
                    "HTTP/1.1 200 OK\r\n"
                    + f"Date: {HttpMessage.date_time_string()}\r\n"
                    + "Server: debian\r\n"
                    + f"{'a' * length}: text\r\n"
                    + "Content-Length: 0\r\n\r\n"
                )
                client.send_request(self.post_request, status_code)


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT_HTTP]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class CookieParsing(tester.TempestaTest):
    cookie = {"name": "cname", "value": "123456789"}

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

server ${server_ip}:8000;

block_action attack reply;

sticky {
    cookie enforce;
}
"""
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="single_cookie", cookies="{0}", expected_status_code="200"),
            marks.Param(
                name="many_cookie_first",
                cookies="{0}; cookie1=value1; cookie2=value2",
                expected_status_code="200",
            ),
            marks.Param(
                name="many_cookie_last",
                cookies="cookie1=value1; cookie2=value2; {0}",
                expected_status_code="200",
            ),
            marks.Param(
                name="many_cookie_between",
                cookies="cookie1=value1; {0}; cookie2=value2",
                expected_status_code="200",
            ),
            marks.Param(name="duplicate_cookie", cookies="{0}; {0}", expected_status_code="500"),
            marks.Param(
                name="many_cookie_and_name_as_substring_other_name_1",
                cookies="cookie1__tfw=value1; {0}",
                expected_status_code="200",
            ),
            marks.Param(
                name="many_cookie_and_name_as_substring_other_name_2",
                cookies="__tfwcookie1=value1; {0}",
                expected_status_code="200",
            ),
            marks.Param(
                name="many_cookie_and_name_as_substring_other_value_1",
                cookies="cookie1=value1__tfw; {0}",
                expected_status_code="200",
            ),
            marks.Param(
                name="many_cookie_and_name_as_substring_other_value_2",
                cookies="cookie1=__tfwvalue1; {0}",
                expected_status_code="200",
            ),
        ]
    )
    def test(self, name, cookies, expected_status_code):
        self.start_all_services()

        client = self.get_client("deproxy")

        client.send_request(client.create_request("GET", []), "302")
        # get a sticky cookie from a response headers
        tfw_cookie = client.last_response.headers.get("set-cookie").split("; ")[0].split("=")

        sticky_cookie = f"{tfw_cookie[0]}={tfw_cookie[1]}"
        for _ in range(2):  # first as string and second as bytes from dynamic table
            client.send_request(
                request=client.create_request(
                    method="GET",
                    headers=[("cookie", cookies.format(sticky_cookie))],
                ),
                expected_status_code=expected_status_code,
            )
            if expected_status_code != "200":
                self.assertTrue(client.wait_for_connection_close())
                break


class DuplicateSingularHeader(H2Base):
    def test_two_header_as_bytes_from_dynamic_table(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save "referer" header into dynamic table
        client.send_request(self.get_request + [("referer", "test1")], "200")
        # send two "referer" headers as bytes (\xbe, 62 index) from dynamic table
        client.send_request(self.get_request + [("referer", "test1"), ("referer", "test1")], "400")

    def test_header_as_string_value(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save "referer" header into dynamic table
        client.send_request(self.get_request + [("referer", "test1")], "200")

        client.h2_connection.send_headers(stream_id=3, headers=self.get_request, end_stream=True)
        client.methods.append("GET")
        # send two "referer" headers:
        # first as byte (\xbe, 62 index) from dynamic table
        # second as string value
        client.send_bytes(
            data=b"\x00\x00\x14\x01\x05\x00\x00\x00\x03\xbf\x84\x87\x82\xbe@\x07referer\x05test1",
            expect_response=True,
        )
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "400")

    def test_header_from_static_table_and_dynamic_table(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save two "referer" header:
        # first as byte from static table (key) and value as string
        # second as byte from dynamic table
        client.send_request(self.get_request + [("referer", "test1"), ("referer", "test1")], "400")


class TestPseudoHeaders(H2Base):
    def test_invalid_pseudo_header(self):
        """
        Endpoints MUST NOT generate pseudo-header fields other than those defined in this document.
        RFC 9113 8.3
        """
        self.__test(self.post_request + [(":content-length", "0")])

    def test_duplicate_pseudo_header(self):
        """
        The same pseudo-header field name MUST NOT appear more than once in a field block.
        A field block for an HTTP request or response that contains a repeated pseudo-header
        field name MUST be treated as malformed.
        RFC 9113 8.3
        """
        self.__test(self.post_request + [(":path", "/")])

    def test_status_header_in_request(self):
        """
        Pseudo-header fields defined for responses MUST NOT appear in requests.
        RFC 9113 8.3
        """
        self.__test(self.post_request + [(":status", "200")])

    def test_regular_header_before_pseudo_header(self):
        """
        All pseudo-header fields MUST appear in a field block before all regular field lines.
        RFC 9113 8.3
        """
        self.__test(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                ("content-length", "0"),
                (":method", "POST"),
            ]
        )

    def test_authority_with_scheme_and_path(self):
        """
        ":authority" MUST NOT include the deprecated userinfo subcomponent for "http"
        or "https" schemed URIs.
        RFC 9113 8.3.1
        """
        self.__test(
            [
                (":path", "/"),
                (":scheme", "https"),
                (":method", "POST"),
                (":authority", "https://example.com/index.html"),
            ]
        )

    def test_without_path_header(self):
        """
        All HTTP/2 requests MUST include exactly one valid value for the ":method",
        ":scheme", and ":path" pseudo-header fields, unless they are CONNECT
        requests. An HTTP request that omits mandatory pseudo-header fields is malformed.
        RFC 9113 8.3.1
        """
        self.__test(
            [
                (":authority", "example.com"),
                (":scheme", "https"),
                (":method", "POST"),
            ]
        )

    def test_without_scheme_header(self):
        """
        All HTTP/2 requests MUST include exactly one valid value for the ":method",
        ":scheme", and ":path" pseudo-header fields, unless they are CONNECT
        requests. An HTTP request that omits mandatory pseudo-header fields is malformed.
        RFC 9113 8.3.1
        """
        self.__test(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":method", "POST"),
            ]
        )

    def test_without_method_header(self):
        """
        All HTTP/2 requests MUST include exactly one valid value for the ":method",
        ":scheme", and ":path" pseudo-header fields, unless they are CONNECT
        requests. An HTTP request that omits mandatory pseudo-header fields is malformed.
        RFC 9113 8.3.1
        """
        self.__test(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
            ]
        )

    def test_connect_method_with_path_and_scheme(self):
        """
        The ":scheme" and ":path" pseudo-header fields MUST be omitted.
        A CONNECT request that does not conform to these restrictions is malformed.
        RFC 9113 8.5
        """
        self.__test(
            [
                (":method", "CONNECT"),
                (":authority", "www.example.com:443"),
                (":path", "/"),
                (":scheme", "https"),
            ]
        )

    def __test(self, request: list):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request,
            "400",
        )

        self.assertTrue(client.wait_for_connection_close())


class TestConnectionHeaders(H2Base):
    def __test_request(self, header: tuple):
        """
        An endpoint MUST NOT generate an HTTP/2 message containing connection-specific
        header fields. Any message containing connection-specific header fields MUST be treated
        as malformed.
        RFC 9113 8.2.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(self.post_request + [header], "400")
        self.assertTrue(client.wait_for_connection_close())

    def __test_response(self, header: tuple):
        """
        An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific
        header fields or their messages will be treated by other HTTP/2 endpoints as malformed.
        RFC 9113 8.2.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.parsing = False

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0].capitalize()}: {header[1]}\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        header = (header[0].lower(), header[1])
        client.send_request(self.post_request, "200")
        self.assertNotIn(header, client.last_response.headers.headers)

    def test_TE_header_in_request(self):
        self.__test_request(header=("te", "gzip"))

    def test_connection_header_in_request(self):
        self.__test_request(header=("connection", "keep-alive"))

    def test_keep_alive_header_in_request(self):
        self.__test_request(header=("keep-alive", "timeout=5, max=10"))

    def test_proxy_connection_header_in_request(self):
        self.__test_request(header=("proxy-connection", "keep-alive"))

    def test_upgrade_header_in_request(self):
        self.__test_request(header=("upgrade", "websocket"))

    def test_connection_header_in_response(self):
        self.__test_response(header=("connection", "keep-alive"))

    def test_keep_alive_header_in_response(self):
        self.__test_response(header=("keep-alive", "timeout=5, max=10"))

    def test_proxy_connection_header_in_response(self):
        self.__test_response(header=("proxy-connection", "keep-alive"))

    def test_upgrade_header_in_response(self):
        self.__test_response(header=("upgrade", "websocket"))

    def test_TE_header_in_response(self):
        self.__test_response(header=("te", "gzip"))


class TestSplitCookies(H2Base):
    """
    Ensure that multiple cookie headers values are merged
    into single header when proxying to backend
    """

    def test_split_cookies(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        cookies = {"foo": "bar", "bar": "baz"}
        client.send_request(
            self.get_request + [("cookie", f"{name}={val}") for name, val in cookies.items()], "200"
        )

        cookie_hdrs = list(self.get_server("deproxy").last_request.headers.find_all("cookie"))
        self.assertEqual(len(cookie_hdrs), 1, "Cookie headers are not merged together")

        received_cookies = {}
        for val in cookie_hdrs[0].split("; "):
            cookie = val.split("=")
            received_cookies[cookie[0]] = cookie[1]
        self.assertEqual(cookies, received_cookies, "Sent and received cookies are not equal")


class TestH2Host(H2Base):
    def test_host_missing(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            expected_status_code="400",
        )

    def test_empty_authority_header(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[(":path", "/"), (":scheme", "https"), (":method", "GET"), (":authority", "")],
            expected_status_code="400",
        )

    def test_empty_host_header(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[(":path", "/"), (":scheme", "https"), (":method", "GET"), ("host", "")],
            expected_status_code="400",
        )

    def test_host_authority_ok(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_host_header_ok(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_different_host_and_authority_headers(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "deproxy"),
                ("host", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_forwarded_and_empty_host_header(self):
        """Host header must be present. Forwarded header does not set host header."""
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", ""),
                ("forwarded", "host=localhost"),
            ],
            expected_status_code="400",
        )


class TestTrailers(H2Base):
    request = [
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
        (":authority", "localhost"),
    ]

    def __create_connection_and_get_client(self):
        self.start_all_services()

        client = self.get_client("deproxy")
        self.initiate_h2_connection(client)

        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        return client

    def __send_headers_and_data_frames(self, client, headers=None):
        # create and send HEADERS frame without END_STREAM and with END_HEADERS
        hf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(headers or self.request),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=False)

        # create and send DATA frame without END_STREAM
        df = frame.DataFrame(stream_id=client.stream_id, data=b"asd")
        client.send_bytes(data=df.serialize(), expect_response=False)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="trailer",
                tr1="x-token1",
                tr1_val="value1",
                tr1_expected=True,
                tr2="x-token2",
                tr2_val="value2",
                tr2_expected=True,
            ),
            marks.Param(
                name="trailer_with_hbp",
                tr1="proxy-authenticate",
                tr1_val="negotiate token68",
                tr1_expected=False,
                tr2="proxy-authenticate",
                tr2_val="negotiate token69",
                tr2_expected=False,
            ),
            marks.Param(
                name="trailer_mix",
                tr1="x-token1",
                tr1_val="value1",
                tr1_expected=True,
                tr2="proxy-authenticate",
                tr2_val="negotiate token68",
                tr2_expected=False,
            ),
        ]
    )
    def test_trailers_in_request(
        self, name, tr1, tr1_val, tr1_expected, tr2, tr2_val, tr2_expected
    ):
        """Send trailers after DATA frame and receive a 200 response."""
        client = self.__create_connection_and_get_client()
        server = self.get_server("deproxy")
        self.__send_headers_and_data_frames(client)

        # create and send trailers into HEADERS frame with END_STREAM and END_HEADERS
        tf1 = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([(tr1, tr1_val), (tr2, tr2_val)]),
            flags=["END_STREAM", "END_HEADERS"],
        )
        client.send_bytes(data=tf1.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual("200", client.last_response.status, "HTTP response code missmatch.")
        if tr1_expected:
            self.assertIn(tr1, server.last_request.headers)
        else:
            self.assertNotIn(tr1, server.last_request.headers)

        if tr2_expected:
            self.assertIn(tr2, server.last_request.headers)
        else:
            self.assertNotIn(tr2, server.last_request.headers)

    def test_trailers_invalid_header_in_request(self):
        """
        A sender MUST NOT generate a trailer that contains a field necessary
        for message framing (e.g., Transfer-Encoding and Content-Length),
        routing (e.g., Host), request modifiers (e.g., controls and
        conditionals in Section 5 of [RFC7231]), authentication (e.g., see
        [RFC7235] and [RFC6265]), response control data (e.g., see Section
        7.1 of [RFC7231]), or determining how to process the payload (e.g.,
        Content-Encoding, Content-Type, Content-Range, and Trailer).
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy")
        for header in [
            ("accept", "*/*"),
            ("authorization", "Basic QWEasdzxc"),
            ("cache-control", "no-cache"),
            ("content-encoding", "gzip"),
            ("content-length", "3"),
            ("content-type", "text/html"),
            ("cookie", "session_id=123"),
            ("if-none-match", '"qweasd"'),
            ("host", "localhost"),
            ("if-modified-since", "Mon, 12 Dec 2016 13:59:39 GMT"),
            ("referer", "/other-page/"),
            ("user-agent", "Mozilla/5.0 (Windows NT 6.1;) Gecko/20100101 Firefox/47.0"),
        ]:
            with self.subTest(msg=f"The request with trailer - `{header[0]}: {header[1]}`"):
                client.restart()
                self.initiate_h2_connection(client)
                client.init_stream_for_send(1)
                self.__send_headers_and_data_frames(client)

                # create and send trailers into HEADERS frame with END_STREAM and END_HEADERS
                tf = frame.HeadersFrame(
                    stream_id=client.stream_id,
                    data=client.h2_connection.encoder.encode([(header[0], header[1])]),
                    flags=["END_STREAM", "END_HEADERS"],
                )
                client.send_bytes(data=tf.serialize(), expect_response=True)

                self.assertTrue(client.wait_for_response())
                self.assertEqual("403", client.last_response.status)
                self.assertTrue(client.wait_for_connection_close())

    def test_trailers_with_continuation_frame_in_request(self):
        """
        Send trailers (HEADER and CONTINUATION frames) after DATA frame and receive a 200 response.
        """
        client = self.__create_connection_and_get_client()
        self.__send_headers_and_data_frames(client)

        # create and send trailers into HEADERS frame with END_STREAM and not END_HEADERS
        tf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("hdr", "val")]),
            flags=["END_STREAM"],
        )

        client.send_bytes(data=tf.serialize(), expect_response=False)

        # create and send CONTINUATION frame with trailers
        cf = frame.ContinuationFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("x-my-hdr", "text")]),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=cf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual("200", client.last_response.status, "HTTP response code missmatch.")

    @marks.Parameterize.expand(
        [
            marks.Param(name="end_headers", flags=["END_HEADERS"]),
            marks.Param(name="no_end_headers", flags=[]),
        ]
    )
    def test_trailers_with_empty_continuation_frame_in_request(self, name, flags):
        """
        Send trailers (HEADER and empty CONTINUATION frames) after DATA
        frame and receive a 200 response in case when CONTINUATION has
        END_HEADERS flag and GO_AWAY protocol error otherwise.
        """
        client = self.__create_connection_and_get_client()
        self.__send_headers_and_data_frames(client)

        # create and send trailers into HEADERS frame with END_STREAM and not END_HEADERS
        tf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("hdr1", "val")]),
            flags=["END_STREAM"],
        )

        client.send_bytes(data=tf.serialize(), expect_response=False)

        # create and send empty CONTINUATION frame in trailer
        cf = frame.ContinuationFrame(stream_id=client.stream_id, flags=flags)

        # response expected when end_headers is set.
        expected_response = flags == ["END_HEADERS"]
        client.send_bytes(data=cf.serialize(), expect_response=expected_response)

        if expected_response:
            self.assertTrue(client.wait_for_response())
            self.assertEqual("200", client.last_response.status, "HTTP response code missmatch.")
        else:
            self.assertTrue(client.wait_for_connection_close(timeout=5))
            self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_trailers_with_pseudo_headers_in_request(self):
        """
        Trailers MUST NOT include pseudo-header fields.
        RFC 9113 8.1
        """
        client = self.__create_connection_and_get_client()
        self.__send_headers_and_data_frames(
            client, [(":path", "/"), (":authority", "localhost"), (":method", "POST")]
        )

        # create and send trailers into HEADERS frame with END_STREAM and END_HEADERS
        tf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([(":scheme", "https")]),
            flags=["END_STREAM", "END_HEADERS"],
        )
        client.send_bytes(data=tf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual("403", client.last_response.status, "HTTP response code missmatch.")

    def test_trailers_without_end_stream_in_request(self):
        """
        An endpoint that receives a HEADERS frame without the END_STREAM flag set after
        receiving the HEADERS frame that opens a request or after receiving a final
        (non-informational) status code MUST treat the corresponding request or response
        as malformed.
        RFC 9113 8.1
        """
        client = self.__create_connection_and_get_client()
        self.__send_headers_and_data_frames(client)

        # create and send trailers into HEADERS frame with END_STREAM and END_HEADERS
        tf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("host", "localhost")]),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=tf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual("400", client.last_response.status, "HTTP response code missmatch.")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "0\r\n"
                + "X-Token: value\r\n\r\n",
            ),
            marks.Param(
                name="not_empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + "X-Token: value\r\n\r\n",
            ),
        ]
    )
    def test_trailers_in_response(self, name, response):
        self.start_all_services()
        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        client.send_request(self.get_request, "200")
        self.assertIsNone(client.last_response.headers.get("Trailer"))
        self.assertIsNone(client.last_response.headers.get("X-Token"))
        self.assertFalse(client.last_response.headers.get("Transfer-Encoding"), "chunked")
        self.assertIsNotNone(client.last_response.trailer.get("X-Token"))


class CurlTestBase(tester.TempestaTest):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-kfv "
                " --resolve tempesta-tech.com:443:${tempesta_ip} https://tempesta-tech.com/ "
            ),
        },
    ]

    def run_test(self, served_from_cache=False):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        nginx = self.get_server("nginx")
        nginx.get_stats()
        self.assertEqual(
            1 if served_from_cache else 2,
            nginx.requests,
            msg="Unexpected number forwarded requests to backend",
        )

    def run_deproxy_test(self, served_from_cache=False):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        srv = self.get_server("deproxy")
        self.assertEqual(
            1 if served_from_cache else 2,
            len(srv.requests),
            msg="Unexpected number forwarded requests to backend",
        )


class AddBackendShortHeaders(CurlTestBase):
    """The test checks the correctness of forwarding short headers with
    duplication in mixed order: put header B between two headers A
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data1 "q";
add_header x-extra-data2 "q";
add_header x-extra-data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class BackendSetCoookieH2(tester.TempestaTest):
    """
    This is a H2 version of BackendSetCoookie test case
    Put special headers with same Set-Cookie name
    """

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-kfv "
                " --resolve tempesta-tech.com:443:${tempesta_ip} https://tempesta-tech.com/"  # Set non-null return code on 4xx-5xx responses.
            ),
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header Set-Cookie "wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-content/plugins; HttpOnly";
add_header Set-Cookie "wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-admin; HttpOnly";
add_header Set-Cookie "wordpress_logged_in_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7Cd20c220a6974e7c1bdad6eb90b19b37986bbb06ada7bff996b55d0269c077c90; path=/; HttpOnly";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self, served_from_cache=True):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.wait_while_busy(curl)
        self.assertEqual(
            0, curl.returncode, msg=("Curl return code is not 0 (%d)." % (curl.returncode))
        )
        curl.stop()

        self.start_all_clients()
        self.wait_while_busy(curl)
        self.assertEqual(
            0, curl.returncode, msg=("Curl return code is not 0 (%d)." % (curl.returncode))
        )

        nginx = self.get_server("nginx")
        nginx.get_stats()
        self.assertEqual(
            1 if served_from_cache else 2,
            nginx.requests,
            msg="Unexpected number forwarded requests to backend",
        )
        setcookie_count = 0
        lines = curl.proc_results[1].decode("utf-8").split("\n")
        for line in lines:
            if line.startswith("< set-cookie:"):
                setcookie_count += 1
                self.assertTrue(len(line.split(",")) == 1, "Wrong separator")
        self.assertTrue(setcookie_count == 3, "Set-Cookie headers quantity mismatch")


class AddBackendShortHeadersCache(CurlTestBase):
    """The test checks the correctness of serving short headers with duplicate
    (in mixed order: put header B between two headers A) from the cache
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data1 "q";
add_header x-extra-data2 "q";
add_header x-extra-data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


class AddBackendLongHeaders(CurlTestBase):
    """The test checks the correctness of forwarding long headers with
    duplication in mixed order: put header B between two headers A
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data2 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class AddBackendLongHeadersCache(CurlTestBase):
    """The test checks the correctness of serving long headers with duplicate
    (in mixed order: put header B between two headers A) from the cache
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data2 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


class LowercaseAddBackendHeaders(CurlTestBase):
    """Test on converting header names to lowercase when converting a forwarded
    response to h2. If the conversion fails, curl will not return 0 and the test
    will fail.
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header X-Extra-Data1 "q";
add_header X-Extra-Data2 "q";
add_header X-Extra-Data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class LowercaseAddBackendHeadersCache(CurlTestBase):
    """Test on converting header names to lowercase if response is served by
    cache. If the conversion fails, curl will not return 0 and the test will
    fail.
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header X-Extra-Data1 "q";
add_header X-Extra-Data2 "q";
add_header X-Extra-Data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


def deproxy_backend_config(headers):
    return {
        "id": "deproxy",
        "type": "deproxy",
        "port": "8000",
        "response": "static",
        "response_content": headers,
    }


class HeadersEmptyCache(CurlTestBase):
    """Empty headers in responses might lead to kernel panic
    (see tempesta issue #1549).
    """

    backends = [
        deproxy_backend_config(
            "HTTP/1.1 200 OK\r\n"
            "Server-id: deproxy\r\n"
            "Content-Length: 0\r\n"
            "Pragma:\r\n"
            "Empty-header:\r\n"
            "X-Extra-Data:\r\n\r\n"
        )
    ]

    tempesta = {
        "config": TEMPESTA_DEPROXY_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_deproxy_test(self, served_from_cache=True)


class HeadersSpacedCache(CurlTestBase):
    """Same as EmptyHeadersCache, but with spaces as header values."""

    backends = [
        deproxy_backend_config(
            "HTTP/1.1 200 OK\r\n"
            "Server-id: deproxy\r\n"
            "Content-Length: 0\r\n"
            "Pragma: \r\n"
            "Empty-header: \r\n"
            "X-Extra-Data: \r\n\r\n"
        )
    ]

    tempesta = {
        "config": TEMPESTA_DEPROXY_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_deproxy_test(self, served_from_cache=True)


class MissingDateServerWithBodyTest(tester.TempestaTest):
    """
    Test response without Date and Server headers, but with short body.
    This test need to verify transforming of HTTP/1 responses to HTTP/2
    which doesn't have Date and Server headers but has a body. At forwarding
    response stage tempesta adds its Server and Date and we need to ensure
    this passed correctly. Exist tests uses nginx to respond to HTTP2,
    but nginx returns Server and Date by default. Also, in most tests body
    not present in response.
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n" "1",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        },
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;

        tls_match_any_server_name;

        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.start_all()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(head)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp)
        self.assertEqual(deproxy_cl.last_response.status, "200")


LARGE_CONTENT_LENGTH = 1024 * 8


class MissingDateServerWithLargeBodyTest(MissingDateServerWithBodyTest):
    """
    Same as `MissingDateServerWithBodyTest`, but with a larger body.
    Can cause panic, see Tempesta issue #1704
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Length: {LARGE_CONTENT_LENGTH}\r\n"
                "\r\n"
                f"{'1' * LARGE_CONTENT_LENGTH}"
            ),
        },
    ]


class TestHeadersBlockedByMaxHeaderListSize(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n" "1",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        },
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            server ${server_ip}:8000;

            http_max_header_list_size 250;

            block_action attack reply;
            block_action error reply;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            tls_match_any_server_name;
        """
    }

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_blocked_by_max_headers_count(self, name, huffman):
        """
        Total header length is 251 bytes, greater then 250.
        :method" "GET" (10 + 32 extra byte according RFC)
        ":path" "/" (6 + 32)
        ":scheme" "https" (12 + 32)
        ":authority" "localhost" (19 + 32)
        "a" "a" * 43
        """
        self.start_all_services()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(
            deproxy_cl.create_request(method="GET", headers=[("a", "a" * 43)], huffman=huffman)
        )

        deproxy_cl.wait_for_response(strict=True)
        self.assertEqual(deproxy_cl.last_response.status, "403")

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_not_blocked_by_max_headers_count(self, name, huffman):
        """
        Total header length is 250 bytes, not greater then 250.
        :method" "GET" (10 + 32 extra byte according RFC)
        ":path" "/" (6 + 32)
        ":scheme" "https" (12 + 32)
        ":authority" "localhost" (19 + 32)
        "a" "a" * 42
        """
        self.start_all_services()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(
            deproxy_cl.create_request(method="GET", headers=[("a", "a" * 42)], huffman=huffman)
        )

        deproxy_cl.wait_for_response(strict=True)
        self.assertEqual(deproxy_cl.last_response.status, "200")


class CustomTemplate(string.Template):
    delimiter = "&"


@marks.parameterize_class(
    [
        {"name": "MethodHEAD", "method": "HEAD", "statuses": [200]},
        {"name": "MethodGET", "method": "GET", "statuses": [200, 302, 304, 400, 401, 404, 500]},
        {
            "name": "MethodPOST",
            "method": "POST",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodDELETE",
            "method": "DELETE",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodPATCH",
            "method": "PATCH",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodPUT",
            "method": "PUT",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
    ]
)
class TestNoContentLengthInMethod(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=https,h2;
            access_log dmesg;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    method: str = None
    statuses: list[int] = None

    @property
    def statuses_description(self) -> dict[int, str]:
        return {
            200: "OK",
            201: "Created",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }

    def test_request_success(self):
        self.start_all_services()
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy")
        client.start()

        for status in self.statuses:
            with self.subTest(status=status):
                server.set_response(
                    f"HTTP/1.1 {status} {self.statuses_description[status]}\r\n"
                    "Server: debian\r\n"
                    "Content-Length: 0\r\n\r\n\r\n"
                )
                client.send_request(
                    request=client.create_request(method=self.method, headers=[]),
                    expected_status_code=str(status),
                )

                self.assertEqual(
                    client.last_response.headers["content-length"],
                    "0",
                    msg=f"Tempesta should proxy the Content-Length header for the "
                    f"`{self.method} {status} {self.statuses_description[status]}` status code also",
                )


@marks.parameterize_class(
    [
        {
            "name": "POST",
            "method": "POST",
        },
        {
            "name": "PUT",
            "method": "PUT",
        },
        {
            "name": "PATCH",
            "method": "PATCH",
        },
        {
            "name": "DELETE",
            "method": "DELETE",
        },
    ]
)
class TestContentTypeWithEmptyBody(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: debian\r\n"
                "Content-Length: 0\r\n"
                "Content-Type: text/html; charset=utf-8\r\n\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=https,h2;
            access_log dmesg;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    method: str = None

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method=self.method, headers=[]),
            expected_status_code="200",
        )
        self.assertEqual(
            client.last_response.headers["content-type"],
            "text/html; charset=utf-8",
            msg="Tempesta should proxy the Content-Type header for the CRUD method with empty body also",
        )
