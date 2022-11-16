import string

from framework import tester
from helpers import deproxy

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


DATE = deproxy.HttpMessage.date_time_string()
CHUNK_SIZE = 16
BODY_PAYLOAD = string.ascii_letters


class CommonUtils:
    def start_all(self):
        srv = self.get_server("backend")
        srv.keep_alive = 1
        srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(1))

    def send_req(self, client, request=None):
        request = (
            (
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Accept-Encoding: gzip, br, chunked\r\n"
                "\r\n"
            )
            if not request
            else request
        )
        client.make_requests(request)
        got_response = client.wait_for_response(timeout=5)
        return got_response

    def encode_chunked(self, data, chunk_size=256):
        result = ""
        while len(data):
            chunk, data = data[:chunk_size], data[chunk_size:]
            result += f"{hex(len(chunk))[2:]}\r\n"
            result += f"{chunk}\r\n"
        return result + "0\r\n\r\n"

    def decode_chunked(self, data):
        data = data.split("\r\n")
        data = [(int(length, base=16), chunk) for length, chunk in zip(data[::2], data[1::2])]
        result = ""
        for length, chunk in data:
            if not length:
                return result
            result += chunk[:length]


class TestH2BodyDechunking(tester.TempestaTest, CommonUtils):
    """
    Transfer-Encoding header and chunked body must be removed
    from responses to HTTP2 clients and from all cacheable responses.
    That implies response received from the cache or response forwarded
    to HTTP2 client must not contain Transfer-Encoding header and chunked
    body must be cleared of chunks also this response must contain correct
    Content-Length header.

    """

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: chunked\r\n\r\n",
        }
    ]
    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;
        cache 2;
        cache_fulfill * *;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        """
    }

    def setUp(self):
        # add a chunked body
        self.backends[0]["response_content"] += self.encode_chunked(BODY_PAYLOAD, CHUNK_SIZE)
        super().setUp()

    def test(self):
        self.start_all()

        client = self.get_client("client")
        server = self.get_server("backend")

        request = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertFalse(
            "Transfer-Encoding" in response.headers,
            "The response should not have Transfer-Encoding",
        )
        cl = response.headers.get("Content-Length", None)
        self.assertTrue(cl, "The response should have Content-Length")
        self.assertEqual(
            response.body, BODY_PAYLOAD, "Dechunked body does not match the original payload"
        )

        # from now on the response is cached
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)

        self.assertTrue(got_response, "Got no response")
        self.assertEqual(len(server.requests), 1, "The response has to be served from cache")


class TestH2ChunkedIsNotLast(tester.TempestaTest, CommonUtils):
    """
    Responses from backend that don't contain Content-Length header
    and in same time have Transfer-Encoding header with chunked encoding
    as not the last encoding must not be placed into the cache.
    Tempesta must add Content-Length to such responses determining length
    of the body by closing the connection by backend.
    """

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: chunked, gzip\r\n\r\n"
            "the body does not actually matter",
        }
    ]
    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;
        cache 2;
        cache_fulfill * *;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        """
    }

    def test(self):
        self.start_all()

        client = self.get_client("client")
        server = self.get_server("backend")

        request = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response1 = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertFalse(
            "Transfer-Encoding" in response1.headers,
            "The response should not have Transfer-Encoding",
        )
        cl = response1.headers.get("Content-Length", None)
        self.assertTrue(cl, "The response should have Content-Length")

        # repeat the response to ensure it wasn't cached
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response2 = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertEqual(len(server.requests), 2, "The response must not be served from the cache")
        self.assertEqual(
            response1.headers.get("Content-Length"),
            response2.headers.get("Content-Length"),
            "Requests Content-Length headers mismatch",
        )


class TestH1ChunkedNonCacheable(tester.TempestaTest, CommonUtils):
    """
    Non-cacheable HTTP1 responses must be forwarded without changes.
    """

    clients = [{"id": "client", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: chunked\r\n\r\n",
        }
    ]
    tempesta = {
        "config": """
        server ${server_ip}:8000;
        cache 0;
        """
    }

    def setUp(self):
        # add a chunked body
        self.backends[0]["response_content"] += self.encode_chunked(BODY_PAYLOAD, CHUNK_SIZE)
        super().setUp()

    def test(self):
        self.start_all()

        client = self.get_client("client")
        server = self.get_server("backend")

        got_response = self.send_req(client)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "There should be a response")
        self.assertEqual(
            response.headers.get("Transfer-Encoding"), "chunked", "Wrong response Transfer-Encoding"
        )

        # second request
        got_response = self.send_req(client)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "There should be a response")
        self.assertEqual(len(server.requests), 2, "The response has to be server from cache")


class TestH1BothTEAndCE(tester.TempestaTest, CommonUtils):
    """
    If a response from backend contains Transfer-Encoding other than chunked
    and Content-Encoding such responses are invalid for us for now.
    Transfer-Encoding other than chunked it's really rare case, we consider it as suspicious.
    """

    clients = [{"id": "client", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: gzip\r\n"
            "Content-Encoding: br\r\n\r\n"
            "the body does not actually matter",
        }
    ]
    tempesta = {
        "config": """
        server ${server_ip}:8000;
        """
    }

    def test(self):
        self.start_all()

        client = self.get_client("client")

        got_response = self.send_req(client)
        got_response = client.wait_for_response(timeout=5)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertEqual(response.status, "502", "Wrong response status code")


class TestH2TEMovedToCE(tester.TempestaTest, CommonUtils):
    """
    The test to verify correctness of copying values from Transfer-Encoding
    header to Content-Encoding header for HTTP2 client.
    Backend sending response with Transfer-Encoding: gzip, br, chunked as result
    client must receive Content-Encoding: gzip,br.
    """

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: gzip, br, chunked\r\n\r\n",
        }
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

    def setUp(self):
        # add a chunked body
        self.backends[0]["response_content"] += self.encode_chunked(BODY_PAYLOAD, CHUNK_SIZE)
        super().setUp()

    def test(self):
        self.start_all()

        client = self.get_client("client")

        request = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertFalse(
            "Transfer-Encoding" in response.headers,
            "The response should not have Transfer-Encoding",
        )
        ce = response.headers.get("Content-Encoding", None)
        self.assertTrue(ce, "The response should have Content-Encoding")
        self.assertEqual(ce, "gzip,br", "Wrong Content-Encoding value")


class TestH2ChunkedWithTrailer(tester.TempestaTest, CommonUtils):
    """
    Response to HTTP2 client has a trailer.
    All headers from trailer must be moved to response headers.
    Expires will be a header from static table, X-Token is from dynamic one.

    """

    token = "value"

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Trailer: Expires,X-Token\r\n\r\n",
        }
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

    def setUp(self):
        self.backends[0]["response_content"] += (
            self.encode_chunked(BODY_PAYLOAD, CHUNK_SIZE)[:-2]
            + f"Expires: {DATE}\r\n"
            + f"X-Token: {self.token}\r\n\r\n"
        )
        super().setUp()

    def test(self):
        self.start_all()

        client = self.get_client("client")

        request = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertEqual(
            response.headers.get("Expires"),
            str(DATE),
            "Moved trailer header value mismatch the original one",
        )
        self.assertEqual(
            response.headers.get("X-Token"),
            self.token,
            "Moved trailer header value mismatch the original one",
        )


class TestH2ChunkedExtensionRemoved(tester.TempestaTest, CommonUtils):
    """
    Response to HTTP2 client or cacheable with chunked body has chunked extension.
    Extension must be removed.
    """

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-type: text/html\r\n"
            f"Last-Modified: {DATE}\r\n"
            f"Date: {DATE}\r\n"
            "Server: Deproxy Server\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\n"
            "some \r\n"
            "4;extension=value\r\n"
            "data\r\n"
            "0\r\n\r\n",
        }
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

    def test(self):
        self.start_all()

        client = self.get_client("client")

        request = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        client.make_request(request)
        got_response = client.wait_for_response(timeout=5)
        response = client.responses[-1] if len(client.responses) else None

        self.assertTrue(got_response, "Got no response")
        self.assertEqual(response.body, "some data", "Wrong response body value")


class TestRequestTEAndCL(tester.TempestaTest, CommonUtils):
    """
    Request that contains Transfer-Encoding: chunked and Content-Length in same time - must be blocked.
    """

    clients = [{"id": "client", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n\r\n",
        }
    ]
    tempesta = {
        "config": """
        server ${server_ip}:8000;
        """
    }

    def test(self):
        self.start_all()

        client = self.get_client("client")
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 33\r\n\r\n"
            "the body does not actually matter",
        )

        self.send_req(client, request)
        self.assertFalse(len(client.responses), "The request was not blocked")


class TestRequestChunkedNotLast(tester.TempestaTest, CommonUtils):
    """
    Request that contains chunked encoding and chunked is not final encoding - must be blocked.
    """

    clients = [{"id": "client", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]
    backends = [
        {
            "id": "backend",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n\r\n",
        }
    ]
    tempesta = {
        "config": """
        server ${server_ip}:8000;
        """
    }

    def test(self):
        self.start_all()

        client = self.get_client("client")
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Transfer-Encoding: chunked, gzip\r\n"
            "the body does not actually matter",
        )

        self.send_req(client, request)
        self.assertFalse(len(client.responses), "The request was not blocked")