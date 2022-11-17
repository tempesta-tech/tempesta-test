from framework import tester
from helpers import deproxy, tf_cfg
from tls import handshake, test_tls_cert, test_tls_handshake

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

# This small testsuite is created to serve as an example or a template for
# tests with iteration over various chunk sizes. It demonstrates how to do
# this job in the right way.
#
# Every test is splitted into two functions: inner_test_xxx() and test_xxx().
# Then the inner_test_xxx() is iterated by the 'universal' function
# iterate_test(), whereas outer text_xxx() is responsible for start and
# setting required parameters, if any.
#
# Three example tests are defined in the ChunkingExampleTest below class:
#
# 1. Test for forwarding the request with long and sophisticated header set.
# 2. A simple request test for chunked response from the backend server.
# 3. A simple request test transmitted over TLS.
#
# Three example tests demonstrate a way to make chunking for tests defined
# in tls/ directory. These tests are defined in their own classes inherited
# from the tls/ classes. Note that tests 5 and 6 uses TLS implementation from
# Scapy and are controlled in a slightly different manner.
#
# 4. Certificate test.
# 5. Certificate select test.
# 6. Basic TLS handshake test.
#


class ChunkingTestIterator(object):
    def iterate_test(self, test_func, msg_size, *args, **kwargs):
        # This function provides iterations over various chunk sizes.
        # It have required positional parameters:
        # @test_func - a function to iterate. Supposed, it implements
        #              a test scenario and is a member of the same class.
        # @msg_size - a size of the message (request or response) which
        #             plays as upper bound for chunk size
        # The function can accept additional positional and keyword
        # parameters with *args and **kwargs to forward them to
        # the @test_func().
        # The function is located in the separate class for better reusability
        CHUNK_SIZES = [1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1500, 9216, 1024 * 1024]
        for i in range(len(CHUNK_SIZES)):
            test_func(CHUNK_SIZES[i], *args, **kwargs)
            if CHUNK_SIZES[i] > msg_size:
                break


class ChunkingExampleTest(tester.TempestaTest, ChunkingTestIterator):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
    ]

    tempesta = {
        "config": """
cache 0;
server ${general_ip}:8000;
listen 80;
listen 443 proto=https;
tls_certificate ${general_workdir}/tempesta.crt;
tls_certificate_key ${general_workdir}/tempesta.key;
""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
        {
            "id": "deproxy_ssl",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def inner_test_long_headers(self, chunksize, request):
        # This function defines a test scenario itself.
        # @chunksize is required positional parameter,
        # to be in accordance with iterate_test().
        #
        # In this partucular example the test reproduses
        # the fills_hdr_tbl_for_req() test from unit tests.
        # However the fills_hdr_tbl_for_req() check for contents
        # of internal TWF tables for parsed headers, whereas
        # this test check for headers forwarded to the backend,
        # so these two tests checks for different potential faults.
        #
        # In your case there could be your own scenario.
        # And it can have additional positional or keyword
        # parameters
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        # This line controls chunking:
        deproxy_cl.segment_size = chunksize
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))

        deproxy_cl.make_request(request)
        self.assertTrue(deproxy_cl.valid_req_num != 0, "Request was not parsed by deproxy client")

        has_resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received; with chunk size = %d" % chunksize)
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(
            status == 200,
            "Wrong status: %d, expected: 200" "; with chunk size = %d" % (status, chunksize),
        )
        self.assertFalse(
            deproxy_srv.last_request is None,
            "Request was not send to backend; with chunk size = %d" % chunksize,
        )

        req = deproxy.Request(request)
        req2 = deproxy_srv.last_request
        hdrs2 = req2.headers
        for hdr in req.headers.iteritems():
            v2 = hdrs2.get(hdr[0], "-")
            self.assertTrue(
                hdr[1] == v2,
                "Header %s mismatch (%s != %s); with chunk size = %d"
                % (hdr[0], v2, hdr[1], chunksize),
            )

    def test_long_headers(self):
        # This function starts the test, iterating over different
        # chunk sizes
        request = (
            "GET / HTTP/1.1\r\n"
            "User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
            "Accept: */*\r\n"
            "Host: localhost\r\n"
            "Connection: Keep-Alive\r\n"
            "X-Custom-Hdr: custom header values\r\n"
            "Dummy0: 0\r\n"
            "Dummy1: 1\r\n"
            "Dummy2: 2\r\n"
            "Dummy3: 3\r\n"
            "Dummy4: 4\r\n"
            "Dummy5: 5\r\n"
            "Dummy6: 6\r\n"
            "Content-Type: text/html; charset=iso-8859-1\r\n"
            "Dummy7: 7\r\n"
            "Dummy8: 8\r\n"
            "Dummy9: 9\r\n"
            "Cache-Control: max-age=1, no-store, min-fresh=30\r\n"
            "Pragma: no-cache, fooo \r\n"
            "Transfer-Encoding: compress, gzip, chunked\r\n"
            "Cookie: session=42; theme=dark\r\n"
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
            "\r\n"
            "6\r\n"
            "123456\r\n"
            "0\r\n"
            "\r\n"
        )
        # Excluded: "X-Forwarded-For: 127.0.0.1, example.com\r\n"
        # because TFW rewrites it
        self.iterate_test(self.inner_test_long_headers, len(request), request)

    def inner_test_ss_chunks(self, chunksize, request):
        # This function makes a simple request to check
        # (with tcpdump) that server response is chunked
        # as required
        deproxy_srv = self.get_server("deproxy")
        # This line controls chunking:
        deproxy_srv.segment_size = chunksize
        deproxy_srv.start()
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))

        deproxy_cl.make_request(request)
        self.assertTrue(deproxy_cl.valid_req_num != 0, "Request was not parsed by deproxy client")

        has_resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received; with chunk size = %d" % chunksize)
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(
            status == 200,
            "Wrong status: %d, expected: 200" "; with chunk size = %d" % (status, chunksize),
        )
        self.assertFalse(
            deproxy_srv.last_request is None,
            "Request was not send to backend" "; with chunk size = %d" % chunksize,
        )

    def test_ss_chunks(self):
        # This function makes a simple request to check
        # (with tcpdump) that server response is chunked
        # as required, iterating over various chunk sizes
        request = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        response = self.get_server("deproxy").response
        self.iterate_test(self.inner_test_ss_chunks, len(response), request)

    def inner_test_ssl(self, chunksize, request):
        # This function makes a simple request over TLS
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.start_tempesta()
        # This line selects the SSL/TLS client:
        deproxy_cl = self.get_client("deproxy_ssl")
        # This line controls chunking:
        deproxy_cl.segment_size = chunksize
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))

        deproxy_cl.make_request(request)
        self.assertTrue(deproxy_cl.valid_req_num != 0, "Request was not parsed by deproxy client")

        has_resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received; with chunk size = %d" % chunksize)
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(
            status == 200,
            "Wrong status: %d, expected: 200" "; with chunk size = %d" % (status, chunksize),
        )
        self.assertFalse(
            deproxy_srv.last_request is None,
            "Request was not send to backend" "; with chunk size = %d" % chunksize,
        )

    def test_ssl(self):
        # This function makes simple requests over TLS,
        # iterating over different chunk sizes
        request = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.iterate_test(self.inner_test_ssl, len(request) + 64, request)  # some overhead for TLS


class CertificateChunkingExampleTest(test_tls_cert.RSA1024_SHA384, ChunkingTestIterator):
    # This test iterates main RSA1024_SHA384 test with various chunk sizes
    # Unchunked test is executed as well because of inheritance

    def inner_test_cert_chunking(self, chunksize):
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.segment_size = chunksize
        self.test()

    def test_cert_chunking(self):
        self.iterate_test(self.inner_test_cert_chunking, 127)


class CertSelectChunkingExampleTest(test_tls_cert.TlsCertSelect, ChunkingTestIterator):
    # This test iterates main TlsCertSelect test with various chunk sizes.
    # This test uses TLS implementation fron Scapy.
    # Unchunked test is executed as well because of inheritance

    segment_size = 0
    segment_gap = 0

    # overriding
    def get_tls_handshake(self):
        return handshake.TlsHandshake(
            chunk=self.segment_size if self.segment_size > 0 else None,
            sleep_time=self.segment_gap / 1000,
        )

    def inner_test_csel_chunking(self, chunksize):
        self.segment_size = chunksize
        self.test_vhost_cert_selection()

    def test_csel_chunking(self):
        self.iterate_test(self.inner_test_csel_chunking, 127)
        self.segment_size = 0


class TlsHandshakeChunkingExampleTest(test_tls_handshake.TlsHandshakeTest, ChunkingTestIterator):
    # This test iterates basic handshake test from TlsHandshakeTest test with
    # various chunk sizes. This test uses TLS implementation fron Scapy.
    # Unchunked tests are executed as well because of inheritance

    segment_size = 0
    segment_gap = 0

    def get_tls_handshake(self):
        return handshake.TlsHandshake(
            chunk=self.segment_size if self.segment_size > 0 else None,
            sleep_time=self.segment_gap / 1000,
        )

    def _test_tls12_parametric(self):
        self.start_all()
        res = self.get_tls_handshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def inner_test_tls12_chunking(self, chunksize):
        self.segment_size = chunksize
        self._test_tls12_parametric()

    def test_tls12_chunking(self):
        self.iterate_test(self.inner_test_tls12_chunking, 127)
        self.segment_size = 0
