import time

from h2.exceptions import ProtocolError

from framework import deproxy_client
from helpers import deproxy
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class DeproxyTestH2(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
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

    def test_make_request(self):
        self.start_all()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = True
        deproxy_cl.make_request(head)

        self.assertTrue(deproxy_cl.wait_for_response(timeout=0.5))
        self.assertEqual(deproxy_cl.last_response.status, "200")

    def test_duplicate_headers(self):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.start_all_services()
        client.send_request(
            request=client.create_request(
                method="GET",
                headers=[
                    ("cookie", "name1=value1"),
                    ("cookie", "name2=value2"),
                ],
            ),
            expected_status_code="200",
        )

        self.assertEqual(server.last_request.headers.get("cookie"), "name1=value1; name2=value2")

    def test_parsing_make_request(self):
        self.start_all()

        head = [(":authority", "localhost"), (":path", "/"), (":scheme", "http"), ("method", "GET")]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = True

        self.assertRaises(ProtocolError, deproxy_cl.make_request, head)
        self.assertIsNone(deproxy_cl.last_response)

    def test_no_parsing_make_request(self):
        self.start_all()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        deproxy_cl.make_request(head)
        self.assertTrue(deproxy_cl.wait_for_response(timeout=0.5))
        self.assertEqual(deproxy_cl.last_response.status, "400")

    def test_bodyless(self):
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
        self.assertEqual(deproxy_cl.last_response.status, "200")

    def test_bodyless_multiplexed(self):
        self.start_all()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        request = [head, head]

        deproxy_srv = self.get_server("deproxy")
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(request)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertEqual(2, len(deproxy_srv.requests))

    def test_with_body(self):
        self.start_all()

        body = "body body body"
        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("conent-length", "14"),
        ]
        request = (head, body)

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(request)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(deproxy_cl.last_response.status, "200")

    def test_get_4xx_response(self):
        self.start_all()

        head = [
            (":authority", ""),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        deproxy_cl.make_request(head)

        self.assertTrue(deproxy_cl.wait_for_response(timeout=2))
        # TODO: decide between 400 or 403 response code later
        self.assertEqual(int(int(deproxy_cl.last_response.status) / 100), 4)

    def test_disable_huffman_encoding(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.make_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            end_stream=True,
            huffman=False,
        )
        self.assertIn(b"example.com", client.request_buffers[0])

    def test_wait_for_headers_frame(self):
        """Tests for `wait_for_headers_frame` method."""
        self.start_all_services()

        # Response body should be large then default window size 64KB
        body_size = 1024 * 100
        server = self.get_server("deproxy")
        # Server return response with headers > 16KB so TempestaFW MUST separate them to
        # HEADERS and CONTINUATION frames.
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"x-my-hdr: {'a' * 20000}\r\n"
            + f"Content-Length: {body_size}\r\n\r\n"
            + ("a" * body_size)
        )

        client = self.get_client("deproxy")
        # disable sending WINDOW frames from client
        client.auto_flow_control = False
        client.make_request(client.create_request(method="GET", headers=[], uri="/large.txt"))
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))
        self.assertIsNotNone(
            client.active_responses.get(1, None),
            "`wait_for_headers_frame` returned True, "
            "but client did not add a new response to buffer.",
        )
        self.assertIsNone(
            client.last_response,
            "Client received response after call `wait_for_headers_frame`. "
            "But it only expects to receive headers (not END_STREAM flag)."
            "Probably you should increase a response body for this test.",
        )

        client.increment_flow_control_window(stream_id=1, flow_controlled_length=body_size)
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")


class DeproxyClientTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Server: deproxy\r\n\r\n",
        },
    ]

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
        {
            "id": "deproxy-interface",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
    ]

    tempesta = {
        "config": (
            "listen 80;\n"
            "access_log dmesg;\n"
            "frang_limits {http_methods GET HEAD POST PUT DELETE;}\n"
            "server ${server_ip}:8000;\n"
        )
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, "200")

    def test_parsing_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        self.assertRaises(
            deproxy.ParseError, client.make_request, "GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        self.assertIsNone(client.last_response)

    def test_no_parsing_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        client.make_request("GET / HTTP/1.1\r\nHost: local<host\r\n\r\n")
        client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, "400")

    def test_many_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        messages = 5
        for _ in range(0, messages):
            client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            client.wait_for_response(timeout=0.5)

        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, "200")

    def test_many_make_request_2(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        messages = 5
        for _ in range(0, messages):
            client.make_request("GET / HTTP/1.1\r\nHost: local<host\r\n\r\n")
            client.wait_for_response(timeout=0.5)

        self.assertEqual(client.last_response.status, "400")
        self.assertEqual(len(client.responses), 1)

    def __send_requests(self, client, request, count, expected_len, pipelined):
        client.make_requests([request] * count, pipelined=pipelined)
        client.wait_for_response(timeout=3)

        self.assertEqual(len(client.responses), expected_len)
        for res in client.responses:
            self.assertEqual(res.status, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_pipelined", pipelined=False),
            marks.Param(name="pipelined", pipelined=True),
        ]
    )
    def test_make_requests(self, name, pipelined):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

        self.__send_requests(client, request, 3, 3, pipelined)
        self.__send_requests(client, request, 3, 6, pipelined)

    def test_parsing_make_requests(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        self.assertRaises(
            deproxy.ParseError,
            client.make_requests,
            [
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            ],
        )
        self.assertIsNone(client.last_response)

    def test_interface(self):
        """
        Deproxy client is started on local network several times.
        We should not receive error.
        """
        client: deproxy_client.DeproxyClient = self.get_client("deproxy-interface")

        self.start_all_services(client=False)

        for _ in range(5):
            try:
                client.start()
                client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                client.stop()
            except OSError:
                raise AssertionError("Deproxy client launch: IP address is not available.")

    def test_pipeline_request(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        messages = 3
        request = ["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" for _ in range(messages)]

        client.make_requests(request, pipelined=True)
        client.valid_req_num = messages
        client.wait_for_response(timeout=3)

        self.assertEqual(client.nrreq, 1, "The estimated number of requests does not match.")
        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, "200")

    def test_send_full_request(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. Don't wait
        for 100-continue response. Due to we send body right after header without any
        time intervals '101-continue' response must not be sent by Tempesta. Only one
        response is expected in this test.
        """
        self.start_all_services(client=False)

        client = self.get_client("deproxy")
        client.start()

        client.send_request(
            request=client.create_request(
                method="PUT",
                headers=[
                    ("Expect", "100-continue"),
                    ("Content-Length", "9"),
                    ("Content-Type", "application/json"),
                ],
                uri="/test_100",
                body="1" * 9,
                version="HTTP/1.1",
            ),
            expected_status_code="200",
        )

    def test_regular_behaviour(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. Send only
        headers, then wait for 100-continue response, and send after that body,
        wait for server response.
        """
        self.disable_deproxy_auto_parser()
        self.start_all_services(client=False)

        client = self.get_client("deproxy")
        client.start()

        client.send_request(
            request=client.create_request(
                method="PUT",
                headers=[
                    ("Expect", "100-continue"),
                    ("Content-Length", "9"),
                    ("Content-Type", "application/json"),
                ],
                uri="/test_100",
                version="HTTP/1.1",
            ),
            expected_status_code="100",
        )
        client.send_bytes(b"1" * 9, expect_response=True)
        client.wait_for_response(strict=True)
        self.assertEqual(client.last_response.status, "200")

    def test_request_pipeline_delay(self):
        """
        Send two pipelined requests, the first request will be forwarded to upstream,
        then Tempesta processes second request that contains 'Expect: 100-continue'
        header, prepares '100-continue' response and puts it into a queue. Then Tempesta
        receives response to the first request, forwards it to the client and then
        forwards '100-continue' response to the client.
        NOTE: To have deterministic behavior upstream sleeps for a 2 seconds when
        request received.
        """
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/test",
                    body="3" * 9,
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/expect",
                    # body="{}",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100],
            "Invalid responses sequence",
        )

        client.send_bytes(b"1" * 9, expect_response=True)
        client.wait_for_response(strict=True)
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_delay_no_wait(self):
        """
        Tempesta should remove response 100-continue
        if the request body comes earlier than responding starts
        """
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/test",
                    body="3" * 9,
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/expect",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        time.sleep(0.2)
        client.send_bytes(b"1" * 9)

        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_delay_3_requests(self):
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/test",
                    body="3" * 9,
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "2"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/expect",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100],
            "Invalid responses sequence",
        )

        request = client.create_request(
            method="GET",
            headers=[],
            uri="/test",
            version="HTTP/1.1",
        )
        client.send_bytes(b"{}" + request.msg.encode(), expect_response=True)
        client.methods.append("GET")
        client.wait_for_response(strict=True, n=4)
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100, 200, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_3_requests_empty_body(self):
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/test",
                    body="3" * 9,
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "0"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/expect",
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="GET",
                    headers=[],
                    uri="/test",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 200, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_3_requests_encoding_chunked(self):
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Content-Length", "9"),
                        ("Content-Type", "application/json"),
                    ],
                    uri="/test",
                    body="3" * 9,
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "100"),
                        ("Content-Type", "text/plain"),
                        ("Content-Encoding", "chunked"),
                    ],
                    uri="/expect",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100],
            "Invalid responses sequence",
        )

        request = client.create_request(
            method="GET",
            headers=[],
            uri="/test",
            version="HTTP/1.1",
        )
        client.send_bytes(b"a" * 100 + request.msg.encode(), expect_response=True)
        client.methods.append("GET")
        client.wait_for_response(strict=True, n=4)
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100, 200, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_3_all_100(self):
        self.disable_deproxy_auto_parser()

        self.start_all_services(client=False)

        client = self.get_client("deproxy")
        client.start()

        client.make_requests(
            requests=[
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "2"),
                        ("Content-Type", "application/json"),
                    ],
                    body="{}",
                    uri="/expect",
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "2"),
                        ("Content-Type", "application/json"),
                    ],
                    body="{}",
                    uri="/expect",
                    version="HTTP/1.1",
                ),
                client.create_request(
                    method="PUT",
                    headers=[
                        ("Expect", "100-continue"),
                        ("Content-Length", "2"),
                        ("Content-Type", "application/json"),
                    ],
                    body="{}",
                    uri="/expect",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 200, 200],
            "Invalid responses sequence",
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
