from h2.exceptions import ProtocolError

from framework.deproxy import deproxy_client, deproxy_message
from framework.helpers import dmesg, remote
from framework.test_suite import marks, tester

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

    async def test_make_request(self):
        await self.start_all_services()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = True
        deproxy_cl.make_request(head)

        self.assertTrue(await deproxy_cl.wait_for_response(timeout=0.5))
        self.assertEqual(deproxy_cl.last_response.status, "200")

    async def test_duplicate_headers(self):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        await self.start_all_services()
        await client.send_request(
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

    async def test_parsing_make_request(self):
        await self.start_all_services()

        head = [(":authority", "localhost"), (":path", "/"), (":scheme", "http"), ("method", "GET")]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = True

        self.assertRaises(ProtocolError, deproxy_cl.make_request, head)
        self.assertIsNone(deproxy_cl.last_response)

    async def test_no_parsing_make_request(self):
        await self.start_all_services()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        deproxy_cl.make_request(head)
        self.assertTrue(await deproxy_cl.wait_for_response(timeout=0.5))
        self.assertEqual(deproxy_cl.last_response.status, "400")

    async def test_bodyless(self):
        await self.start_all_services()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(head)

        await deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(deproxy_cl.last_response.status, "200")

    async def test_bodyless_multiplexed(self):
        await self.start_all_services()

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

        await deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertEqual(2, len(deproxy_srv.requests))

    async def test_with_body(self):
        await self.start_all_services()

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

        await deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(deproxy_cl.last_response.status, "200")

    async def test_get_4xx_response(self):
        await self.start_all_services()

        head = [
            (":authority", ""),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        deproxy_cl.make_request(head)

        self.assertTrue(await deproxy_cl.wait_for_response(timeout=2))
        # TODO: decide between 400 or 403 response code later
        self.assertEqual(int(int(deproxy_cl.last_response.status) / 100), 4)

    async def test_disable_huffman_encoding(self):
        await self.start_all_services()
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

    async def test_wait_for_headers_frame(self):
        """Tests for `wait_for_headers_frame` method."""
        await self.start_all_services()

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
        self.assertTrue(await client.wait_for_headers_frame(stream_id=1))
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
        self.assertTrue(await client.wait_for_response())
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
        "config": """
cache 0;
listen 80;

server ${server_ip}:8000;
"""
    }

    def restore_defaults(self):
        remote.client.run_cmd(f"sysctl -w net.ipv4.tcp_syn_retries={self.saved_retries}")
        remote.client.run_cmd(f"sysctl -w net.ipv4.tcp_syn_linear_timeouts={self.saved_timeouts}")

    @marks.Parameterize.expand(
        [
            marks.Param(name="wait", need_wait=True, block_duration=3, timeout=6),
            marks.Param(name="timeout", need_wait=True, block_duration=10, timeout=2),
            marks.Param(name="not_wait", need_wait=False, block_duration=3, timeout=0),
        ]
    )
    async def test_open_connection(self, name, need_wait, block_duration, timeout):
        """
        Test for wait_for_connection_open().

        Description for wait version: Open the new connection and send bad request. Tempesta blocks
        the client, then while client still blocked try to establish one more connection and wait
        using wait_for_connection_open(). SYN will be retransmitted few times during block and
        when block will be finished connection will be established. Using `ip_block` in this test
        we simulate unstable connection that loses few SYN segments and verify in this condition
        wait_for_connection_open() really waits until connection establishing. Alternative solution
        could be implemnted using nftables instead of Tempesta + ip_block.

        Description for not_wait version: The same as wait version of this test, but expected
        result is not established connection due to not calling wait_for_connection_open() and
        trying to connect while client still blocked.

        Description for timeout version: The same as wait version of this test, but expected
        timeout during waiting for connection establishing.

        To make test predictable and stable adjust tcp_syn_retries and tcp_syn_linear_timeouts, but
        restore previous values when test finished.

        Set high timeout value for wait version to be sure we cover linear timeouts(4s by default)
        plus a little bit more. With default tcp_syn_retries 6 and tcp_syn_linear_timeouts 4
        expected SYN RTO is 1, 1, 1, 1, 1, 2, 4, ...
        """
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(
            tempesta.config.defconfig
            + f"frang_limits {{ip_block {block_duration}; http_uri_len 4;}}\n"
        )
        klog = dmesg.DmesgFinder(disable_ratelimit=True)
        await self.start_all_services(False)

        # Save system values
        self.saved_retries = int(
            remote.client.run_cmd("sysctl --values net.ipv4.tcp_syn_retries")[0]
        )
        self.saved_timeouts = int(
            remote.client.run_cmd("sysctl --values net.ipv4.tcp_syn_linear_timeouts")[0]
        )
        self.addCleanup(self.restore_defaults)

        # Set test values. They are equal to Linux default.
        remote.client.run_cmd("sysctl -w net.ipv4.tcp_syn_retries=6")
        remote.client.run_cmd("sysctl -w net.ipv4.tcp_syn_linear_timeouts=4")

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-interface")
        client.start()
        await client.wait_for_connection_open(timeout=2)
        client.make_request("GET /qwerty HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await client.wait_for_connection_close(timeout=2)
        # Connect one more time during block duration.
        client.restart()
        if timeout > 0:
            await client.wait_for_connection_open(timeout=timeout)
        # If wait less than block_duration time thus expected not established connection.
        expected_connected = True if timeout > block_duration else False
        self.assertEqual(client.connected, expected_connected)
        self.assertTrue(
            await klog.find("Warning: block client:", cond=dmesg.amount_equals(1)),
            "Client has not been blocked.",
        )

    async def test_make_request(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        client.make_requests(["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"] * 3)
        await client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(len(client.responses), 3)
        self.assertEqual(client.last_response.status, "200")

    async def test_parsing_make_request(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        self.assertRaises(
            deproxy_message.ParseError,
            client.make_request,
            "GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        self.assertIsNone(client.last_response)

    async def test_no_parsing_make_request(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        client.make_request("GET / HTTP/1.1\r\nHost: local<host\r\n\r\n")
        await client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, "400")

    async def test_many_make_request(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        messages = 5
        for _ in range(0, messages):
            client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await client.wait_for_response(timeout=0.5)

        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, "200")

    async def test_many_make_request_2(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        messages = 5
        for _ in range(0, messages):
            client.make_request("GET / HTTP/1.1\r\nHost: local<host\r\n\r\n")
            await client.wait_for_response(timeout=0.5)

        self.assertEqual(client.last_response.status, "400")
        self.assertEqual(len(client.responses), 1)

    async def __send_requests(self, client, request, count, expected_len, pipelined):
        client.make_requests([request] * count, pipelined=pipelined)
        await client.wait_for_response(timeout=3)

        self.assertEqual(len(client.responses), expected_len)
        for res in client.responses:
            self.assertEqual(res.status, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_pipelined", pipelined=False),
            marks.Param(name="pipelined", pipelined=True),
        ]
    )
    async def test_make_requests(self, name, pipelined):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

        await self.__send_requests(client, request, 3, 3, pipelined)
        await self.__send_requests(client, request, 3, 6, pipelined)

    async def test_parsing_make_requests(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = True

        self.assertRaises(
            deproxy_message.ParseError,
            client.make_requests,
            [
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            ],
        )
        self.assertIsNone(client.last_response)

    async def test_interface(self):
        """
        Deproxy client is started on local network several times.
        We should not receive error.
        """
        client: deproxy_client.DeproxyClient = self.get_client("deproxy-interface")

        await self.start_all_services(client=False)

        for _ in range(5):
            try:
                client.start()
                client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                client.stop()
            except OSError:
                raise AssertionError("Deproxy client launch: IP address is not available.")

    async def test_pipeline_request(self):
        await self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        messages = 3
        request = ["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" for _ in range(messages)]

        client.make_requests(request, pipelined=True)
        client.valid_req_num = messages
        await client.wait_for_response(timeout=3)

        self.assertEqual(client.nrreq, 1, "The estimated number of requests does not match.")
        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, "200")
