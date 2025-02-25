from test_suite import tester


class Test100ContinueResponse(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            access_log dmesg;
            frang_limits {http_methods GET HEAD POST PUT DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-seg",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "segment_gap": 250,  # ms
            "segment_size": 75,
        },
        {
            "id": "deproxy-seg-76",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "segment_gap": 100,  # ms
            "segment_size": 76,
        },
    ]

    def test_send_full_request(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. Don't wait
        for 100-continue response. Due to we send body right after header without any
        time intervals '101-continue' response must not be sent by Tempesta. Only one
        response is expected in this test.
        """
        self.start_all_services(client=False)

        client = self.get_client("deproxy")
        client.allow_expect_100_continue_behavior = False
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
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [100, 200],
            "Invalid responses sequence",
        )

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

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        self.start_all_services()
        client = self.get_client("deproxy")

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
                    body="{}",
                    version="HTTP/1.1",
                ),
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        self.assertEqual(
            [int(response.status) for response in client.responses],
            [200, 100, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_delay_3_requests(self):
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        self.start_all_services()
        client = self.get_client("deproxy")

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
                    body="{}",
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
            [200, 100, 200, 200],
            "Invalid responses sequence",
        )

    def test_request_pipeline_delay_3_requests_empty_body(self):
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        self.start_all_services()
        client = self.get_client("deproxy")

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
