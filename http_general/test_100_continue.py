from test_suite import tester


class Test100ContinueResponse(tester.TempestaTest):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": (
                "pid ${pid}; "
                "worker_processes  auto; "
                "events { "
                "   worker_connections   1024; "
                "   use epoll; "
                "} "
                "http { "
                "   keepalive_timeout ${server_keepalive_timeout}; "
                "   keepalive_requests ${server_keepalive_requests}; "
                "   access_log off; "
                "   server { "
                "       listen        ${server_ip}:8000; "
                "       location / { "
                "          return 200 'hello'; "
                "       } "
                "       location /nginx_status { "
                "           stub_status on; "
                "       } "
                "   } "
                "} "
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            access_log dmesg;
            frang_limits {http_methods GET HEAD POST PUT DELETE;}
            server ${server_ip}:8001;
        """
    }

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-XPUT "
                '-H "Accept-Encoding: identity" '
                '-H "X-Amz-Meta-Purpose: test" '
                '-H "User-Agent: Boto3/1.35.99 md/Botocore#1.35.99 ua/2.0 os/linux#6.8.0-52-generic md/arch#x86_64 lang/python#3.12.3 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.99" '
                '-H "Content-Md5: tqko9U/zjvYv0x7KrNw4kg==" '
                '-H "Expect: 100-continue" '
                '-H "X-Amz-Date: 20250205T211821Z" '
                '-H "X-Amz-Content-Sha256: 1e9415183638cd30c03fb2cff9ba7d85a3604dccd1cbc1b7d32355174e2858b8" '
                '-H "Authorization: WS4-HMAC-SHA256 Credential=3VJTIQ8OQG642KKXLLMG/20250205/us-east-1/s3/aws4_request, SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date;x-amz-meta-purpose, Signature=717bf26945806cfc48b2a392110ac96b5e587fb0149c6df8e8b8db7c794b3b48" '
                '-H "Amz-Sdk-Invocation-Id: 8c3e4ebb-0dc8-49a6-b0ab-afbfcb22b649" '
                '-H "Amz-Sdk-Request: attempt=2; max=2" '
                '-H "Content-Length: 8" '
                '-d "limits66" '
                "-vvv "
                " http://localhost:80/ "
            ),
        }
    ]

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("curl")
        client.start()

        self.wait_while_busy(client)


class Test100ContinueResponseSeg(tester.TempestaTest):
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

    def test_request_with_body(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. Don't wait
        for 100-continue response. Due to we send body right after header without any
        time intervals '101-continue' response must not be sent by Tempesta. Only one
        response is expected in this test.
        """
        self.disable_deproxy_auto_parser()
        self.start_all_services()
        client = self.get_client("deproxy")

        request = f"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length:3\r\nExpect: 100-continue\r\n\r\nasd"

        client.send_request(
            request=request,
            expected_status_code="200",
        )

    def test_request_with_body_seg_100(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. Send only
        headers, then wait for 100-continue response.

        NOTE: Implemented via sending request by multiple segments, maybe we can
        implement this sending only 2 segments(headers and body) send headers then wait
        for 100-response, then send body?
        """
        self.start_all_services()
        client = self.get_client("deproxy-seg")

        request = f"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length:3\r\nExpect: 100-continue\r\n\r\nasd"

        client.send_request(
            request=request,
            expected_status_code="100",
        )
        # TODO: Ensure that 200 response received as well.

    def test_request_with_body_seg_76(self):
        """
        Send request that contains 'Expect: 100-continue' header and body. But send
        only part of the body, in this case '100-continue' response is not expected.
        """
        self.disable_deproxy_auto_parser()
        self.start_all_services()
        client = self.get_client("deproxy-seg-76")

        request = f"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length:3\r\nExpect: 100-continue\r\n\r\nasd"

        client.send_request(
            request=request,
            expected_status_code="200",
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
        self.get_server("deproxy").sleep_when_receiving_data = 2
        self.start_all_services()
        client = self.get_client("deproxy-seg")

        client.parsing = False
        client.make_requests(
            requests=[
                f"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length:3\r\nqwr: 100-continue\r\n\r\nasd",
                f"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length:3\r\nExpect: 100-continue\r\n\r\n",
            ],
            pipelined=True,
        )
        client.wait_for_response(timeout=10)

        # TODO: Ensure that received 3 responses with status-codes: 200, 101, 200.
        # Also would be great, to have ID for each request/response to verify correct
        # orders of responses.
