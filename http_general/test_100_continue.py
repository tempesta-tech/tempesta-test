from test_suite import tester


class Test100ContinueResponse(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "".join(
                "HTTP/1.1 200 OK\r\n" "Content-Length: 10\r\n\r\n" "0123456789",
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
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
        }
    ]

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(
            uri="/brussels8452/pleased2838",
            method="PUT",
            headers=[
                ("Accept-Encoding", "identity"),
                ("X-Amz-Meta-Purpose", "test"),
                (
                    "User-Agent",
                    "Boto3/1.35.99 md/Botocore#1.35.99 ua/2.0 os/linux#6.8.0-52-generic md/arch#x86_64 lang/python#3.12.3 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.99",
                ),
                ("Content-Md5", "tqko9U/zjvYv0x7KrNw4kg=="),
                ("Expect", "100-continue"),
                ("X-Amz-Date", "20250205T211821Z"),
                (
                    "X-Amz-Content-Sha256",
                    "1e9415183638cd30c03fb2cff9ba7d85a3604dccd1cbc1b7d32355174e2858b8",
                ),
                (
                    "Authorization",
                    "AWS4-HMAC-SHA256 Credential=3VJTIQ8OQG642KKXLLMG/20250205/us-east-1/s3/aws4_request, SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date;x-amz-meta-purpose, Signature=717bf26945806cfc48b2a392110ac96b5e587fb0149c6df8e8b8db7c794b3b48",
                ),
                ("Amz-Sdk-Invocation-Id", "8c3e4ebb-0dc8-49a6-b0ab-afbfcb22b649"),
                ("Amz-Sdk-Request", "attempt=2; max=2"),
                ("Content-Length", "8"),
            ],
            body="limits66",
        )
        client.send_request(request, expected_status_code="200")
