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
            server ${server_ip}:8000;
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
