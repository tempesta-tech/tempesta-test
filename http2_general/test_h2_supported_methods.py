from test_suite import tester


class TestHttp2Methods(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ),
        },
    ]

    clients = [
        {
            "id": "deproxy-h2",
            "type": "deproxy-h2",
            "addr": "${tempesta_ip}",
            "port": "443",
        },
    ]

    tempesta = {
        "config": (
            "listen 443 proto=h2;\n"
            "tls none;\n"
            "server ${server_ip}:8000;\n"
            "frang_limits {\n"
            "    http_methods GET HEAD POST PUT DELETE OPTIONS PATCH "
            "PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK TRACE;\n"
            "}\n"
        )
    }

    def _test_method(self, method):
        self.start_all_services(client=False)

        client = self.get_client("deproxy-h2")
        client.start()

        print(f"Sending method: {method} via HTTP/2")
        client.send_request(
            request=client.create_request(
                method=method,
                uri="/test_method",
                headers=[
                    ("Content-Length", "0"),
                    ("Content-Type", "application/json"),
                ],
            ),
            expected_status_code="200",
        )

    def test_common_methods(self):
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
            self._test_method(method)

    def test_extended_methods(self):
        for method in [
            "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "TRACE"
        ]:
            self._test_method(method)

