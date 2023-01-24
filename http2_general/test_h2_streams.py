"""Functional tests for h2 streams."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestH2Stream(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
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

    def test_max_concurrent_stream(self):
        """
        Tempesta must not concurrently process streams when their count exceeds set value.
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        request_headers = [
            (":authority", "debian"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
        ]
        # TODO need change after fix issue #1394
        max_streams = 128

        for _ in range(max_streams):
            client.make_request(request=request_headers, end_stream=False)
            client.stream_id += 2

        client.make_request(request=request_headers, end_stream=True)
        client.wait_for_response()

        self.assertTrue(
            client.connection_is_closed(),
            "Tempesta did not close connection when number of concurrent streams was exceeded.",
        )
