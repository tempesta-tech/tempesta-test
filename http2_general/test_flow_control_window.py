"""Functional tests for flow control window."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestFlowControl(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 2000\r\n\r\n"
                + ("x" * 2000)
            ),
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

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    request_headers = [
        (":authority", "debian"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    def test_flow_control_window_for_stream(self):
        """
        Client sets SETTINGS_INITIAL_WINDOW_SIZE = 1k bytes and backend returns response
        with 2k bytes body.
        Tempesta must forward DATA frame with 1k bytes and wait WindowUpdate from client.
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        client.update_initiate_settings(initial_window_size=1000)
        client.make_request(self.request_headers)

        self.assertTrue(
            client.wait_for_response(), "Tempesta ignored flow control window for stream."
        )
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )
