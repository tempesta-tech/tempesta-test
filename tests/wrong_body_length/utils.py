"""Utils for wrong length tests"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.deproxy_server import StaticDeproxyServer
from helpers import tf_cfg
from test_suite import checks_for_tests as checks
from test_suite.tester import TempestaTest


class TestContentLengthBase(TempestaTest, base=True):
    """Base class for checking length of request/response body."""

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2;
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            
            server ${server_ip}:8000;
            
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
            }

            cache 0;
            block_action error reply;
            block_action attack reply;
            """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    # request params
    request_method: str
    uri: str
    request_headers: str or list
    request_body: str

    # response params
    response_status: str
    response_headers: str
    response_body: str
    keep_alive: int

    # expected params for check
    expected_response_status: str
    cl_msg_parsing_errors: int
    srv_msg_parsing_errors: int
    cl_msg_other_errors: int
    srv_msg_other_errors: int
    expected_requests_to_server: int

    def _test(self):
        """
        Send request with correct or incorrect data to server and check if response have been
        received.
        """
        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.keep_alive = self.keep_alive
        self.start_all_services()

        client: DeproxyClient = self.get_client("deproxy")
        client.parsing = False

        response = (
            f"HTTP/1.1 {self.response_status}\r\n"
            + "Server: Deproxy Server\r\n"
            + f"{self.response_headers}\r\n"
            + f"{self.response_body}"
        )
        srv.set_response(response)

        if isinstance(client, DeproxyClientH2):
            headers = [
                (":authority", "localhost"),
                (":path", self.uri),
                (":scheme", "https"),
                (":method", self.request_method),
            ]
            headers.extend(self.request_headers)
            request = (headers, self.request_body) if self.request_body else headers
        elif isinstance(client, DeproxyClient):
            request = (
                f"{self.request_method} {self.uri} HTTP/1.1\r\n"
                + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
                + f"{self.request_headers}\r\n"
                + f"{self.request_body}"
            )

        client.send_request(
            request=request,
            expected_status_code=self.expected_response_status,
        )

        checks.check_tempesta_error_stats(
            tempesta=self.get_tempesta(),
            cl_msg_parsing_errors=self.cl_msg_parsing_errors,
            cl_msg_other_errors=self.cl_msg_other_errors,
            srv_msg_other_errors=self.srv_msg_other_errors,
            srv_msg_parsing_errors=self.srv_msg_parsing_errors,
        )
        self.assertEqual(
            self.expected_requests_to_server,
            len(srv.requests),
            "Server received unexpected number of requests.",
        )


class H2Config:
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
