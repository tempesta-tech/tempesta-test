"""Utils for wrong length tests"""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import tf_cfg
from helpers import checks_for_tests as checks


class TestContentLengthBase(TempestaTest, base=True):
    """Base class for checking length of request/response body."""
    backends = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': '',
        },
    ]

    tempesta = {
        'config': """
            listen 80;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost default {
                proxy_pass default;
            }

            cache 0;
            block_action error reply;
            block_action attack reply;
            """
    }

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': '${tempesta_ip}',
            'port': '80',
        },
    ]

    # request params
    request_method: str
    uri: str
    request_headers: str
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
        srv: StaticDeproxyServer = self.get_server('deproxy')
        srv.keep_alive = self.keep_alive
        self.start_all_services()

        client: DeproxyClient = self.get_client('deproxy')
        client.parsing = False

        response = (
            f'HTTP/1.1 {self.response_status}\r\n'
            + 'Connection: keep-alive\r\n'
            + 'Server: Deproxy Server\r\n'
            + f'{self.response_headers}\r\n'
            + f'{self.response_body}'
        )
        srv.set_response(response)

        client.send_request(
            request=(
                f'{self.request_method} {self.uri} HTTP/1.1\r\n'
                + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
                + f'{self.request_headers}\r\n'
                + f'{self.request_body}'
            ),
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
            'Server received unexpected number of requests.',
        )
