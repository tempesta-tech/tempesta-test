"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from hpack import HeaderTuple

from http2_general.helpers import BlockActionH2Base, H2Base, generate_custom_error_page
from test_suite import marks
from framework.deproxy_client import BaseDeproxyClient


@marks.parameterize_class(
    [
        {
            "name": "ReplyWithCustomErrorPage",
            "resp_tempesta_conf": "response_body 4* {0};",
            "ERROR_RESPONSE_BODY": "a" * 1000,
            "INITIAL_WINDOW_SIZE": 65535,
        },
        {
            "name": "ReplyWithCustomErrorPageSmallWindow",
            "resp_tempesta_conf": "response_body 4* {0};",
            "ERROR_RESPONSE_BODY": "a" * 1000,
            "INITIAL_WINDOW_SIZE": 100,
        },
    ]
)
class TestBlockActionH2(BlockActionH2Base):
    def setUp(self):
        path = generate_custom_error_page(self.ERROR_RESPONSE_BODY)
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply", self.resp_tempesta_conf.format(path)),
        }
        H2Base.setUp(self)

    def check_sniffer_for_attack_reply(self, sniffer, clients: list[BaseDeproxyClient]):
        self.check_fin_and_rst_in_sniffer(sniffer, clients)

    def check_last_error_response(self, client, expected_status_code, expected_goaway_code):
        if self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY):
            self.assertTrue(client.wait_for_response())
            self.assertEqual(client.last_response.status, expected_status_code)
            self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
            self.assertIn(expected_goaway_code, client.error_codes)
        else:
            self.assertFalse(client.wait_for_response())
        self.assertTrue(client.wait_for_connection_close())

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.make_request(
            request=[
                HeaderTuple(":authority", "bad.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
        )

        self.check_last_error_response(
            client, expected_status_code="403", expected_goaway_code=ErrorCodes.PROTOCOL_ERROR
        )

        self.check_sniffer_for_attack_reply(sniffer, [client])

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.send_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
                HeaderTuple("X-Forwarded-For", "1.1.1.1.1.1"),
            ],
            expected_status_code="400",
        )
        self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
        self.assertFalse(client.connection_is_closed())

        client.send_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="200",
        )

        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets, [client])
        self.assert_unreset_socks(sniffer.packets, [client])

    def test_block_action_error_reply_with_conn_close(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.make_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
                HeaderTuple("Content-Type", "invalid"),
            ],
        )
        self.check_last_error_response(
            client, expected_status_code="400", expected_goaway_code=ErrorCodes.PROTOCOL_ERROR
        )
        self.check_fin_no_rst_in_sniffer(sniffer, [client])

    def test_block_action_attack_reply_not_on_req_rcv_event(self):
        """
        Special test case when on_req_recv_event variable in C
        code is set to false, and connection closing is handled
        in the function which responsible for sending error
        response.
        """
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.send_request(
            request=[
                HeaderTuple(":authority", "frang.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="200",
        )

        client.make_request(
            request=[
                HeaderTuple(":authority", "frang.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
        )

        self.check_last_error_response(
            client, expected_status_code="403", expected_goaway_code=ErrorCodes.PROTOCOL_ERROR
        )

        self.check_fin_and_rst_in_sniffer(sniffer, [client])


class TestBlockActionH2Drop(BlockActionH2Base):
    INITIAL_WINDOW_SIZE = 65535

    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop", ""),
        }
        H2Base.setUp(self)

    def test_block_action_attack_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.make_request(
            request=[
                HeaderTuple(":authority", "bad.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)

        self.check_rst_no_fin_in_sniffer(sniffer, [client])

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)

        client.make_request(
            request=[
                HeaderTuple(":authority", ""),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            end_stream=False,
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)

        self.check_rst_no_fin_in_sniffer(sniffer, [client])
