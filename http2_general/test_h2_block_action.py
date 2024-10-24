"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import ConnectionInputs
from h2.errors import ErrorCodes
from h2.settings import SettingCodes
from hpack import HeaderTuple

import run_config
from http2_general.helpers import BlockActionH2Base, H2Base, generate_custom_error_page
from test_suite import marks


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

    def setup_sniffer_for_attack_reply(self, client):
        """
        In case of TCP segmentation and attack we can't be sure that
        kernel doesn't send TCP RST when we receive some data on the
        DEAD sock.
        """
        if self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY):
            """
            If response body size is less then INITIAL_WINDOW_SIZE
            we expect both TCP FIN and TCP RST. Kernel sends TCP RST
            when Tempesta receive WINDOW UPDATE frame on the DEAD sock.
            """
            self.save_must_fin_socks([client])
            self.save_must_reset_socks([client])
        else:
            """
            If INITIAL_WINDOW_SIZE is less then response body
            we expect only TCP FIN, because Tempesta FW sends TCP FIN
            when it closes connection even if some data was not sent.
            RST from the kernel can be send if client will have time
            to send WINDOW_UPDATE before receiving TCP FIN.
            """
            self.save_must_fin_socks([client])

    def check_sniffer_for_attack_reply(self, sniffer):
        if not run_config.TCP_SEGMENTATION:
            if self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY):
                self.check_fin_and_rst_in_sniffer(sniffer)
            else:
                sniffer.stop()
                self.assert_fin_socks(sniffer.packets)

    def check_last_error_response(self, client, expected_status_code, expected_goaway_code):
        """
        In case of TCP segmentation and attack we can't be sure that client
        receive response, because kernel send TCP RST to client when we
        receive some data on the DEAD sock. If INITIAL_WINDOW_SIZE is less then
        response body we also can't send response, because we need to process
        WINDOW_UPDATE frames, but can't do it on the DEAD sock.
        """
        if not run_config.TCP_SEGMENTATION and (
            self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY)
        ):
            self.assertTrue(client.wait_for_response())
            self.assertEqual(client.last_response.status, expected_status_code)
            self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
            self.assertIn(expected_goaway_code, client.error_codes)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        self.setup_sniffer_for_attack_reply(client)

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
        self.assertTrue(client.wait_for_connection_close())
        self.check_sniffer_for_attack_reply(sniffer)

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        self.save_must_not_fin_socks([client])
        self.save_must_not_reset_socks([client])

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
        self.assert_not_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def test_block_action_error_reply_with_conn_close(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
                HeaderTuple("Content-Type", "invalid"),
            ],
            expected_status_code="400",
        )
        self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
        self.assertTrue(client.wait_for_connection_close())

        self.check_fin_no_rst_in_sniffer(sniffer)

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
        self.setup_sniffer_for_attack_reply(client)

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
        self.assertTrue(client.wait_for_connection_close())
        self.check_sniffer_for_attack_reply(sniffer)


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
        self.save_must_reset_socks([client])
        self.save_must_not_fin_socks([client])

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
        self.check_rst_no_fin_in_sniffer(sniffer)

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        self.save_must_reset_socks([client])
        self.save_must_not_fin_socks([client])

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
        self.check_rst_no_fin_in_sniffer(sniffer)
