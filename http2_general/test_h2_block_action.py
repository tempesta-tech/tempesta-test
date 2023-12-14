"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from h2.settings import SettingCodes, Settings
from hpack import HeaderTuple
from hyperframe.frame import (
    ContinuationFrame,
    DataFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    PriorityFrame,
    RstStreamFrame,
    SettingsFrame,
)

import run_config
from framework.custom_error_page import CustomErrorPageGenerator
from framework.deproxy_client import HuffmanEncoder
from helpers import analyzer, asserts, remote, tf_cfg
from http2_general.helpers import H2Base


class BlockActionH2Base(H2Base, asserts.Sniffer):
    tempesta_tmpl = """
        listen 443 proto=h2;
        srv_group default {
            server ${server_ip}:8000;
        }
        vhost good {
            proxy_pass default;
        }
        vhost frang {
            frang_limits {
                http_methods GET;
                http_resp_code_block 200 1 10;
            }
            proxy_pass default;
        }
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        block_action attack %s;
        block_action error %s;
        http_chain {
            host == "bad.com"   -> block;
            host == "good.com"  -> good;
            host == "frang.com" -> frang;
        }
    """

    @staticmethod
    def setup_sniffer() -> analyzer.Sniffer:
        sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5, ports=(443,))
        sniffer.start()
        return sniffer


class BlockActionH2Reply(BlockActionH2Base):
    ERROR_RESPONSE_BODY = ""
    INITIAL_WINDOW_SIZE = 65535

    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        H2Base.setUp(self)

    def check_fin_no_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def check_rst_no_fin_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets)
        self.assert_reset_socks(sniffer.packets)

    def check_fin_and_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_reset_socks(sniffer.packets)
        self.assert_fin_socks(sniffer.packets)

    def setup_sniffer_for_attack_reply(self, client):
        """
        In case of TCP segmentation and attack we can't be sure that
        kernel doesn't send TCP RST when we receive some data on the
        DEAD sock.
        """
        if not run_config.TCP_SEGMENTATION:
            if len(self.ERROR_RESPONSE_BODY) == 0:
                self.save_must_fin_socks([client])
                self.save_must_not_reset_socks([client])
            elif self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY):
                self.save_must_fin_socks([client])
                self.save_must_reset_socks([client])
            else:
                self.save_must_not_fin_socks([client])
                self.save_must_reset_socks([client])

    def check_sniffer_for_attack_reply(self, sniffer):
        if not run_config.TCP_SEGMENTATION:
            if len(self.ERROR_RESPONSE_BODY) == 0:
                self.check_fin_no_rst_in_sniffer(sniffer)
            elif self.INITIAL_WINDOW_SIZE > len(self.ERROR_RESPONSE_BODY):
                self.check_fin_and_rst_in_sniffer(sniffer)
            else:
                self.check_rst_no_fin_in_sniffer(sniffer)

    def start_services_and_initiate_conn(self, client):
        self.start_all_services()

        client.update_initial_settings(initial_window_size=self.INITIAL_WINDOW_SIZE)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta foes not returns SETTINGS frame with ACK flag.",
        )

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
        self.assertEqual(client._last_response.body, self.ERROR_RESPONSE_BODY)
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
        self.assertEqual(client._last_response.body, self.ERROR_RESPONSE_BODY)
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


class BlockActionH2ReplyWithCustomErrorPage(BlockActionH2Reply):
    tempesta_tmpl = """
        listen 443 proto=h2;
        srv_group default {
            server ${server_ip}:8000;
        }
        vhost good {
            proxy_pass default;
        }
        vhost frang {
            frang_limits {
                http_methods GET;
                http_resp_code_block 200 1 10;
            }
            proxy_pass default;
        }
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        block_action attack %s;
        block_action error %s;
        response_body 4* %s;

        http_chain {
            host == "bad.com"   -> block;
            host == "good.com"  -> good;
            host == "frang.com" -> frang;
        }
    """

    ERROR_RESPONSE_BODY = "a" * 1000
    INITIAL_WINDOW_SIZE = 65535

    def __generate_custom_error_page(self, data):
        workdir = tf_cfg.cfg.get("General", "workdir")
        cpage_gen = CustomErrorPageGenerator(data=data, f_path=f"{workdir}/4xx.html")
        path = cpage_gen.get_file_path()
        remote.tempesta.copy_file(path, data)

        return path

    def setUp(self):
        path = self.__generate_custom_error_page(self.ERROR_RESPONSE_BODY)
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply", path),
        }
        H2Base.setUp(self)


class BlockActionH2ReplyWithCustomErrorPageSmallWindow(BlockActionH2ReplyWithCustomErrorPage):
    ERROR_RESPONSE_BODY = "a" * 1000
    INITIAL_WINDOW_SIZE = 100

    def test_block_action_error_reply_with_conn_close_multiple_requests(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        good_req = [
            HeaderTuple(":authority", "good.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "GET"),
        ]
        curr_responses = len(client.responses)

        client.make_requests(
            requests=[
                [
                    HeaderTuple(":authority", "good.com"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("Content-Type", "invalid"),
                ],
                good_req,
                good_req,
                good_req,
            ]
        )
        client.wait_for_response(3)

        self.assertEqual(curr_responses + 1, len(client.responses))
        self.assertEqual(client._last_response.status, "400")
        self.assertEqual(client._last_response.body, self.ERROR_RESPONSE_BODY)
        self.assertTrue(client.wait_for_connection_close())

        self.check_fin_no_rst_in_sniffer(sniffer)

    """
    Check that all frames except WINDOW_UPDATE are ignored after connection
    is closed by shutdown.
    """

    def __test_block_action_error_reply_with_conn_close_frames(self, frame, expected_response=True):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        if expected_response:
            self.save_must_fin_socks([client])
            self.save_must_not_reset_socks([client])

        curr_responses = len(client.responses)

        client.make_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
                HeaderTuple("Content-Type", "invalid"),
            ]
        )

        client.send_bytes(frame.serialize() if isinstance(frame, Frame) else frame)
        client.wait_for_response(3)

        if expected_response:
            self.assertEqual(curr_responses + 1, len(client.responses))
            self.assertEqual(client._last_response.status, "400")
            self.assertEqual(client._last_response.body, self.ERROR_RESPONSE_BODY)
            self.assertTrue(client.wait_for_connection_close())
            self.check_fin_no_rst_in_sniffer(sniffer)

    def test_block_action_error_reply_with_conn_close_data(self):
        frame = DataFrame(stream_id=1, data=b"request body")
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_good_priority(self):
        frame = PriorityFrame(stream_id=1)
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_rst(self):
        frame = RstStreamFrame(stream_id=1)
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_settings(self):
        new_settings = dict()
        new_settings[SettingCodes.INITIAL_WINDOW_SIZE] = 0
        frame = SettingsFrame(0)
        frame.settings = new_settings
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_goaway(self):
        frame = GoAwayFrame(0)
        frame.last_stream_id = 12
        frame.error_code = 3
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_headers(self):
        encoder = HuffmanEncoder()
        frame = HeadersFrame(
            stream_id=100,
            data=encoder.encode(self.post_request),
            flags=["END_HEADERS", "END_STREAM"],
        )
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_continuation(self):
        encoder = HuffmanEncoder()
        request_segment_2 = [("header", "header_value")]
        frame = ContinuationFrame(
            100,
            encoder.encode(request_segment_2),
            flags={"END_HEADERS"},
        )
        self.__test_block_action_error_reply_with_conn_close_frames(frame)

    def test_block_action_error_reply_with_conn_close_garbage(self):
        frame = b"\x00\x0f\x0f\x0f\xff"
        self.__test_block_action_error_reply_with_conn_close_frames(frame, expected_response=False)


class BlockActionH2Drop(BlockActionH2Base):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop"),
        }
        H2Base.setUp(self)

    def check_fin_and_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_reset_socks(sniffer.packets)
        self.assert_not_fin_socks(sniffer.packets)

    def test_block_action_attack_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.initiate_h2_connection(client)
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
        self.check_fin_and_rst_in_sniffer(sniffer)

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.initiate_h2_connection(client)
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
        self.check_fin_and_rst_in_sniffer(sniffer)
