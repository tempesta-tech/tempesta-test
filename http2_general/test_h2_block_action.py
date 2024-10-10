"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from h2.settings import SettingCodes
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
from framework.deproxy_client import HuffmanEncoder
from helpers import analyzer, remote, tf_cfg
from http2_general.helpers import H2Base
from test_suite import asserts, custom_error_page
from test_suite.parameterize import param, parameterize, parameterize_class


def generate_custom_error_page(data):
    workdir = tf_cfg.cfg.get("General", "workdir")
    cpage_gen = custom_error_page.CustomErrorPageGenerator(data=data, f_path=f"{workdir}/4xx.html")
    path = cpage_gen.get_file_path()
    remote.tempesta.copy_file(path, data)
    return path


class BlockActionH2Base(H2Base, asserts.Sniffer):
    tempesta_tmpl = """
        listen 443 proto=h2;
        srv_group default {
            server ${server_ip}:8000;
        }
        frang_limits {http_strict_host_checking false;}
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
        %s

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

    def check_no_fin_no_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def start_services_and_initiate_conn(self, client):
        self.start_all_services()

        client.update_initial_settings(initial_window_size=self.INITIAL_WINDOW_SIZE)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta foes not returns SETTINGS frame with ACK flag.",
        )


@parameterize_class(
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
class BlockActionH2(BlockActionH2Base):
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


class BlockActionH2ReplyFramesAfterShutdownWithCustomErrorPageSmallWindow(BlockActionH2Base):
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
    INITIAL_WINDOW_SIZE = 100

    def setUp(self):
        path = generate_custom_error_page(self.ERROR_RESPONSE_BODY)
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply", path),
        }
        H2Base.setUp(self)

    """
    Check that all frames except WINDOW_UPDATE are ignored after connection
    is closed by shutdown.
    """

    @parameterize.expand(
        [
            param(
                name="data_frame",
                frame=DataFrame(stream_id=1, data=b"request body"),
                expected_response=True,
            ),
            param(
                name="priority_frame",
                frame=PriorityFrame(stream_id=1),
                expected_response=True,
            ),
            param(
                name="rst_frame",
                frame=RstStreamFrame(1),
                expected_response=True,
            ),
            param(
                name="settings_frame",
                frame=SettingsFrame(stream_id=0, settings={SettingCodes.INITIAL_WINDOW_SIZE: 0}),
                expected_response=True,
            ),
            param(
                name="goaway_frame",
                frame=GoAwayFrame(stream_id=0, last_stream_id=12, error_code=3),
                expected_response=True,
            ),
            param(
                name="headers_frame",
                frame=HeadersFrame(
                    stream_id=100,
                    data=HuffmanEncoder().encode(H2Base.post_request),
                    flags=["END_HEADERS", "END_STREAM"],
                ),
                expected_response=True,
            ),
            param(
                name="continuation_frame",
                frame=ContinuationFrame(
                    100,
                    HuffmanEncoder().encode([("header", "header_value")]),
                    flags={"END_HEADERS"},
                ),
                expected_response=True,
            ),
            param(
                name="garbage",
                frame=b"\x00\x0f\x0f\x0f\xff",
                expected_response=False,
            ),
        ]
    )
    def test_block_action_error_reply_with_conn_close(self, name, frame, expected_response):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_services_and_initiate_conn(client)
        if expected_response:
            self.save_must_fin_socks([client])
            self.save_must_not_reset_socks([client])
        else:
            self.save_must_not_fin_socks([client])
            self.save_must_not_reset_socks([client])

        curr_responses = len(client.responses)

        client.make_request(
            client.create_request(
                method="GET", authority="good.com", headers=[("Content-Type", "invalid")]
            )
        )

        client.send_bytes(
            frame.serialize() if isinstance(frame, Frame) else frame,
            expect_response=expected_response,
        )

        if expected_response:
            self.assertTrue(client.wait_for_connection_close())
            self.assertIsNotNone(client.last_response)
            self.assertEqual(client.last_response.status, "400")
            self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
            self.check_fin_no_rst_in_sniffer(sniffer)
        else:
            self.assertFalse(client.wait_for_connection_close())
            self.assertIsNone(client.last_response)
            self.check_no_fin_no_rst_in_sniffer(sniffer)


class BlockActionH2Drop(BlockActionH2Base):
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
