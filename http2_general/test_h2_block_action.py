"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from hpack import HeaderTuple

from helpers import analyzer, asserts, remote
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
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        H2Base.setUp(self)

    def check_fin_and_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.initiate_h2_connection(client)
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=[
                HeaderTuple(":authority", "bad.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)
        self.check_fin_and_rst_in_sniffer(sniffer)

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.initiate_h2_connection(client)
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

    def test_block_action_attack_reply_not_on_req_rcv_event(self):
        """
        Special test case when on_req_recv_event variable in C
        code is set to false, and connection closing is handled
        in the function which responsible for sending error
        response.
        """
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.initiate_h2_connection(client)
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=[
                HeaderTuple(":authority", "frang.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="200",
        )

        client.send_request(
            request=[
                HeaderTuple(":authority", "frang.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)
        self.check_fin_and_rst_in_sniffer(sniffer)


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
