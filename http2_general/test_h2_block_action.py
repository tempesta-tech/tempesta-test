"""Functional tests for h2 block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from http2_general.helpers import H2Base
from hpack import HeaderTuple
from h2.errors import ErrorCodes


class BlockActionH2Base(H2Base):
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

    def check_response(self, client, expected_status_code: str):
        self.assertIsNotNone(client.last_response, "Deproxy client has lost response.")
        assert expected_status_code in client.last_response.status, (
            f"HTTP response status codes mismatch. Expected - {expected_status_code}. "
            + f"Received - {client.last_response.status}"
        )


class BlockActionH2Reply(BlockActionH2Base):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        H2Base.setUp(self)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

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

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.make_request(
            request=[
                HeaderTuple(":authority", ""),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            end_stream=False,
        )

        self.assertTrue(client.wait_for_reset_stream(stream_id=client.stream_id))
        self.check_response(client, expected_status_code="400")
        self.assertFalse(client.connection_is_closed())

        client.stream_id += 2
        client.valid_req_num += 1

        client.send_request(
            request=[
                HeaderTuple(":authority", "good.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="200",
        )

    def test_block_action_attack_reply_not_on_req_rcv_event(self):
        """
        Special test case when on_req_recv_event variable in C
        code is set to false, and connection closing is handled
        in the function which responsible for sending error
        response.
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

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


class BlockActionH2Drop(BlockActionH2Base):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop"),
        }
        H2Base.setUp(self)

    def test_block_action_attack_drop(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

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

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

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
