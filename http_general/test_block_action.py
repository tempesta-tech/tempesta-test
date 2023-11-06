"""Functional tests for http block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers import analyzer, asserts, remote


class BlockActionBase(tester.TempestaTest, asserts.Sniffer):
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
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta_tmpl = """
        listen 80;
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
        sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5, ports=(80,))
        sniffer.start()
        return sniffer


class BlockActionReply(BlockActionBase):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        tester.TempestaTest.setUp(self)

    def check_fin_and_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: bad.com\r\n\r\n",
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_and_rst_in_sniffer(sniffer)

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_not_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: good.com\r\nX-Forwarded-For: 1.1.1.1.1.1\r\n\r\n",
            expected_status_code="400",
        )

        self.assertFalse(client.connection_is_closed())

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: good.com\r\n\r\n",
            expected_status_code="200",
        )

        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets)
        self.assert_unreset_socks(sniffer.packets)

    def test_block_action_error_reply_multiple_requests(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_not_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.make_requests(
            requests=[
                f"GET / HTTP/1.1\r\nHost: good.com\r\nX-Forwarded-For: 1.1.1.1.1.1\r\n\r\n",
                f"GET / HTTP/1.1\r\nHost: good.com\r\n\r\n",
            ],
            pipelined=True,
        )
        client.wait_for_response()
        self.assertEqual(len(client.responses), 2)
        self.assertFalse(client.connection_is_closed())

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
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: frang.com\r\n\r\n",
            expected_status_code="200",
        )

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: frang.com\r\n\r\n",
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_and_rst_in_sniffer(sniffer)


class BlockActionDrop(BlockActionBase):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop"),
        }
        tester.TempestaTest.setUp(self)

    def check_fin_and_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_reset_socks(sniffer.packets)
        self.assert_not_fin_socks(sniffer.packets)

    def test_block_action_attack_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_reset_socks([client])
        self.save_must_not_fin_socks([client])

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost: bad.com\r\n\r\n",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)
        self.check_fin_and_rst_in_sniffer(sniffer)

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_reset_socks([client])
        self.save_must_not_fin_socks([client])

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost:\r\n\r\n",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)
        self.check_fin_and_rst_in_sniffer(sniffer)
