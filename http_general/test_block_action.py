"""Functional tests for http block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import run_config
from framework import tester
from helpers import analyzer, asserts, deproxy, remote, tf_cfg
from helpers.custom_error_page import CustomErrorPageGenerator


class BlockActionBase(tester.TempestaTest, asserts.Sniffer):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
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

    def check_fin_no_rst_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        if not run_config.TCP_SEGMENTATION:
            self.assert_fin_socks(sniffer.packets)
            self.assert_unreset_socks(sniffer.packets)

    def check_rst_no_fin_in_sniffer(self, sniffer: analyzer.Sniffer) -> None:
        sniffer.stop()
        self.assert_reset_socks(sniffer.packets)
        self.assert_not_fin_socks(sniffer.packets)


class BlockActionReply(BlockActionBase):
    ERROR_RESPONSE_BODY = ""

    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        tester.TempestaTest.setUp(self)

    def check_last_error_response(self, client, expected_status_code):
        """
        In case of TCP segmentation and attack we can't be sure that client
        receive response, because kernel send TCP RST to client when we
        receive some data on the DEAD sock.
        """
        if not run_config.TCP_SEGMENTATION:
            self.assertTrue(client.wait_for_response())
            self.assertEqual(client.last_response.status, expected_status_code)
            self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost: bad.com\r\n\r\n",
        )
        self.check_last_error_response(client, expected_status_code="403")

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_no_rst_in_sniffer(sniffer)

    def test_block_action_error_reply_with_conn_close(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: good.com\r\nContent-Type: invalid\r\n\r\n",
            expected_status_code="400",
        )
        self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_no_rst_in_sniffer(sniffer)

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
        self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)

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

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost: frang.com\r\n\r\n",
        )
        self.check_last_error_response(client, expected_status_code="403")

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_no_rst_in_sniffer(sniffer)


class BlockActionReplyWithCustomErrorPage(BlockActionBase):
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
        response_body 4* %s;

        http_chain {
            host == "bad.com"   -> block;
            host == "good.com"  -> good;
            host == "frang.com" -> frang;
        }
    """

    ERROR_RESPONSE_BODY = "a" * 1000

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
        tester.TempestaTest.setUp(self)

    def test_block_action_error_reply_with_conn_close(self):
        client = self.get_client("deproxy")

        sniffer = self.setup_sniffer()
        self.start_all_services()
        self.save_must_fin_socks([client])
        self.save_must_not_reset_socks([client])

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: good.com\r\nContent-Type: invalid\r\n\r\n",
            expected_status_code="400",
        )
        self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)

        self.assertTrue(client.wait_for_connection_close())
        self.check_fin_no_rst_in_sniffer(sniffer)


class BlockActionDrop(BlockActionBase):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop"),
        }
        tester.TempestaTest.setUp(self)

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
        self.check_rst_no_fin_in_sniffer(sniffer)

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
        self.check_rst_no_fin_in_sniffer(sniffer)
