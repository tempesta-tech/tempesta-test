"""Functional tests for http block action error/attack behavior."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class BlockActionBase(tester.TempestaTest):
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

    def check_response(self, client, expected_status_code: str):
        self.assertIsNotNone(client.last_response, "Deproxy client has lost response.")
        assert expected_status_code in client.last_response.status, (
            f"HTTP response status codes mismatch. Expected - {expected_status_code}. "
            + f"Received - {client.last_response.status}"
        )


class BlockActionReply(BlockActionBase):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply"),
        }
        tester.TempestaTest.setUp(self)

    def test_block_action_attack_reply(self):
        client = self.get_client("deproxy")

        self.start_all_services()

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: bad.com\r\n\r\n",
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())

    def test_block_action_error_reply(self):
        client = self.get_client("deproxy")

        self.start_all_services()

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost:\r\n\r\n",
            expected_status_code="400",
        )

        self.assertFalse(client.connection_is_closed())

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: good.com\r\n\r\n",
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

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: frang.com\r\n\r\n",
            expected_status_code="200",
        )

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: frang.com\r\n\r\n",
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())


class BlockActionDrop(BlockActionBase):
    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % ("drop", "drop"),
        }
        tester.TempestaTest.setUp(self)

    def test_block_action_attack_drop(self):
        client = self.get_client("deproxy")

        self.start_all_services()

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost: bad.com\r\n\r\n",
            expected_status_code="403",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)

    def test_block_action_error_drop(self):
        client = self.get_client("deproxy")

        self.start_all_services()

        client.make_request(
            request=f"GET / HTTP/1.1\r\nHost:\r\n\r\n",
            expected_status_code="400",
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIsNone(client.last_response)
