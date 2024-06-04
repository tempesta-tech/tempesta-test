"""The functional tests for `max_queued_control_frames` directive."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import time

from h2.settings import SettingCodes
from hyperframe.frame import HeadersFrame, PingFrame, PriorityFrame, SettingsFrame

from framework import tester
from framework.parameterize import param, parameterize
from helpers import dmesg


class TestH2ControlFramesFlood(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",  # "deproxy" for HTTP/1
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n" + "Content-Length: 200000\r\n\r\n" + ("a" * 200000)
            ),
        }
    ]

    tempesta = {
        "config": """
        keepalive_timeout 1000;
        listen 443 proto=h2;

        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }
        %s
        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }
        """
    }

    def __update_tempesta_config(self, limit: int) -> None:
        limit = "" if limit == 10000 else f"max_queued_control_frames {limit};"
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig % limit

    def __init_connection_and_disable_readable(self, client) -> None:
        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        self.assertTrue(client.wait_for_ack_settings())

        client.make_request(client.create_request(method="GET", headers=[]))
        client.readable = lambda: False  # disable socket for reading

    @parameterize.expand(
        [
            param(
                name="ping",
                frame=PingFrame(0, b"\x00\x01\x02\x03\x04\x05\x06\x07").serialize(),
            ),
            param(
                name="settings",
                frame=SettingsFrame(
                    settings={k: 100 for k in (SettingCodes.MAX_CONCURRENT_STREAMS,)}
                ).serialize(),
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, frame):
        self.__update_tempesta_config(100)

        client = self.get_client("deproxy")
        # Set a small buffer for the client. it is needed for stability of tests.
        # The different VMs have a different size of buffer
        client.add_socket_options(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

        self.start_all_services()
        # requests a large data from backend and disable socket for reading.
        # Tempesta can not send any data to the client until the client enable socket for reading
        self.__init_connection_and_disable_readable(client)

        # wait until the client buffer is full
        time.sleep(2)

        # the client should send more frames for stability of test
        for _ in range(110):  # max_queued_control_frames is 100.
            client.send_bytes(frame, expect_response=False)

        self.assertTrue(
            self.oops.find(
                "Warning: Too many control frames in send queue, closing connection",
                dmesg.amount_positive,
            ),
            "An unexpected number of dmesg warnings",
        )
        client.readable = lambda: True  # enable socket for reading
        self.assertTrue(
            client.wait_for_connection_close(),
            "TempestaFW did not block client after exceeding `max_queued_control_frames` limit.",
        )

    @parameterize.expand(
        [
            param(name="default_limit", limit=10000),
            param(name="100_limit", limit=100),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_reset_stream(self, name, limit: int):
        self.__update_tempesta_config(limit)

        client = self.get_client("deproxy")
        # Set a small buffer for the client. it is needed for stability of tests.
        # The different VMs have a different size of buffer
        client.add_socket_options(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

        self.start_all_services()
        # requests a large data from backend and disable socket for reading.
        # Tempesta can not send any data to the client until the client enable socket for reading
        self.__init_connection_and_disable_readable(client)

        # wait until the client buffer is full
        time.sleep(2)

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "tempesta-tech.com"),
            (":scheme", "https"),
        ]

        # the client should send more frames for stability of test
        for i in range(3, int(limit * 2.2), 2):
            hf = HeadersFrame(
                stream_id=i,
                data=client.h2_connection.encoder.encode(headers),
                flags=["END_HEADERS"],
            ).serialize()
            prio = PriorityFrame(stream_id=i, depends_on=i).serialize()
            client.send_bytes(hf + prio, expect_response=False)

        self.assertTrue(
            self.oops.find(
                "Warning: Too many control frames in send queue, closing connection",
                dmesg.amount_positive,
            ),
            "An unexpected number of dmesg warnings",
        )
        client.readable = lambda: True  # enable socket for reading
        self.assertTrue(
            client.wait_for_connection_close(),
            "TempestaFW did not block client after exceeding `max_queued_control_frames` limit.",
        )
