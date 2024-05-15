__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl

import h2
from h2.settings import SettingCodes
from hyperframe.frame import HeadersFrame, PingFrame, PriorityFrame, SettingsFrame

from framework import tester
from framework.parameterize import param, parameterize
from helpers import tf_cfg


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
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
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

        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }
        """
    }

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
    def test(self, name, frame):
        self.oops_ignore = ["WARNING"]
        self.start_all_services()

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as ssock:
                conn = h2.connection.H2Connection()
                conn.initiate_connection()

                for _ in range(1000_0000):
                    try:
                        ssock.sendall(frame)
                    except ssl.SSLEOFError:
                        return
        self.oops.find(
            "Warning: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )

    def test_reset_stream(self):
        self.oops_ignore = ["WARNING"]
        self.start_all_services()
        client = self.get_client("deproxy")

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "tempesta-tech.com"),
            (":scheme", "https"),
        ]

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as s:
                c = h2.connection.H2Connection()
                c.initiate_connection()
                s.sendall(c.data_to_send())

                for i in range(1, 100_0000, 2):
                    hf = HeadersFrame(
                        stream_id=i,
                        data=client.h2_connection.encoder.encode(headers),
                        flags=["END_HEADERS"],
                    ).serialize()
                    prio = PriorityFrame(stream_id=i, depends_on=i).serialize()
                    try:
                        s.sendall(hf + prio)
                    except ssl.SSLEOFError:
                        return
        self.oops.find(
            "Warning: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )
