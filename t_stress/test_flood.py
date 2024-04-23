__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl
import time
import unittest

import h2
from h2.settings import SettingCodes

from framework import tester
from helpers import tf_cfg


class TestH2ControlFramesFlood(tester.TempestaTest):
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

    def test_ping(self):
        self.oops_ignore = ["ERROR"]
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as ssock:
                conn = h2.connection.H2Connection()
                ping_data = b"\x00\x01\x02\x03\x04\x05\x06\x07"

                conn.initiate_connection()

                for _ in range(1000_0000):
                    conn.ping(ping_data)
                    try:
                        ssock.sendall(conn.data_to_send())
                    except ssl.SSLEOFError:
                        return
        self.oops.find(
            "ERROR: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )

    def test_settings(self):
        self.oops_ignore = ["ERROR"]
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        new_settings = dict()
        new_settings[SettingCodes.MAX_CONCURRENT_STREAMS] = 100

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as ssock:
                conn = h2.connection.H2Connection()
                conn.initiate_connection()

                for _ in range(1000_0000):
                    conn.update_settings(new_settings)
                    try:
                        ssock.sendall(conn.data_to_send())
                    except ssl.SSLEOFError:
                        return
        self.oops.find(
            "ERROR: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )

    def test_rst_stream_flood(self):
        self.start_all_services()
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())
        client = self.get_client("deproxy")
        client.h2_connection.encoder.huffman = True

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
                    s.sendall(hf + prio)
