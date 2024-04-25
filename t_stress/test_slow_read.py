__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl
import time
import unittest
from threading import Thread

import h2
from h2.settings import SettingCodes, Settings
from hyperframe.frame import HeadersFrame, PriorityFrame, WindowUpdateFrame

from framework import tester
from framework.parameterize import param, parameterize
from helpers import deproxy, tf_cfg
from t_long_body import utils


class TestH2SlowRead(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",  # "deproxy" for HTTP/1
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    tempesta = {
        "config": """
        cache 0;
        keepalive_timeout 60;
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
                # CVE-2019-9517 “Internal Data Buffering”
                name="tcp",
            ),
            param(
                # CVE-2019-9511 “Data Dribble”
                name="data",
            ),
        ]
    )
    def test(self, name):
        # self.oops_ignore = ["ERROR"]

        self.start_all_services()

        server: deproxy_server.StaticDeproxyServer = self.get_server("deproxy")
        BODY_SIZE = 1024 * 1024 * 100
        body = "x" * BODY_SIZE
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Content-Length: {BODY_SIZE}\r\n"
            + "\r\n"
            + body
        )

        client = self.get_client("deproxy")
        client.h2_connection.encoder.huffman = True

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "tempesta-tech.com"),
            (":scheme", "https"),
        ]
        headers_data = client.h2_connection.encoder.encode(headers)

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        if name == "data":

            def run_test():
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2"])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.keylog_filename = "secrets.txt"

                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as s:
                        c = h2.connection.H2Connection()
                        settings = dict()
                        settings[SettingCodes.INITIAL_WINDOW_SIZE] = 1
                        c.local_settings = Settings(initial_values=settings)
                        c.local_settings.update(settings)
                        c.initiate_connection()
                        s.sendall(c.data_to_send())

                        for i in range(1, 190, 2):
                            c.send_headers(i, headers, end_stream=True)
                            s.sendall(c.data_to_send())

                        response_stream_ended = False

                        while not response_stream_ended:
                            # read raw data from the socket
                            data = s.recv(65536 * 1024)
                            if not data:
                                break

                            # feed raw data into h2, and process resulting events
                            events = c.receive_data(data)
                            for event in events:
                                if isinstance(event, h2.events.DataReceived):
                                    # update flow control so the server doesn't starve us
                                    c.acknowledge_received_data(
                                        event.flow_controlled_length, event.stream_id
                                    )
                                    win = WindowUpdateFrame(event.stream_id, 1).serialize()
                                    s.sendall(win)
                                    time.sleep(0.003)
                                if isinstance(event, h2.events.StreamEnded):
                                    # response body completed, let's exit the loop
                                    response_stream_ended = True
                                    break
                            # send any pending data to the server
                            s.sendall(c.data_to_send())

        elif name == "tcp":

            def run_test():
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2"])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port)) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16)
                    with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as s:
                        c = h2.connection.H2Connection()
                        settings = dict()
                        settings[SettingCodes.INITIAL_WINDOW_SIZE] = (1 << 31) - 10
                        c.local_settings = Settings(initial_values=settings)
                        c.local_settings.update(settings)
                        c.initiate_connection()
                        s.sendall(c.data_to_send())

                        for i in range(1, 190, 2):
                            hf = HeadersFrame(
                                stream_id=i,
                                data=headers_data,
                                flags=["END_HEADERS", "END_STREAM"],
                            ).serialize()
                            s.sendall(hf)

                        time.sleep(63)

        parallel = 3
        plist = []
        for _ in range(parallel):
            p = Thread(target=run_test, args=())
            p.start()
            plist.append(p)
        for p in plist:
            p.join()
