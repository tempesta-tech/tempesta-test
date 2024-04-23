__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random
import socket
import ssl
import string
import time
import unittest
from threading import Thread

import h2

from framework import tester
from helpers import tf_cfg
from http2_general.helpers import H2Base


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


class TestH2HeaderLeak(H2Base):
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

    def test(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        port = 443

        def run_test():
            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2"])
            context.check_hostname = False
            context.keylog_filename = "secrets.txt"
            context.verify_mode = ssl.CERT_NONE

            headers = [
                (":method", "GET"),
                (":path", "/"),
                (":authority", "tempesta-tech.com"),
                (":scheme", "https"),
            ]

            # memory leak even after the connection closed, if too many big headers
            for _ in range(50):
                headers.append((randomword(100), randomword(100)))

            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as s:
                    c = h2.connection.H2Connection()
                    c.initiate_connection()
                    s.sendall(c.data_to_send())

                    # memory grow until OOM even if one active stream at one time
                    for i in range(1, 100_0000, 2):
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
                                if isinstance(event, h2.events.StreamEnded):
                                    # response body completed, let's exit the loop
                                    response_stream_ended = True
                                    break
                            # send any pending data to the server
                            s.sendall(c.data_to_send())

        parallel = 30
        plist = []
        for _ in range(parallel):
            p = Thread(target=run_test, args=())
            p.start()
            plist.append(p)
        for p in plist:
            p.join()
