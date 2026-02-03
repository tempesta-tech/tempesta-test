__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl
import time

import h2

from framework.helpers import tf_cfg
from framework.test_suite import tester


class TestH2Ping(tester.TempestaTest):
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

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as ssock:
                conn = h2.connection.H2Connection()
                window_size = 65535
                ping_data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
                ts = time.time()
                timeout = 5

                conn.initiate_connection()
                conn.ping(ping_data)
                ssock.sendall(conn.data_to_send())

                stream_ended, got_response = False, False
                while not stream_ended:
                    data = ssock.recv(window_size)
                    if not data:
                        break

                    events = conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.WindowUpdated):
                            window_size += event.delta
                        if isinstance(event, h2.events.PingAckReceived):
                            self.assertEqual(
                                ping_data,
                                event.ping_data,
                                "Received ping data doesn't match",
                            )
                            stream_ended, got_response = True, True
                            break
                        if isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                            stream_ended = True
                            break
                    self.assertTrue(
                        time.time() - ts < timeout,
                        f"Didn't get a PONG response in {timeout} sec, timed out",
                    )
                self.assertTrue(got_response, "Got no PONG response")
