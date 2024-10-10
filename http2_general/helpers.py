__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import deproxy_client
from helpers.deproxy import HttpMessage
from test_suite import tester


class H2Base(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost good {
                frang_limits {http_strict_host_checking false;}
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            http_max_header_list_size 134217728; #128 KB
            
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    post_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    get_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def initiate_h2_connection(self, client: deproxy_client.DeproxyClientH2):
        # add preamble + settings frame with default variable into data_to_send
        client.update_initial_settings()
        # send preamble + settings frame to Tempesta
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta foes not returns SETTINGS frame with ACK flag.",
        )
