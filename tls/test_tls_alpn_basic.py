__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl

from framework import tester
from framework.parameterize import param, parameterize, parameterize_class
from helpers import dmesg, tf_cfg


class TestALPN(tester.TempestaTest):
    tempesta_template = {
        "config": """
        listen 443 proto=%(tempesta_proto)s;

        tls_match_any_server_name;

        srv_group default {
            server %(server_ip)s:8000;
        }

        vhost tempesta-tech.com {
           tls_certificate %(work_dir)s/tempesta.crt;
           tls_certificate_key %(work_dir)s/tempesta.key;
           proxy_pass default;
        }
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
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
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 10\r\n"
            "Connection: keep-alive\r\n\r\n"
            "0123456789",
        }
    ]

    def init_config(self, proto):
        self.get_tempesta().config.set_defconfig(
            self.tempesta_template["config"]
            % {
                "tempesta_proto": proto,
                "work_dir": tf_cfg.cfg.get("General", "workdir"),
                "server_ip": tf_cfg.cfg.get("Server", "ip"),
            }
        )

    @parameterize.expand(
        [
            param(
                name="order_https",
                tempesta_proto="https",
                protocols=["http/1.1", "h2"],
            ),
            param(
                name="order_h2",
                tempesta_proto="h2",
                protocols=["h2", "http/1.1"],
            ),
            param(
                name="mixed_https",
                tempesta_proto="https,h2",
                protocols=["http/1.1"],
            ),
            param(
                name="mixed_h2",
                tempesta_proto="https,h2",
                protocols=["h2"],
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_proto(self, name, tempesta_proto, protocols):
        self.init_config(tempesta_proto)
        self.start_tempesta()

        self.assertTrue(ssl.HAS_ALPN, "`ssl` library backend does not support ALPN")

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        context = ssl.create_default_context()
        context.set_alpn_protocols(protocols)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname="tempesta-tech.com") as ssock:
                self.assertEqual(
                    ssock.selected_alpn_protocol(),
                    protocols[0],
                    "wrong protocol has been prioritized",
                )

    @parameterize.expand(
        [
            param(
                name="https",
                tempesta_proto="https",
                protocols=["h2"],
                msg="ClientHello: cannot find matching ALPN for h2",
            ),
            param(
                name="h2",
                tempesta_proto="h2",
                protocols=["http/1.1"],
                msg="ClientHello: cannot find matching ALPN for http/1.1",
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_negative(self, name, tempesta_proto, protocols, msg):
        """
        Try to establish handshake with unsupported protocol in ALPN protocols list. Tempesta
        must not finish handshake successfully.
        """
        self.init_config(tempesta_proto)
        self.start_tempesta()

        self.assertTrue(ssl.HAS_ALPN, "`ssl` library backend does not support ALPN")

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        context = ssl.create_default_context()
        context.set_alpn_protocols(protocols)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443)) as sock:
            try:
                ssock = context.wrap_socket(sock, server_hostname="tempesta-tech.com")
            except:
                pass

        self.assertTrue(
            self.oops.find(msg, cond=dmesg.amount_positive),
            "Can't find expected error",
        )

    def test_alpn_default(self):
        """
        Send request to Tempesta h2/h1 listener using empty ALPN. Tempesta must choose HTTP1 by
        default.
        """
        self.init_config("https,h2")
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.deproxy_manager.start()
        self.start_tempesta()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=1), "No connection from Tempesta to backends"
        )
        self.start_all_clients()

        client = self.get_client("deproxy")
        client.make_request("GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")
        res = client.wait_for_response(timeout=3)
        status = client.last_response.status
        # Verify ALPN didn't use.
        self.assertTrue(client.socket.selected_alpn_protocol() == None)
        self.assertEqual(status, "200", "Wrong response status: %s" % status)
