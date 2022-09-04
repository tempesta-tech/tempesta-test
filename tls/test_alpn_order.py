__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import ssl
import socket
from copy import deepcopy

from framework import tester
from helpers import tf_cfg


class TestALPNOrderBase(tester.TempestaTest, base=True):
    tempesta_template = {
        "config": """
        listen 443 proto=%(tempesta_proto)s;

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

    def setUp(self):
        self.tempesta = deepcopy(self.tempesta_template)
        self.tempesta["config"] = self.tempesta["config"] % {
            "tempesta_proto": getattr(self, "tempesta_proto", ""),
        }
        super(TestALPNOrderBase, self).setUp()

    def test(self):
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections())

        self.assertTrue(ssl.HAS_ALPN, "`ssl` library backend does not support ALPN")

        hostname = tf_cfg.cfg.get("Tempesta", "hostname")
        context = ssl.create_default_context()
        context.set_alpn_protocols(self.protocols)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(
                sock, server_hostname="tempesta-tech.com"
            ) as ssock:
                self.assertEqual(
                    ssock.selected_alpn_protocol(),
                    self.protocols[0],
                    "wrong protocol has been prioritized",
                )


class TestALPNOrderH1(TestALPNOrderBase):
    tempesta_proto = "https"
    protocols = ["http/1.1", "h2"]


class TestALPNOrderH2(TestALPNOrderBase):
    tempesta_proto = "h2"
    protocols = ["h2", "http/1.1"]
