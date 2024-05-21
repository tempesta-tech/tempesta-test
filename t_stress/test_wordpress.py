"""
HTTP Stress tests with WordPress Docker image.
"""

import time
from pathlib import Path

from framework import tester
from helpers import remote, sysnet, tf_cfg
from t_stress.test_stress import CustomMtuMixin

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))


class BaseWorpressStress(CustomMtuMixin, tester.TempestaTest, base=True):
    tempesta_tmpl = """
        listen 443 proto=%s;
        server ${server_ip}:8000;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        frang_limits {
            http_strict_host_checking false;
        }
        tls_match_any_server_name;
        cache 0;
    """

    backends = [
        {
            "id": "wordpress",
            "type": "docker",
            "image": "wordpress",
            "ports": {8000: 80},
            "env": {
                "WP_HOME": "https://${tempesta_ip}/",
                "WP_SITEURL": "https://${tempesta_ip}/",
            },
        },
    ]

    clients = [
        {
            "id": "get_images",
            "type": "curl",
            "uri": f"/images/2048.jpg?ver=[1-{REQUESTS_COUNT}]",
            "ssl": True,
            "parallel": CONCURRENT_CONNECTIONS,
            "headers": {
                "Connection": "close",
            },
            "disable_output": True,
        },
    ]

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto),
        }
        super().setUp()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(5))

    def test_get_large_images(self):
        self.start_all()
        client = self.get_client("get_images")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertGreater(client.statuses[200], 0, "Client has not received 200 responses.")


class TlsWordpressStress(BaseWorpressStress):
    proto = "https"


class H2WordpressStress(BaseWorpressStress):
    proto = "h2"

    def setUp(self):
        self.clients = [{**client, "http2": True} for client in self.clients]
        super().setUp()
