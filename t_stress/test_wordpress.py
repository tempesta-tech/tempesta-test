"""
HTTP Stress tests with WordPress LXC container.
"""

from helpers import tf_cfg
from helpers.networker import NetWorker
from run_config import CONCURRENT_CONNECTIONS, REQUESTS_COUNT
from test_suite import tester
from test_suite.marks import parameterize_class

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


@parameterize_class(
    [
        {"name": "Https", "proto": "https", "http2": False},
        {"name": "H2", "proto": "h2", "http2": True},
    ]
)
class TestWordpressStress(tester.TempestaTest):
    proto: str
    http2: bool
    tempesta_tmpl = """
        listen 443 proto=%s;
        server ${server_ip}:${server_website_port};
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        frang_limits {http_strict_host_checking false;}
        cache 0;
    """

    backends = [{"id": "wordpress", "type": "lxc"}]

    clients = [
        {
            "id": "get_images",
            "type": "curl",
            "uri": f"/wp-content/uploads/2023/10/tfw_wp_http2-1536x981.png?ver=[1-{REQUESTS_COUNT}]",
            "ssl": True,
            "parallel": CONCURRENT_CONNECTIONS,
            "headers": {
                "Connection": "close",
            },
            "disable_output": True,
        },
    ]

    def setUp(self):
        self.tempesta = {"config": self.tempesta_tmpl % (self.proto,)}
        self.clients = [{**client, "http2": self.http2} for client in self.clients]
        super().setUp()

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def test_get_large_images(self):
        self.start_all_services(client=False)
        client = self.get_client("get_images")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertGreater(client.statuses[200], 0, "Client has not received 200 responses.")
