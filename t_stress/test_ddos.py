__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os
import unittest

from helpers import dmesg, tf_cfg
from test_suite import tester

DURATION = int(tf_cfg.cfg.get("General", "duration"))
MHDDOS_DIR = os.path.join("tools/mhddos")
PROXY_PATH = f"{MHDDOS_DIR}/files/proxies/http.txt"
MHDDOS_PATH = f"{MHDDOS_DIR}/start.py"


# @unittest.skipIf(
#     TEMPESTA_IP.startswith("127."), "Please don't use loopback interface for this test."
# )
class TestDDoSL7(tester.TempestaTest):
    L7_METHODS_ = [
        "GET",
        "POST",
        "OVH",
        "RHEX",
        "STOMP",
        "STRESS",
        "DYN",
        "DOWNLOADER",
        "SLOW",
        "HEAD",
        "NULL",
        "COOKIE",
        "PPS",
        "EVEN",
        "GSB",
        "DGB",
        "AVB",
        "BOT",
        "APACHE",
        "XMLRPC",
        "CFB",
        "CFBUAM",
        "BYPASS",
        "KILLER",
        "TOR",
    ]
    invalid_methods = ["BOMB"]

    L7_METHODS = ["GET"]

    clients = [
        {
            "id": f"{method}",
            "type": "external",
            "binary": "python3",
            "cmd_args": "",
        }
        for method in L7_METHODS
    ]

    tempesta = {
        "config": """
#cache 0;
#cache_fulfill * *;
#cache_methods GET HEAD;
#cache_ttl 3600;

#listen 443 proto=https;
listen 80;

server ${server_ip}:8000 conns_n=128;
        """
    }

    backends = [{"id": "wordpress", "type": "lxc", "external_port": "8000"}]

    @dmesg.unlimited_rate_on_tempesta_node
    def test_ddos_post_method(self):
        self.start_all_services(client=False)
        client = self.get_client("GET")

        client.options = [
            f"{MHDDOS_PATH} "
            + f"--url http://{tf_cfg.cfg.get('Tempesta', 'ip')}:80 "
            + f"--threads {tf_cfg.cfg.get('General', 'stress_threads')} "
            + f"--conns {tf_cfg.cfg.get('General', 'concurrent_connections')} "
            + f"--rpc {tf_cfg.cfg.get('General', 'stress_requests_count')} "
            + f"--duration {DURATION} "
            + f"--interface {tf_cfg.cfg.get('Server', 'aliases_interface')}"
        ]

        client.start()
        self.assertTrue(client.wait_for_finish(timeout=DURATION + 2))
        client.stop()

        print(client.response_msg)

        tempesta = self.get_tempesta()
        tempesta.get_stats()
        print(tempesta.stats.__dict__)
