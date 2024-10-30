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
listen 443 proto=h2,https;

# cache 2;
# cache_fulfill * *;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

srv_group main {server ${server_ip}:8000 conns_n=128;}

block_action attack reply;
block_action error reply;

frang_limits {
    http_methods get head post put;
}

vhost tempesta-tech.com {proxy_pass main;}

http_chain {
  -> tempesta-tech.com;
}
"""
    }

    backends = [
        {"id": "wordpress", "type": "lxc", "external_port": "8000"}
        #         {
        #             "id": "nginx",
        #             "type": "nginx",
        #             "port": "8000",
        #             "status_uri": "http://${server_ip}:8000/nginx_status",
        #             "config": """
        # pid ${pid};
        # worker_processes  auto;
        #
        # events {
        #     worker_connections   1024;
        #     use epoll;
        # }
        #
        # http {
        #     keepalive_timeout ${server_keepalive_timeout};
        #     keepalive_requests ${server_keepalive_requests};
        #     sendfile         on;
        #     tcp_nopush       on;
        #     tcp_nodelay      on;
        #
        #     open_file_cache max=1000;
        #     open_file_cache_valid 30s;
        #     open_file_cache_min_uses 2;
        #     open_file_cache_errors off;
        #     client_max_body_size 10000M;
        #
        #     # [ debug | info | notice | warn | error | crit | alert | emerg ]
        #     # Fully disable log errors.
        #     error_log /dev/null emerg;
        #
        #     # Disable access log altogether.
        #     access_log off;
        #
        #     server {
        #         listen        ${server_ip}:8000;
        #
        #         location / {
        #             return 200;
        #         }
        #         location /nginx_status {
        #             stub_status on;
        #         }
        #     }
        # }
        # """,
        #         },
    ]

    @dmesg.unlimited_rate_on_tempesta_node
    def test_default_tempesta_config(self):
        self.start_all_services(client=False)
        client = self.get_client("GET")

        client.options = [
            f"{MHDDOS_PATH} "
            + f"--url https://{tf_cfg.cfg.get('Tempesta', 'ip')}:443 "
            + f"--hostname tempesta-tech.com "
            + f"--threads {tf_cfg.cfg.get('General', 'stress_threads')} "
            + f"--conns {tf_cfg.cfg.get('General', 'concurrent_connections')} "
            + f"--rpc {tf_cfg.cfg.get('General', 'stress_requests_count')} "
            + f"--duration {DURATION} "
            + f"--interface {tf_cfg.cfg.get('Server', 'aliases_interface')}"
        ]

        client.start()
        self.assertTrue(client.wait_for_finish(timeout=DURATION + 5))
        client.stop()

        print(client.response_msg)

        tempesta = self.get_tempesta()
        tempesta.get_stats()
        print(tempesta.stats.__dict__)
