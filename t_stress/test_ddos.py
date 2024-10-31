__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os
import unittest

from helpers import dmesg, remote, tf_cfg
from test_suite import sysnet, tester

DURATION = int(tf_cfg.cfg.get("General", "duration"))
MHDDOS_DIR = os.path.join("tools/mhddos")
PROXY_PATH = f"{MHDDOS_DIR}/files/proxies/http.txt"
MHDDOS_PATH = f"{MHDDOS_DIR}/start.py"
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))
CONNS = int(tf_cfg.cfg.get("General", "concurrent_connections"))


# @unittest.skipIf(
#     TEMPESTA_IP.startswith("127."), "Please don't use loopback interface for this test."
# )
class TestDDoSL7(tester.TempestaTest):
    clients = [
        {
            "id": f"mhddos",
            "type": "external",
            "binary": "python3",
            "cmd_args": "",
        }
    ]

    tempesta = {
        "config": """
listen 443 proto=h2,https;

cache 2;
cache_fulfill * *;

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
        # {"id": "wordpress", "type": "lxc", "external_port": "8000"}
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
        pid ${pid};
        worker_processes  auto;

        events {
            worker_connections   1024;
            use epoll;
        }

        http {
            keepalive_timeout ${server_keepalive_timeout};
            keepalive_requests ${server_keepalive_requests};
            sendfile         on;
            tcp_nopush       on;
            tcp_nodelay      on;

            open_file_cache max=1000;
            open_file_cache_valid 30s;
            open_file_cache_min_uses 2;
            open_file_cache_errors off;
            client_max_body_size 10000M;

            # [ debug | info | notice | warn | error | crit | alert | emerg ]
            # Fully disable log errors.
            error_log /dev/null emerg;

            # Disable access log altogether.
            access_log off;

            server {
                listen        ${server_ip}:8000;

                location / {
                    return 200;
                }
                location /nginx_status {
                    stub_status on;
                }
            }
        }
        """,
        },
    ]

    proxies = []

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.addClassCleanup(cls.cleanup_proxies)

        interface = tf_cfg.cfg.get("Server", "aliases_interface")
        base_ip = tf_cfg.cfg.get("Server", "aliases_base_ip")
        client_ip = tf_cfg.cfg.get("Client", "ip")

        for n in range(THREADS * CONNS):
            (_, ip) = sysnet.create_interface(len(cls.proxies), interface, base_ip)
            sysnet.create_route(interface, ip, client_ip)
            cls.proxies.append(ip)

        ips_str = "\n".join(cls.proxies)
        remote.client.run_cmd(f'echo "{ips_str}" > {PROXY_PATH}')

    @classmethod
    def cleanup_proxies(cls):
        interface = tf_cfg.cfg.get("Server", "aliases_interface")
        sysnet.remove_routes(interface, cls.proxies)
        sysnet.remove_interfaces(interface, cls.proxies)

    @dmesg.limited_rate_on_tempesta_node
    def test_default_tempesta_config(self):
        self.start_all_services(client=False)
        client = self.get_client("mhddos")

        client.options = [
            f"{MHDDOS_PATH} "
            + f"--url https://{tf_cfg.cfg.get('Tempesta', 'ip')}:443 "
            + f"--hostname tempesta-tech.com "
            + f"--threads {THREADS} "
            + f"--conns {CONNS} "
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
