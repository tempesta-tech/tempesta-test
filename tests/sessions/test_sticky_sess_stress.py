"""
With sticky sessions each client is pinned to only one server in group.
"""

import sys

from framework.helpers import dmesg
from framework.services import tempesta
from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestStressStickyCookie(tester.TempestaTest):
    backends = [
        {
            "id": f"{i}",
            "type": "nginx",
            "status_uri": f"http://${{server_ip}}:{i}/nginx_status",
            "config": f"""
                pid ${{pid}};
                worker_processes    auto;
                events {{
                    worker_connections 1024;
                    use epoll;
                }}
                http {{
                    keepalive_timeout ${{server_keepalive_timeout}};
                    keepalive_requests {sys.maxsize};
                    sendfile        on;
                    tcp_nopush      on;
                    tcp_nodelay     on;
                    open_file_cache max=1000;
                    open_file_cache_valid 30s;
                    open_file_cache_min_uses 2;
                    open_file_cache_errors off;
                    error_log /dev/null emerg;
                    access_log off;
                    server {{
                        listen       ${{server_ip}}:{i};
                        location / {{
                            return 200;
                        }}
                        location /nginx_status {{
                            stub_status on;
                        }}
                    }}
                }}
            """,
        }
        for i in range(8000, 8000 + tempesta.servers_in_group())
    ]

    tempesta = {
        "config": """
sched ratio;
cache 0;
listen 80;
listen 443 proto=https;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

sticky {
   cookie enforce;
   secret "f00)9eR59*_/22";
   sticky_sessions;
}

frang_limits {http_strict_host_checking false;}
"""
        + "".join(
            [
                f"server ${{server_ip}}:{i};\n"
                for i in range(8000, 8000 + tempesta.servers_in_group())
            ]
        )
    }

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:443",
            "ssl": True,
        },
    ]

    @dmesg.limited_rate_on_tempesta_node
    def test_one_client(self):
        self.start_all_services(client=False)

        wrk = self.get_client("wrk")
        wrk.set_script("cookie-one-client")
        wrk.threads = 1

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()
        self.assertIsNotNone(wrk.statuses.get(200))

        for server in self.get_servers():
            server.get_stats()
        servers_with_requests = list(server for server in self.get_servers() if server.requests)
        self.assertEqual(len(servers_with_requests), 1, "Only one server must pull all the load.")

        # Positive allowance: this means some responses are missed by the client.
        # wrk does not wait for responses to last requests in each connection
        # before closing it and does not account for those requests.
        # So, [0; concurrent_connections] responses will be missed by the client.
        exp_max = wrk.statuses.get(200, 0) + wrk.connections
        exp_min = wrk.statuses.get(200, 0)

        self.assertTrue(
            exp_min <= servers_with_requests[0].requests <= exp_max,
            msg=(
                f"Number of requests forwarded to server ({servers_with_requests[0].requests}) "
                f"doesn't match expected value: [{exp_min}, {exp_max}]"
            ),
        )

    @dmesg.limited_rate_on_tempesta_node
    def test_many_clients(self):
        self.start_all_services(client=False)

        wrk = self.get_client("wrk")
        wrk.set_script("cookie-many-clients")
        wrk.threads = wrk.connections

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()
        self.assertIsNotNone(wrk.statuses.get(200))

        for server in self.get_servers():
            server.get_stats()

        servers_with_requests = list(server for server in self.get_servers() if server.requests)
        self.assertEqual(
            len(servers_with_requests),
            tempesta.servers_in_group(),
            "All server must pull all the load.",
        )

        # Positive allowance: this means some responses are missed by the client.
        # wrk does not wait for responses to last requests in each connection
        # before closing it and does not account for those requests.
        # So, [0; concurrent_connections] responses will be missed by the client.
        exp_max = wrk.statuses.get(200, 0) + wrk.connections
        exp_min = wrk.statuses.get(200, 0)
        servers_requests_sum = sum(list(server.requests for server in servers_with_requests))

        self.assertTrue(
            exp_min <= servers_requests_sum <= exp_max,
            msg=(
                f"Number of requests forwarded to server ({servers_requests_sum}) "
                f"doesn't match expected value: [{exp_min}, {exp_max}]"
            ),
        )
