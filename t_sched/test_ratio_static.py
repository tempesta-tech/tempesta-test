"""
Test for ratio static scheduler. All servers has the same (default) weight.

Load must be distributed uniformly across all servers in the group.
All servers must receive almost the same number of requests, less than 0.5%
error is allowed. Enforce allowed error to 10 requests for short term tests.

Number of server connections doesn't affect load distribution, so test both:
- the same number of connections between all servers.
- random number of connections for each server.

Backend is configured to never close connections (keepalive_requests),
since it unpredictably affects load distribution.
"""

from framework import tester
from helpers import tf_cfg
from helpers.control import servers_get_stats

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 1000000000;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:${port};

        location / {
            root ${server_resources};
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 10000;

cache 0;
server ${server_ip}:8000;
server ${server_ip}:8001;
server ${server_ip}:8002;
server ${server_ip}:8003;
server ${server_ip}:8004;
server ${server_ip}:8005;
server ${server_ip}:8006;
server ${server_ip}:8007;
server ${server_ip}:8008;
server ${server_ip}:8009;

"""

# Random number of connections for each server.
TEMPESTA_CONFIG_VAR_CONNS = """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 10000;

cache 0;
server ${server_ip}:8000;
server ${server_ip}:8001 conns_n=5;
server ${server_ip}:8002 conns_n=30;
server ${server_ip}:8003 conns_n=6;
server ${server_ip}:8004 conns_n=12;
server ${server_ip}:8005 conns_n=33;
server ${server_ip}:8006 conns_n=4;
server ${server_ip}:8007 conns_n=2;
server ${server_ip}:8008 conns_n=10;
server ${server_ip}:8009 conns_n=12;

"""


class Ratio(tester.TempestaTest):
    """Use 'ratio static' scheduler with default weights. Load must be
    distributed equally across all servers.
    """

    # 10 backend servers, only difference between them - listen port.
    backends = [
        {
            "id": "nginx_8000",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8001",
            "type": "nginx",
            "port": "8001",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8002",
            "type": "nginx",
            "port": "8002",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8003",
            "type": "nginx",
            "port": "8003",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8004",
            "type": "nginx",
            "port": "8004",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8005",
            "type": "nginx",
            "port": "8005",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8006",
            "type": "nginx",
            "port": "8006",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8007",
            "type": "nginx",
            "port": "8007",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8008",
            "type": "nginx",
            "port": "8008",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8009",
            "type": "nginx",
            "port": "8009",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    clients = [
        {
            "id": "client",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    # Base precision to check the fairness.
    precision = 0.005
    # Minimum request count delta used for short term tests.
    min_delta = 10

    def test_load_distribution(self):
        """All servers must receive almost the same number of requests."""
        client = self.get_client("client")

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(client)

        tempesta = self.get_tempesta()
        servers = self.get_servers()
        tempesta.get_stats()
        servers_get_stats(servers)

        cl_reqs = tempesta.stats.cl_msg_forwarded
        s_reqs_expected = cl_reqs / len(servers)
        # On short running tests too small delta leads to false negatives.
        delta = max(self.precision * s_reqs_expected, self.min_delta)

        for srv in servers:
            tf_cfg.dbg(
                3,
                "Server %s received %d requests, [%d, %d] was expected"
                % (srv.get_name(), srv.requests, s_reqs_expected - delta, s_reqs_expected + delta),
            )
            self.assertAlmostEqual(
                srv.requests,
                s_reqs_expected,
                delta=delta,
                msg=(
                    "Server %s received %d requests, but [%d, %d] "
                    "was expected"
                    % (
                        srv.get_name(),
                        srv.requests,
                        s_reqs_expected - delta,
                        s_reqs_expected + delta,
                    )
                ),
            )


class RatioVariableConns(Ratio):
    """Same as base test, but now every server has the random number of
    connections.
    """

    tempesta = {"config": TEMPESTA_CONFIG_VAR_CONNS}

    def test_load_distribution(self):
        super(RatioVariableConns, self).test_load_distribution()
