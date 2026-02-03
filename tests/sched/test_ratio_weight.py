"""
Test for ratio static scheduler. Each server has random weight.
Difference from test_ratio_static.py: each server has random weight.

Load between servers must be distributed according to theirs weight. The
bigger weight server has, the more requests it should receive. Manually
calculate resulting weight for every server, according to number of received
requests. Resulted weigh must be almost equal the weight defined in
the configuration file.

The calculated weight may be slightly different from the defined one, allowed
error is:
- 10% if server weight is (30, 100],
- 20% if server weight is (10, 30],
- 40% if server weight is (0, 10].

Number of server connections doesn't affect load distribution, so test both:
- the same number of connections between all servers.
- random number of connections for each server.

Backend is configured to never close connections (keepalive_requests),
since it unpredictably affects load distribution.
"""

from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
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
server ${server_ip}:8001 weight=50;
server ${server_ip}:8002 weight=5;
server ${server_ip}:8003 weight=20;
server ${server_ip}:8004 weight=30;
server ${server_ip}:8005 weight=44;
server ${server_ip}:8006 weight=22;
server ${server_ip}:8007 weight=80;
server ${server_ip}:8008 weight=100;
server ${server_ip}:8009 weight=10;
frang_limits {http_strict_host_checking false;}
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
server ${server_ip}:8001 weight=50 conns_n=5;
server ${server_ip}:8002 weight=5 conns_n=30;
server ${server_ip}:8003 weight=20 conns_n=6;
server ${server_ip}:8004 weight=30 conns_n=12;
server ${server_ip}:8005 weight=44 conns_n=33;
server ${server_ip}:8006 weight=22 conns_n=4;
server ${server_ip}:8007 weight=80 conns_n=2;
server ${server_ip}:8008 weight=100 conns_n=10;
server ${server_ip}:8009 weight=10 conns_n=12;
frang_limits {http_strict_host_checking false;}
"""


def sched_ratio_static_def_weight():
    return 50


class Ratio(tester.TempestaTest):
    """Ratio static scheduler with random weight of every server."""

    # 10 backend servers, only difference between them - listen port.
    backends = [
        {
            "id": "nginx_8000",
            "type": "nginx",
            "port": "8000",
            "weight": "50",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8001",
            "type": "nginx",
            "port": "8001",
            "weight": "50",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8002",
            "type": "nginx",
            "port": "8002",
            "weight": "5",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8003",
            "type": "nginx",
            "port": "8003",
            "weight": "20",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8004",
            "type": "nginx",
            "port": "8004",
            "weight": "30",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8005",
            "type": "nginx",
            "port": "8005",
            "weight": "44",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8006",
            "type": "nginx",
            "port": "8006",
            "weight": "22",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8007",
            "type": "nginx",
            "port": "8007",
            "weight": "80",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8008",
            "type": "nginx",
            "port": "8008",
            "weight": "100",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8009",
            "type": "nginx",
            "port": "8009",
            "weight": "10",
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
    precision = 0.1

    def test_load_distribution(self):
        """Manually calculate resulted weight of every server and compare with
        definded in configuration.
        """
        client = self.get_client("client")

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        self.wait_while_busy(client)

        tempesta = self.get_tempesta()
        servers = self.get_servers()

        tempesta.get_stats()
        for srv in servers:
            srv.get_stats()

        cl_reqs = tempesta.stats.cl_msg_forwarded
        tot_weight = 0
        def_weight = sched_ratio_static_def_weight()
        for srv in servers:
            tot_weight += srv.weight if srv.weight else def_weight

        for srv in servers:
            exp_weight = srv.weight if srv.weight else def_weight
            calc_weight = 1.0 * srv.requests / cl_reqs * tot_weight

            prec = self.precision
            if exp_weight <= 30:
                prec *= 2
            if exp_weight <= 10:
                prec *= 2

            s_reqs_expected = cl_reqs * exp_weight / tot_weight
            delta = prec * s_reqs_expected

            self.assertAlmostEqual(
                calc_weight,
                exp_weight,
                delta=(exp_weight * prec),
                msg=(
                    "Server %s calculated weight is %f, but %d was expected"
                    % (srv.get_name(), calc_weight, exp_weight)
                ),
            )


class RatioVariableConns(Ratio):
    """Same as base test, but now every server has the random number of
    connections.
    """

    tempesta = {"config": TEMPESTA_CONFIG_VAR_CONNS}

    def test_load_distribution(self):
        super(RatioVariableConns, self).test_load_distribution()
