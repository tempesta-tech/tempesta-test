"""
Ratio scheduler is fast and fair scheduler based on weighted round-robin
principle. Functional test for Ratio scheduler requires intensive loads to
evaluate how fair the load distribution is.
"""

from framework import tester
from helpers.control import servers_get_stats
from helpers import tf_cfg

NGINX_CONFIG = """
load_module /usr/lib/nginx/modules/ngx_http_echo_module.so;

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
            echo_sleep ${delay};
            echo_exec @default;
        }
        location @default {
            root ${server_resources};
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
cache 0;

sched ${sched_opts};
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

def sched_ratio_static_def_weight():
    return 50


class Ratio(tester.TempestaTest):
    """Use 'ratio predict' scheduler with default The faster server is the
    more load it get. In dynamic or prediction mode load balancing between
    servers only predictable, if they have the same number of connections.
    This behaviour is different from ratio static mode.
    """

    # 10 backend servers, each has unique delay before send response.
    backends = [
        {
            'id' : 'nginx_8000',
            'type' : 'nginx',
            'port' : '8000',
            'delay' : '0',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8001',
            'type' : 'nginx',
            'port' : '8001',
            'delay' : '0.05',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8002',
            'type' : 'nginx',
            'port' : '8002',
            'delay' : '0.1',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8003',
            'type' : 'nginx',
            'port' : '8003',
            'delay' : '0.15',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8004',
            'type' : 'nginx',
            'port' : '8004',
            'delay' : '0.2',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8005',
            'type' : 'nginx',
            'port' : '8005',
            'delay' : '0.25',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8006',
            'type' : 'nginx',
            'port' : '8006',
            'delay' : '0.3',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8007',
            'type' : 'nginx',
            'port' : '8007',
            'delay' : '0.35',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8008',
            'type' : 'nginx',
            'port' : '8008',
            'delay' : '0.4',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8009',
            'type' : 'nginx',
            'port' : '8009',
            'delay' : '0.5',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
    ]

    clients = [
        {
            'id' : 'wrk',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        'sched_opts' : "ratio predict",
        'config' : TEMPESTA_CONFIG,
    }

    def check_weight(self, sid_fast, sid_slow):
        slow_srv = self.get_server(sid_slow)
        fast_srv = self.get_server(sid_fast)

        # Request rate in this test is low, ignore servers which doesn't
        # get enough requests to configure the balancer effectively.
        if min(slow_srv.weight, fast_srv.weight) < 30:
            return
        self.assertLessEqual(
            slow_srv.weight, fast_srv.weight,
            msg=("Faster server %s got less weight than slower %s"
                 % (sid_fast, sid_slow))
        )

    def check_load(self):
        tempesta = self.get_tempesta()
        servers = self.get_servers()
        tempesta.get_stats()
        servers_get_stats(servers)

        cl_reqs = tempesta.stats.cl_msg_forwarded
        tot_weight = len(servers) * 50  # for weight normalisation

        for srv in servers:
            calc_weight = 1.0 * srv.requests / cl_reqs * tot_weight
            srv.weight = calc_weight
            tf_cfg.dbg(3,
                       "Server %s received %d responses, got weight %d"
                       % (srv.get_name(), srv.requests, calc_weight)
                      )

        self.check_weight('nginx_8008', 'nginx_8009')
        self.check_weight('nginx_8007', 'nginx_8008')
        self.check_weight('nginx_8006', 'nginx_8007')
        self.check_weight('nginx_8005', 'nginx_8006')
        self.check_weight('nginx_8004', 'nginx_8005')
        self.check_weight('nginx_8003', 'nginx_8004')
        self.check_weight('nginx_8002', 'nginx_8003')
        self.check_weight('nginx_8001', 'nginx_8002')
        self.check_weight('nginx_8000', 'nginx_8001')

    def test_load_distribution(self):
        wrk = self.get_client('wrk')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        self.wait_while_busy(wrk)
        self.check_load()


class RatioMin(Ratio):

    tempesta = {
        'sched_opts' : "ratio predict minimum",
        'config' : TEMPESTA_CONFIG
    }


class RatioMax(Ratio):

    tempesta = {
        'sched_opts' : "ratio predict maximum",
        'config' : TEMPESTA_CONFIG
    }


class RatioAv(Ratio):

    tempesta = {
        'sched_opts' : "ratio predict average",
        'config' : TEMPESTA_CONFIG
    }


class RatioPerc(Ratio):

    tempesta = {
        'sched_opts' : "ratio predict percentile",
        'config' : TEMPESTA_CONFIG
    }
