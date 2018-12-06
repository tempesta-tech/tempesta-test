"""
Ratio scheduler is fast and fair scheduler based on weighted round-robin
principle. Functional test for Ratio scheduler requires intensive loads to
evaluate how fair the load distribution is.
"""

from framework import tester
from helpers.control import servers_get_stats
from helpers import tf_cfg

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

"""

TEMPESTA_CONFIG_VAR_CONNS = """
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

"""

def sched_ratio_static_def_weight():
    return 50


class Ratio(tester.TempestaTest):
    """Use 'ratio static' scheduler with default weights. Load must be
    distributed equally across all servers.
    """

    # 10 backend servers, only difference between them - listen port.
    backends = [
        {
            'id' : 'nginx_8000',
            'type' : 'nginx',
            'port' : '8000',
            'weight' : '50',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8001',
            'type' : 'nginx',
            'port' : '8001',
            'weight' : '50',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8002',
            'type' : 'nginx',
            'port' : '8002',
            'weight' : '5',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8003',
            'type' : 'nginx',
            'port' : '8003',
            'weight' : '20',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8004',
            'type' : 'nginx',
            'port' : '8004',
            'weight' : '30',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8005',
            'type' : 'nginx',
            'port' : '8005',
            'weight' : '44',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8006',
            'type' : 'nginx',
            'port' : '8006',
            'weight' : '22',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8007',
            'type' : 'nginx',
            'port' : '8007',
            'weight' : '80',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8008',
            'type' : 'nginx',
            'port' : '8008',
            'weight' : '100',
            'status_uri' : 'http://${server_ip}:${port}/nginx_status',
            'config' : NGINX_CONFIG,
        },
        {
            'id' : 'nginx_8009',
            'type' : 'nginx',
            'port' : '8009',
            'weight' : '10',
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
        'config' : TEMPESTA_CONFIG,
    }

    # Base precision to check the fairness.
    precision = 0.1

    def check_fair_load(self):
        """ Manually calculate resulted weight of every server and compare with
        definded in configuration.
        """
        tempesta = self.get_tempesta()
        servers = self.get_servers()
        tempesta.get_stats()
        servers_get_stats(servers)

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

            tf_cfg.dbg(3,
                       "Server %s with weight %d received %d responses; "
                       "calculated weight is %f, [%d, %d] requests was expected"
                       % (srv.get_name(), exp_weight, srv.requests,
                          calc_weight,
                          s_reqs_expected - delta,
                          s_reqs_expected + delta)
                      )
            self.assertAlmostEqual(
                calc_weight, exp_weight, delta=(exp_weight * prec),
                msg=("Server %s calculated weight is %f, but %d was expected"
                     % (srv.get_name(), calc_weight, exp_weight)
                    )
                )

    def test_load_distribution(self):
        wrk = self.get_client('wrk')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        self.wait_while_busy(wrk)
        self.check_fair_load()


class RatioVariableConns(Ratio):
    """ 'ratio static' scheduler with default weights. Each server has random
    connection number. Load distributed between servers according to theirs
    weights, not number of connections, thus different connection count doesn't
    affect load distribution.
    """

    tempesta = {
        'config' : TEMPESTA_CONFIG_VAR_CONNS
    }
