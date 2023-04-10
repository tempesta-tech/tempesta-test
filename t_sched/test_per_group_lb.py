"""
Test per group load balancers. Each server group has its own load balancer
and load balancer settings. This test covers following statements:

Group load balancers are not linked to each other, and load balancing is done
_inside_ group. Two different groups with different load balancing settings
are used in the test to confirm that behaviour.

A group scheduler can be defined explicitly or implicitly (according to current
defaults). This also called _inheritting of scheduler settings_. Each test case
have a description how the inheriting should work.
"""

from framework import tester
from framework.wrk_client import Wrk
from helpers import tf_cfg
from helpers.control import servers_get_stats

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

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
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;

${sched_global_opt}

srv_group custom {

    ${sched_custom_opt}
    server ${server_ip}:8000;
    server ${server_ip}:8001;
    server ${server_ip}:8002;
    server ${server_ip}:8003;
    server ${server_ip}:8004;
}

${sched_global_late_opt}

server ${server_ip}:8005;
server ${server_ip}:8006;
server ${server_ip}:8007;
server ${server_ip}:8008;
server ${server_ip}:8009;

vhost vhost_1 {
    proxy_pass custom;
}

vhost vhost_2 {
    proxy_pass default;
}

http_chain {
        hdr Host == "example.com" -> vhost_1;
         -> vhost_2;
        }

"""


class AllDefaults(tester.TempestaTest):
    """
    No explicit scheduler configuration. All server groups use default
    scheduler which is 'ratio static'.
    """

    # 10 backend servers, each has unique delay before send response.
    backends = [
        {
            "id": "nginx_8000",
            "type": "nginx",
            "port": "8000",
            "delay": "0",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8001",
            "type": "nginx",
            "port": "8001",
            "delay": "0.01",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8002",
            "type": "nginx",
            "port": "8002",
            "delay": "0.02",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8003",
            "type": "nginx",
            "port": "8003",
            "delay": "0.03",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8004",
            "type": "nginx",
            "port": "8004",
            "delay": "0.04",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8005",
            "type": "nginx",
            "port": "8005",
            "delay": "0.05",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8006",
            "type": "nginx",
            "port": "8006",
            "delay": "0.06",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8007",
            "type": "nginx",
            "port": "8007",
            "delay": "0.07",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8008",
            "type": "nginx",
            "port": "8008",
            "delay": "0.08",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8009",
            "type": "nginx",
            "port": "8009",
            "delay": "0.1",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    clients = [
        {
            "id": "client_vhost_1",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "client_vhost_2",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "sched_global_opt": "",
        "sched_custom_opt": "",
        "sched_global_late_opt": "",
        "config": TEMPESTA_CONFIG,
    }

    group_scheds = [("custom", "static"), ("default", "static")]

    # Base precision for ratio static.
    precision = 0.005
    # Minimum request count delta used for short term tests.
    min_delta = 10
    # Min server weight for ratio dynamic scheduler.
    min_server_weight = 30

    def check_static_lb(self, servers, group_name):
        """Group of servers use ratio static load balancer. For details
        see test_ratio_static.py .
        """
        exp_reqs = 0
        delta = 0

        for srv in servers:
            tf_cfg.dbg(3, "Server %s received %d requests" % (srv.get_name(), srv.requests))
            if not exp_reqs:
                exp_reqs = srv.requests
                delta = max(exp_reqs * self.precision, self.min_delta)
                continue
            self.assertAlmostEqual(
                srv.requests,
                exp_reqs,
                delta=delta,
                msg=(
                    "Server %s received %d requests, but [%d, %d] "
                    "was expected"
                    % (srv.get_name(), srv.requests, exp_reqs - delta, exp_reqs + delta)
                ),
            )
        tf_cfg.dbg(3, "Server group %s uses 'ratio static' scheduler" % (group_name))

    def check_dynamic_lb(self, servers, group_name):
        """Group of servers use ratio dynamic load balancer. For details
        see test_ratio_dynamic.py .
        """
        tot_weight = len(servers) * 50  # for weight normalisation.
        tot_reqs = 0
        for srv in servers:
            tot_reqs += srv.requests

        weights = [(srv.get_name(), 1.0 * srv.requests / tot_reqs * tot_weight) for srv in servers]
        weights.sort()

        prev_name, prev_weight = weights[0]
        for name, weight in weights:
            self.assertLessEqual(
                weight,
                prev_weight,
                msg=("Faster server %s got less weight than slower %s" % (prev_name, name)),
            )
            if weight <= self.min_server_weight:
                break
            prev_weight = weight
            prev_name = name

        tf_cfg.dbg(3, "Server group %s uses 'ratio dynamic' scheduler" % (group_name))

    def check_lb(self, group_name, lb_name):
        """
        Choose correct function to validate load distribution between servers.
        """
        group = []
        if group_name == "custom":
            group = [
                self.get_server("nginx_8000"),
                self.get_server("nginx_8001"),
                self.get_server("nginx_8002"),
                self.get_server("nginx_8003"),
                self.get_server("nginx_8004"),
            ]
        else:
            group = [
                self.get_server("nginx_8005"),
                self.get_server("nginx_8006"),
                self.get_server("nginx_8007"),
                self.get_server("nginx_8008"),
                self.get_server("nginx_8009"),
            ]

        if lb_name == "static":
            self.check_static_lb(group, group_name)
        else:
            self.check_dynamic_lb(group, group_name)

    def test_inherit(self):
        client_1 = self.get_client("client_vhost_1")
        client_2 = self.get_client("client_vhost_2")

        if isinstance(client_1, Wrk):
            client_1.options = ['-H "Host: example.com"']
        else:
            client_1.options[0] += ' -H "Host: example.com"'

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(client_1, client_2)

        servers = self.get_servers()
        servers_get_stats(servers)

        for group, lb_type in self.group_scheds:
            self.check_lb(group, lb_type)


class RedefineGlobalSched(AllDefaults):
    """
    Scheduler default is overridden and set to 'ratio dynamic'. Both server
    groups must use the 'ratio dynamic' scheduler.
    """

    tempesta = {
        "sched_global_opt": "sched ratio dynamic;",
        "sched_custom_opt": "",
        "sched_global_late_opt": "",
        "config": TEMPESTA_CONFIG,
    }

    group_scheds = [("custom", "dynamic"), ("default", "dynamic")]


class RedefineGroupSched(AllDefaults):
    """
    Global scheduler configuration is set to defaults, 'default' group
    must use 'ratio static' scheduler. Scheduler for group 'custom' is
    explicitly set as `ratio dynamic`.
    """

    tempesta = {
        "sched_global_opt": "",
        "sched_custom_opt": "sched ratio dynamic;",
        "sched_global_late_opt": "",
        "config": TEMPESTA_CONFIG,
    }

    group_scheds = [("custom", "dynamic"), ("default", "static")]


class RedefineAllScheds(AllDefaults):
    """
    Global scheduler configuration is set to 'ratio dynamic', default group
    must use is. Scheduler for group 'custom' is  explicitly set as
    `ratio static`.
    """

    tempesta = {
        "sched_global_opt": "sched ratio dynamic;",
        "sched_custom_opt": "sched ratio static;",
        "sched_global_late_opt": "",
        "config": TEMPESTA_CONFIG,
    }

    group_scheds = [("custom", "static"), ("default", "dynamic")]


class LateRedefineGlobalSched(AllDefaults):
    """
    Global scheduler configuration is set to 'ratio dynamic', default group
    must use it. But group 'custom' is defined before global scheduler settings
    was overridden. Thus server group 'custom' must use previous global
    scheduler configuration, which is 'ratio static'.
    """

    tempesta = {
        "sched_global_opt": "",
        "sched_custom_opt": "",
        "sched_global_late_opt": "sched ratio dynamic;",
        "config": TEMPESTA_CONFIG,
    }

    group_scheds = [("custom", "static"), ("default", "dynamic")]
