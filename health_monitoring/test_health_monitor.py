"""
Tests for health monitoring functionality.
"""

from __future__ import print_function
from access_log.test_access_log_h2 import backends
from framework import tester


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

REQ_COUNT = 100

TEMPESTA_CONFIG = """

server_failover_http 404 50 5;
server_failover_http 502 50 5;
server_failover_http 403 50 5;
cache 0;

health_check h_monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}


srv_group srv_grp1 {
        server ${server_ip}:8080;
        server ${server_ip}:8081;
        server ${server_ip}:8082;

        health h_monitor1;
}

vhost srv_grp1{
        proxy_pass srv_grp1;
}

http_chain {
-> srv_grp1;
}
%s
"""

NGINX_CONFIG = """
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

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:%s;

        location / {
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestHealthMonitor(tester.TempestaTest):
    """ Test for health monitor functionality with stress option.
    Testing process is divided into several stages:
    1. Run tempesta-fw without backends
    2. Create two backends for enabled HM server's state:
    403/404 responses will be returned until the configured time limit is
    reached.
    3. Create a backend, which returns valid for HM response 200 code and ensure 
    that requested statuses are 404/403 until HM disables the old servers
    and responses become 502 for old / 200 for new
    4. Now 403/404 backends are marked unhealthy and must be gone
    """

    tempesta = {
        'config': TEMPESTA_CONFIG % "",
    }

    backends = [
        {
            'id' : 'nginx1',
            'type' : 'nginx',
            'port' : '8080',
            'status_uri' : 'http://${server_ip}:8080/nginx_status',
            'config' : NGINX_CONFIG % (8080, """

return 403;
"""),
        },{
            'id' : 'nginx2',
            'type' : 'nginx',
            'port' : '8081',
            'status_uri' : 'http://${server_ip}:8081/nginx_status',
            'config' : NGINX_CONFIG % (8081, """

return 404;
"""),
        },{
            'id' : 'nginx3',
            'type' : 'nginx',
            'port' : '8082',
            'status_uri' : 'http://${server_ip}:8082/nginx_status',
            'config' : NGINX_CONFIG % (8082, """

return 200;
"""),        
        }
    ]

    clients = [
        {
            'id': 'curl',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': (
                    ' -o /dev/null -s -w "%{http_code}\n" '
                    'http://${tempesta_ip}'
            )
        },
    ]


    def wait_for_server(self, srv):
        srv.start()
        while srv.state != 'started':
            pass
        srv.wait_for_connections()


    def run_curl(self, n=1):
        res = []
        for _ in range(n):
            curl = self.get_client('curl')
            curl.run_start()
            curl.proc_results = curl.resq.get(True, 1)
            res.append(int((curl.proc_results[0].decode("utf-8"))[:-1]))
        return res
        

    def test(self):
        """Test health monitor functionality with described stages"""
        self.start_tempesta()
        
        # 1
        back1 = self.get_server('nginx1')
        back2 = self.get_server('nginx2')
        back3 = self.get_server('nginx3')
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(list(set(res)) == [502], "No 502 in statuses")
        
        # 2
        self.wait_for_server(back1)
        self.wait_for_server(back2)
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [403, 404], "Not valid status")

        # 3
        self.wait_for_server(back3)
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [200, 403, 404, 502], "Not valid status")
        
        # 4
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [200, 502], "Not valid status")
        back3.stop()
