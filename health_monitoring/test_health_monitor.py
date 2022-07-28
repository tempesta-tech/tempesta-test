"""
Tests for health monitoring functionality.
"""

from __future__ import print_function
import re
import copy
import binascii
from access_log.test_access_log_h2 import backends
from framework import deproxy_client, tester
from helpers import deproxy, chains, tempesta, dmesg
import time
from access_log.common import AccessLogLine

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CHAIN_TIMEOUT = 100

TEMPESTA_CONFIG = """

server_failover_http 404 5 5;
server_failover_http 502 5 5;
server_failover_http 403 5 5;
cache 0;

health_check h_monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}


srv_group srv_grp1 {
        server ${tempesta_ip}:8080;
        server ${tempesta_ip}:8081;
        server ${tempesta_ip}:8082;

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
        listen        ${server_ip}:8080;

        location / {
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


NGINX_CONFIG1 = """
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
        listen        ${server_ip}:8081;

        location / {
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

NGINX_CONFIG2 = """
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
        listen        ${server_ip}:8082;

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
    1. Create one message chain for enabled HM server's state:
    404 response will be returning until configured limit is
    reached (at this time HM will disable the server).
    2. Create another message chain - for disabled HM state:
    502 response will be returning by Tempesta until HM
    request will be sent to server after configured
    timeout (200 response will be returned and HM will
    enable the server).
    3. Create five Stages with alternated two message chains:
    so five transitions 'enabled=>disabled/disabled=>enabled'
    must be passed through. Particular Stage objects are
    constructed in create_tester() method and then inserted
    into special StagedDeproxy tester.
    4. Each Stage must verify server's HTTP avalability state
    in 'check_transition()' method.
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
            'config' : NGINX_CONFIG % """

return 404;
""",
        },{
            'id' : 'nginx2',
            'type' : 'nginx',
            'port' : '8081',
            'status_uri' : 'http://${server_ip}:8081/nginx_status',
            'config' : NGINX_CONFIG1 % """

return 404;
""",        
        },{
            'id' : 'nginx3',
            'type' : 'nginx',
            'port' : '8082',
            'status_uri' : 'http://${server_ip}:8082/nginx_status',
            'config' : NGINX_CONFIG2 % """

return 200;
""",        
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

    count = 100
    def wait_for_server(self, srv):
        # srv.run_start()
        while not srv.is_running():
            print('asd')

    def run_curl(self, n=1):
        res = []
        for _ in range(n):
            curl = self.get_client('curl')
            curl.run_start()
            curl.proc_results = curl.resq.get(True, 1)
            res.append(int((curl.proc_results[0].decode("utf-8"))[:-1]))
        print(sorted(res))
        return res
        

    def test(self):
        """Test health monitor functionality with all new configuration
        directives and options.
        """
        self.start_tempesta()
        
        back1 = self.get_server('nginx1')
        back2 = self.get_server('nginx2')
        back3 = self.get_server('nginx3')
        res = self.run_curl(self.count)
        time.sleep(2)
        self.assertTrue(502 in res, "No 502 in statuses")
        
        print('start nginx1+2')
        back1.run_start()
        back2.run_start()
        time.sleep(1)
        # self.wait_for_server(back1)
        res = self.run_curl(self.count)
        self.assertTrue(502 in res and 404 in res, "Not valid status")
        
        print('start nginx1+2+3')
        back3.run_start()
        time.sleep(2)
        res = self.run_curl(self.count)
        self.assertTrue(200 in res, "Not valid status")
        
        print('stop nginx1+2')
        back1.stop_nginx()
        back2.stop_nginx()
        time.sleep(2)
        res = self.run_curl(self.count)
        self.assertTrue(404 not in res, "Not valid status")
        back3.stop_nginx()


# class TestHealthMonitorCRCOnly(TestHealthMonitor):
#     resp_codes_list = None
#     crc_check = True

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
