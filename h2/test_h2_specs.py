from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

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
        listen        ${server_ip}:8000;

        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}

cache 0;

"""

class H2Spec(tester.TempestaTest):
    '''Tests for h2 proto implementation. Run h2spec utility against Tempesta.
    Simply check return code and warnings in system log for test errors.
    '''

    clients = [
        {
            'id' : 'h2spec',
            'type' : 'external',
            'binary' : 'h2spec',
            'ssl' : True,
            'cmd_args' : '-tkh ${tempesta_ip}'
        },
    ]

    backends = [
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'port' : '8000',
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : NGINX_CONFIG,
        }
    ]

    tempesta = {
        'config' : TEMPESTA_CONFIG,
    }

    def test_h2_specs(self):
        h2spec = self.get_client('h2spec')
        # TODO #88: for now run only simple test to check http2 connectivity
        # After all h2-related issues will be fixed, remove the line
        h2spec.options.append('generic/4')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(h2spec)

class H2Load(tester.TempestaTest):
    '''Tests for h2 proto implementation. Run h2load utility against Tempesta.
    Simply check return code and warnings in system log for test errors.
    '''

    clients = [
        {
            'id' : 'h2load',
            'type' : 'external',
            'binary' : 'h2load',
            'ssl' : True,
            'cmd_args' : ' https://${tempesta_ip} -D100'
        },
    ]

    backends = [
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'port' : '8000',
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : NGINX_CONFIG,
        }
    ]

    tempesta = {
        'config' : TEMPESTA_CONFIG,
    }

    def test_h2_specs(self):
        h2load = self.get_client('h2load')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(h2load)
