"""
Tests for correct parsing of some parts of http2 messages, such as headers.
For now tests run curl as external program capable to generate h2 messages and
analises its return code.
"""

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
            root ${server_resources};
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
"""

class HeadersParsing(tester.TempestaTest):
    '''Ask curl to make an h2 request, test failed if return code is not 0.
    '''

    clients = [
        {
            'id' : 'curl',
            'type' : 'external',
            'binary' : 'curl',
            'cmd_args' : (
                '-kf ' # Set non-null return code on 4xx-5xx responses.
                'https://${tempesta_ip}/ '
                )
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

    def test_random_header(self):
        curl = self.get_client('curl')
        # In tempesta-tech/tempesta#1412 an arbitrary header not known by
        # Tempesta and shorter than 4 characters caused request blocking,
        # check everything is fine.
        curl.options.append('-H "dnt: 1"')

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(curl)
