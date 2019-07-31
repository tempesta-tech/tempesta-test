"""
TLS Stress tests - load Tempesta FW with multiple TLS connections.
"""
from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class StressTls(tester.TempestaTest):

    backends = [
        {
            'id' : '0',
            'type' : 'nginx',
            'check_ports' : [
                {
                    "ip" : "${server_ip}",
                    "port" : "8000",
                }
            ],
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : """
                pid ${pid};
                worker_processes    auto;
                events {
                    worker_connections 1024;
                    use epoll;
                }
                http {
                    keepalive_timeout ${server_keepalive_timeout};
                    keepalive_requests ${server_keepalive_requests};
                    sendfile        on;
                    tcp_nopush      on;
                    tcp_nodelay     on;
                    open_file_cache max=1000;
                    open_file_cache_valid 30s;
                    open_file_cache_min_uses 2;
                    open_file_cache_errors off;
                    error_log /dev/null emerg;
                    access_log off;
                    server {
                        listen       ${server_ip}:8000;
                        location / {
                            return 200;
                        }
                        location /nginx_status {
                            stub_status on;
                        }
                    }
                }
            """,
            }
        ]

    clients = [
        {
            'id' : '0',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:443",
            'ssl' : True,
        },
    ]

    tempesta = {
        'config' : """
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;

            # wrk sends IP address in SNI, so we test the option here.
            tls_match_any_server_name;

            server ${server_ip}:8000;
        """
    }

    def test(self):
        self.start_all_servers()
        self.start_tempesta()

        wrk = self.get_client('0')
        wrk.set_script("foo", content="")
        # Wrk can't handle very big amound of TLS connections.
        wrk.connections = min(
            int(tf_cfg.cfg.get('General', 'concurrent_connections')),
            100)
        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()

        self.assertTrue(wrk.statuses.has_key(200))
        self.assertGreater(wrk.statuses[200], 0)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
