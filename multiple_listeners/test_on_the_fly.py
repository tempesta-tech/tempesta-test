"""TestCase for change Tempesta config on the fly."""
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

WRK_SCRIPT = 'conn_close'  # with header 'connection: close'
STATUS_OK = 200

SOCKET_START = ('127.0.0.4:8282',)
SOCKET_AFTER_RELOAD = ('127.0.1.5:7654',)


class TestOnTheFly(tester.TempestaTest):

    backends = [
        {
            'id': 'nginx',
            'type': 'nginx',
            'port': '8000',
            'status_uri': 'http://${server_ip}:8000/nginx_status',
            'config': """
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
                    error_log /dev/null emerg;
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
            """,
        }
    ]

    clients = [
        {
            'id': 'wrk-127.0.0.4:8282',
            'type': 'wrk',
            'addr': '127.0.0.4:8282'
        },
        {
            'id': 'curl-127.0.0.4:8282',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf http://127.0.0.4:8282/'
        },
        {
            'id': 'wrk-127.0.1.5:7654',
            'type': 'wrk',
            'addr': '127.0.1.5:7654'
        },
        {
            'id': 'curl-127.0.1.5:7654',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf http://127.0.1.5:7654/'
        },
    ]

    tempesta = {
        'config': """

            listen 127.0.0.4:8282;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost tempesta-cat {
                proxy_pass default;
            }

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;

            http_chain {
                -> tempesta-cat;
            }

        """
    }

    tempesta_after_reload = {
        'config': tempesta['config']
    }

    for soc in range(0, len(SOCKET_START)):
        try:
            tempesta_after_reload['config'] = tempesta_after_reload['config'].replace(SOCKET_START[soc],
                                                                                      SOCKET_AFTER_RELOAD[soc])
        except IndexError:
            pass

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()

    def test_change_config_on_the_fly(self):
        """
        Test Tempesta for change config on the fly.

        Start Tempesta with one config - start wrk -
            - reload Tempesta with new config -
            - start new wrk
        """
        self.start_all()

        tempesta = self.get_tempesta()

        for soc_start in SOCKET_START:
            wrk = self.get_client('wrk-{0}'.format(soc_start))
            wrk.set_script(WRK_SCRIPT)
            wrk.start()
            # TODO self.wait_while_busy(wrk)

            self.assertIn(
                'listen {0};'.format(soc_start),
                tempesta.config.get_config(),
            )

        # check reload sockets not in config
        for soc_reload in SOCKET_AFTER_RELOAD:
            self.assertRaises(
                Exception,
                self.make_curl_request,
                'curl-{0}'.format(soc_reload)
            )
            self.assertNotIn(
                'listen {0};'.format(soc_reload),
                tempesta.config.get_config(),
            )

        # change config and reload Tempesta
        tempesta.config.defconfig = self.tempesta_after_reload['config']
        tempesta.reload()

        # check old sockets  not in config
        for soc_start in SOCKET_START:
            self.assertRaises(
                Exception,
                self.make_curl_request,
                'curl-{0}'.format(soc_start)
            )
            self.assertNotIn(
                'listen {0};'.format(soc_start),
                tempesta.config.get_config(),
            )

        for soc_reload in SOCKET_AFTER_RELOAD:
            wrk_after = self.get_client('wrk-{0}'.format(soc_reload))
            wrk_after.set_script(WRK_SCRIPT)
            wrk_after.start()
            self.wait_while_busy(wrk_after)
            wrk_after.stop()
            self.assertIn(
                STATUS_OK,
                wrk_after.statuses,
            )
            self.assertGreater(
                wrk_after.statuses[STATUS_OK],
                0,
            )

            self.assertIn(
                'listen {0};'.format(soc_reload),
                tempesta.config.get_config(),
            )

    def make_curl_request(self, curl_client_id: str):
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        """
        curl = self.get_client(curl_client_id)
        curl.start()
        self.wait_while_busy(curl)
        response = curl.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl.stop()
