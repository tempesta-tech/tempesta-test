"""Test module for http2 and Sticky Cookie Scheduler."""
import http

from framework import tester
from helpers.response_parser import parse_response


class H2StickySchedulerTestCase(tester.TempestaTest):
    """Sticky Cookie H2 test case."""

    clients = [
        {
            'id': 'curl-init',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v --http2 https://good.com/',
        },
        {
            'id': 'curl-good',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v --http2 https://good.com/ -H "Cookie: BIGipServerwebapps-sea-7775=1695682732.24350.0000"',  # noqa:E501
        },
        {
            'id': 'curl-bad',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v --http2 https://bad.com/ -H "Cookie: BIGipServerwebapps-sea-7775=1695682732.24350.0000"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            listen 127.0.0.4:8765 proto=h2;

            srv_group default {
                server ${server_ip}:8000;
            }
            vhost default {
                proxy_pass default;
            }
            vhost good.com {
                proxy_pass default;
                sticky {
                    sticky_sessions;
                    cookie enforce;
                    secret "f00)9eR59*_/22";
                }
            }
            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            cache 0;
            cache_fulfill * *;
            block_action attack reply;
            http_chain {
                host == "bad.com"	-> block;
                host == "good.com" -> default;
            }
        """,
    }

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
        },
    ]

    def test_h2_cookie_scheduler(self):
        """
        Test for sticky cookie scheduler by issue.

        Cookies are taken from response.

        1. client request URI http://good.com/
        2. tempesta responds with 302 and sticky cookie TODO 200?
        3. client repeat the request with sticky cookie set
        4. tempesta forwards the request to server and
        forwards it's response to the client with 200
        5. client requests URI http://bad.com/ with sticky cookie set
        6. tempesta forwards the request to server and forwards it's response
        to the client test passed  TODO 302?

        No filtering out seen.

        """
        curl_init = self.get_client('curl-init')
        curl_good = self.get_client('curl-good')
        curl_bad = self.get_client('curl-bad')

        self.start_all_servers()
        self.start_tempesta()

        curl_init.start()
        self.wait_while_busy(curl_init)
        resp_init = parse_response(
            curl_init.resq.get(True, 1)[0].decode(),
        )
        self.assertEqual(
            resp_init.status,
            http.HTTPStatus.OK,
            'Expected http status {0}'.format(http.HTTPStatus.OK),
        )
        curl_init.stop()

        curl_good.start()
        self.wait_while_busy(curl_good)
        resp_good = parse_response(
            curl_good.resq.get(True, 1)[0].decode(),
        )
        self.assertEqual(
            resp_good.status,
            http.HTTPStatus.OK,
            'Expected http status {0}'.format(http.HTTPStatus.OK),
        )
        curl_good.stop()

        curl_bad.start()
        self.wait_while_busy(curl_bad)
        resp_bad = parse_response(
            curl_bad.resq.get(True, 1)[0],
        )
        self.assertEqual(
            resp_bad.status,
            http.HTTPStatus.FOUND,
            'Expected http status {0}'.format(http.HTTPStatus.FOUND),
        )
        curl_bad.stop()
