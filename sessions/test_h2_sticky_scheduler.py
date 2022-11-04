"""Test module for http2 and Sticky Cookie Scheduler."""
import http

from framework import tester
from helpers import dmesg
from helpers.response_parser import parse_response


class H2StickySchedulerTestCase(tester.TempestaTest):
    """Sticky Cookie H2 test case."""

    clients = [
        {
            'id': 'curl-init',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v --http2 https://${tempesta_ip}:8765/ -H "Host: good.com"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            listen ${tempesta_ip}:8765 proto=h2;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost v_good {
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
            cache 1;
            cache_fulfill * *;
            block_action attack reply;
            http_chain {
                host == "bad.com"	-> block;
                host == "good.com" -> v_good;
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

        1. client request URI with Host http://good.com/
        2. tempesta responds with 302 and sticky cookie
        3. client repeat the request with sticky cookie set
        4. tempesta forwards the request to server and
        forwards its response to the client with 200
        5. client requests URI with Host http://bad.com/ with sticky cookie set
        6. tempesta filtering out request

        """
        klog = dmesg.DmesgFinder()
        curl_init = self.get_client('curl-init')

        self.start_all_servers()
        self.start_tempesta()

        # perform `init` request
        curl_init.start()
        self.wait_while_busy(curl_init)
        resp_init = curl_init.resq.get(True, 1)[0]
        resp_init = parse_response(resp_init, encoding='latin-1')
        set_cookie = resp_init.headers.get('set-cookie')
        self.assertEqual(
            int(resp_init.status),
            int(http.HTTPStatus.FOUND),
            'Expected http status {0}'.format(http.HTTPStatus.FOUND),
        )
        self.assertTrue(set_cookie)
        curl_init.stop()

        # perform `good` request
        # we expected options length equal to one
        initial_curl_cmd = curl_init.options[0]
        curl_init.options[0] = '{0} -H "Cookie: {1}"'.format(
            initial_curl_cmd,
            set_cookie,
        )

        curl_init.start()
        self.wait_while_busy(curl_init)
        resp_good = curl_init.resq.get(True, 1)[0]
        resp_good = parse_response(resp_good, encoding='latin-1')

        self.assertEqual(
            resp_good.status,
            http.HTTPStatus.OK,
            'Expected http status {0}'.format(http.HTTPStatus.OK),
        )
        curl_init.stop()

        # perform `bad` request
        good_curl_cmd = curl_init.options[0]
        curl_init.options[0] = good_curl_cmd.replace(
            'good.com',
            'bad.com',
        )

        curl_init.start()
        self.wait_while_busy(curl_init)
        curl_init.resq.get(True, 1),
        curl_init.stop()

        # response structure is not standard, check for filtering out
        self.assertEqual(
            klog.warn_count(
                'request has been filtered out via http table',
            ),
            1,
            'Expected msg in `dmesg`',
        )
