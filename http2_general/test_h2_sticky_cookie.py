"""Test module for http2 and Sticky Cookie."""
from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


nginx_backend = {
    "id": "nginx",
    "type": "nginx",
    "port": "8000",
    "status_uri": "http://${server_ip}:8000/nginx_status",
    "config": """
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


class H2StickyCookieBaseTestCase(tester.TempestaTest):
    """Sticky Cookie H2 test case."""

    clients = [
        {
            "id": "curl-1",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": '-Ikf -v --http2 https://${tempesta_ip}:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:8765 proto=h2;

            sticky {
                cookie name=__test;
            }

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
        """,
    }

    backends = [
        nginx_backend,
    ]

    def test_h2_cookie_default(self):
        """Check for presents `set-cookie` header."""
        curl = self.get_client("curl-1")

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        response = curl.response_msg
        self.assertIn(
            "set-cookie",
            response,
            "Expected header `set-cookie` in response",
        )
        # cookie name `__test` set up in settings
        self.assertIn(
            "__test",
            response,
            "Expected cookie name in response",
        )


class H2StickyCookieTestCase(tester.TempestaTest):
    """Test case to check cookies' behavior."""

    clients = [
        {
            "id": "curl-2",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": '-Ikf -v --http2 https://${tempesta_ip}:8765/ -H "Host: tempesta-tech.com:8765" -H "Cookie: name1=value1" -H "Cookie: name2=value2"',  # noqa:E501
        },
        {
            "id": "curl-3",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": '-Ikf -v --http2 https://${tempesta_ip}:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:8765 proto=h2;

            sticky {
                cookie name=__test enforce;
            }

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
        """,
    }

    backends = [
        nginx_backend,
    ]

    def test_h2_many_cookie_enforce(self):
        """Send request with many `Cookie` headers and enforced option."""
        curl = self.get_client("curl-2")

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        response = curl.response_msg
        self.assertIn(
            "https",
            response,
            "Expected `https` schema in response",
        )
        self.assertIn(
            "HTTP/2 302",
            response,
            "Expected status `302` and sticky cookie",
        )
        self.assertIn(
            "set-cookie",
            response,
            "Expected header `set-cookie` in response",
        )
        # cookie name `__test` set up in settings
        self.assertIn(
            "__test",
            response,
            "Expected cookie name in response",
        )

    def test_h2_no_cookie_enforce(self):
        """Send request with no `Cookie` headers and enforced option."""
        curl = self.get_client("curl-3")

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        response = curl.response_msg
        self.assertIn(
            "https",
            response,
            "Expected `https` schema in response",
        )
        self.assertIn(
            "HTTP/2 302",
            response,
            "Expected status `302` and sticky cookie",
        )
        self.assertIn(
            "set-cookie",
            response,
            "Expected header `set-cookie` in response",
        )
        # cookie name `__test` set up in settings
        self.assertIn(
            "__test",
            response,
            "Expected cookie name in response",
        )
