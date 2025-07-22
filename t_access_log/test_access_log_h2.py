__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.access_log import AccessLogLine
from test_suite import marks, tester


# Some tests for access_log over HTTP/2.0
class TestAccessLogH2(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
listen 443 proto=h2;
access_log dmesg;

frang_limits {
    ip_block off;
    http_uri_len 1050;
    http_strict_host_checking false;
}

block_action attack reply;
block_action error reply;

server ${server_ip}:8000;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
"""
    }

    backends = [
        {
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

                    # [ debug | info | notice | warn | error | crit | alert | emerg ]
                    # Fully disable log errors.
                    error_log /dev/null emerg;

                    # Disable access log altogether.
                    access_log off;

                    server {
                        listen        ${server_ip}:8000;

                        location /200 { return 200; }
                        location /204 { return 204; }
                        location /302 { return 302; }
                        location /404 { return 404; }
                        location /500 { return 500; }
                        location / { return 200; }
                        location /nginx_status {
                            stub_status on;
                        }
                    }
                }
                """,
        }
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(name="200", status="200", uri="/200"),
            marks.Param(name="204", status="204", uri="/204"),
            marks.Param(name="302", status="302", uri="/302"),
            marks.Param(name="404", status="404", uri="/404"),
            marks.Param(name="500", status="500", uri="/500"),
            marks.Param(name="403_frang", status="403", uri=f"/{'1' * 1100}"),
        ]
    )
    def test_response(self, name, status: str, uri: str):
        self.start_all_services()

        referer = f"http2-referer-{status}"
        user_agent = f"http2-user-agent-{status}"

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(
                method="GET", uri=uri, headers=[("referer", referer), ("user-agent", user_agent)]
            ),
            expected_status_code=status,
        )

        msg = AccessLogLine.from_dmesg(self.loggers.dmesg)
        self.assertIsNotNone(msg, "No access_log message in dmesg")
        self.assertEqual(msg.method, "GET", "Wrong method")
        self.assertEqual(msg.status, int(status), "Wrong HTTP status")
        self.assertEqual(msg.user_agent, user_agent)
        self.assertEqual(msg.referer, referer)

    def test_response_truncated_uri(self):
        self.start_all_services()

        referer = f"http2-referer"
        user_agent = f"http2-user-agent"

        client = self.get_client("deproxy")
        base_uri = "/truncated_uri"
        request = client.create_request(
            method="GET",
            uri=f"{base_uri}{'_' * 1000}",
            headers=[("referer", referer), ("user-agent", user_agent)],
        )
        client.send_request(request, expected_status_code="200")

        msg = AccessLogLine.from_dmesg(self.loggers.dmesg)
        self.assertEqual(msg.uri[: len(base_uri)], base_uri, "Invalid URI")
        self.assertEqual(msg.uri[-3:], "...", "URI does not look like truncated")
