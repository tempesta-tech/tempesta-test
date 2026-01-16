__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import deproxy
from helpers.access_log import AccessLogLine
from test_suite import marks, tester


def create_one_big_chunk(body_size: int) -> str:
    return "\r\n".join(["%x" % body_size, "x" * body_size, "0", "", ""])


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

srv_group localhost {
    server ${server_ip}:8000;
}

vhost localhost {
    proxy_pass localhost;
}

srv_group chunked {
    server ${server_ip}:8001;
}

vhost chunked {
    proxy_pass chunked;
}

http_chain {
    uri == "/chunked" -> chunked;
    -> localhost;
}
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
        },
        {
            "id": "chunked",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "",
        },
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

        self.assertEqual(
            AccessLogLine.from_dmesg(self.loggers.dmesg),
            AccessLogLine(
                address=client.src_ip,
                vhost="localhost",
                method="GET",
                uri=uri,
                version="2.0",
                status=int(status),
                response_content_length=len(client.last_response.body),
                referer=referer,
                user_agent=user_agent,
                tft="66cb8f00d4250002",
                tfh="b23a008c0340",
            ),
        )

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

    def test_chunked_response(self):
        self.start_all_services()

        body_size = 158036
        server = self.get_server("chunked")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html; charset=UTF-8\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + create_one_big_chunk(body_size)
        )

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(
                method="GET", uri="/chunked", headers=[("User-Agent", "deproxy")]
            ),
            expected_status_code="200",
        )
        self.assertEqual(
            len(client.last_response.body),
            body_size,
        )

        self.assertEqual(
            AccessLogLine.from_dmesg(self.loggers.dmesg),
            AccessLogLine(
                address=client.src_ip,
                vhost="chunked",
                method="GET",
                uri="/chunked",
                version="2.0",
                status=200,
                response_content_length=body_size,
                referer="-",
                user_agent="deproxy",
                tft="66cb8f00d4250002",
                tfh="1031008c0280",
            ),
        )
