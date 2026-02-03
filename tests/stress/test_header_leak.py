__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random
import re
import string

import psutil
from hyperframe.frame import HeadersFrame

from framework.helpers import dmesg, remote
from framework.test_suite import tester


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def get_memory_lines(*names):
    """Get values from /proc/meminfo"""
    [stdout, stderr] = remote.tempesta.run_cmd("cat /proc/meminfo")
    lines = []
    for name in names:
        line = re.search("%s:[ ]+([0-9]+)" % name, str(stdout))
        if line:
            lines.append(int(line.group(1)))
        else:
            raise Exception("Can not get %s from /proc/meminfo" % name)
    return lines


class TestH2HeaderLeak(tester.TempestaTest):
    """
    1. For 0-length header name, tempesta returns 400 and GOAWAY and
    closes the connection, so no further effect happens after.
    2. If we send a request followed by RST_STREAM, temepesta will close
    the connection when the response arrives from the backend,
    so no further effect too.
    """

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
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
    keepalive_requests 10;
    tcp_nopush       on;
    tcp_nodelay      on;
    error_log /dev/null emerg;
    access_log off;
    server {
        listen        ${server_ip}:8000;
        location / {
            return 200 'foo';
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        }
    ]

    tempesta = {
        "config": """
        cache 0;

        keepalive_timeout 1000;

        listen 443 proto=h2;

        tls_match_any_server_name;
        max_concurrent_streams 10000;

        srv_group default {
            server ${server_ip}:8000;
        }
        frang_limits {
            http_strict_host_checking false;
            http_header_cnt 1000;
        }

        ctrl_frame_rate_multiplier 65536;

        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }
        """
    }

    @dmesg.limited_rate_on_tempesta_node
    def test(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(
            uri="/", method="GET", headers=[(randomword(100), randomword(100)) for _ in range(50)]
        )

        # create http2 connection and stream 1. The stream and connection are open.
        # It is necessary for check of a memory consumption
        client.make_request(client.create_request(method="GET", headers=[]), end_stream=False)

        # save a memory consumption and make a lot of requests with different headers
        (mem1,) = get_memory_lines("MemAvailable")
        mem1 = mem1 + psutil.Process().memory_info().rss // 1024  # python memory
        for stream_id in range(3, 20000, 2):
            client.stream_id = stream_id
            client.make_request(request, end_stream=False)

            # send trailer headers with invalid `x-forwarded-for` header
            # it is necessary for calling the RST_STREAM
            client.send_bytes(
                HeadersFrame(
                    stream_id=stream_id,
                    data=client.h2_connection.encoder.encode([("x-forwarded-for", "1.1.1.1.1.1")]),
                    flags=["END_STREAM", "END_HEADERS"],
                ).serialize(),
                expect_response=True,
            )

        self.assertTrue(client.wait_for_response(120))
        # check a memory consumption (http2 connection is still open)
        (mem2,) = get_memory_lines("MemAvailable")
        mem2 = mem2 + psutil.Process().memory_info().rss // 1024
        memdiff = abs(mem2 - mem1) / mem1
        self.assertLess(memdiff, 0.05)

        # close first stream and http2 connection and finish test
        client.stream_id = 1
        client.make_request("data", end_stream=True)
        self.assertTrue(client.wait_for_response())
