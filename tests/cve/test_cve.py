__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random
import string
from pathlib import Path

from hyperframe.frame import HeadersFrame, PriorityFrame

from framework.deproxy.deproxy_message import HttpMessage
from framework.helpers import dmesg, memworker, remote, tf_cfg
from framework.test_suite import marks, tester


class TestSlowRead(tester.TempestaTest):
    clients = [
        {
            "id": f"deproxy-{i}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for i in range(20)
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
""",
        }
    ]

    tempesta = {
        "config": """
        cache 0;
        keepalive_timeout 10;
        listen 443 proto=h2;

        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }

        """
    }

    response_file_name = "large.txt"
    response_file_path = str(Path(tf_cfg.cfg.get("Server", "resources")) / response_file_name)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        remote.server.run_cmd(
            f"fallocate -l {1024**2 * int(tf_cfg.cfg.get("General", "long_body_size"))} {cls.response_file_path}"
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        remote.server.remove_file(cls.response_file_path)

    def test_cve_2019_9511(self):
        """
        CVE-2019-9511 - “Data Dribble”
        Some HTTP/2 implementations are vulnerable to window size manipulation
        and stream prioritization manipulation, potentially leading to a denial of service.
        The attacker requests a large amount of data from a specified resource over multiple streams.
        They manipulate window size and stream priority to force the server to queue the data in 1-byte chunks.
        Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.
        """
        self.start_all_services()

        request = self.get_clients()[0].create_request(
            method="GET",
            headers=[],
            authority="tempesta-tech.com",
            uri=f"/{self.response_file_name}",
        )

        for client in self.get_clients():
            client.update_initial_settings(initial_window_size=1)
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            client.make_requests([request] * 100)

        for client in self.get_clients():
            client.wait_for_connection_close(strict=True)

    def test_cve_2019_9517(self):
        """
        CVE-2019-9517 - “Internal Data Buffering”
        Some HTTP/2 implementations are vulnerable to unconstrained internal data buffering,
        potentially leading to a denial of service. The attacker opens the HTTP/2 window
        so the peer can send without constraint; however, they leave the TCP window closed
        so the peer cannot actually write (many of) the bytes on the wire.
        The attacker sends a stream of requests for a large response object.
        Depending on how the servers queue the responses, this can consume excess memory, CPU, or both.
        """
        self.start_all_services()

        request = self.get_clients()[0].create_request(
            method="GET",
            headers=[],
            authority="tempesta-tech.com",
            uri=f"/{self.response_file_name}",
        )

        for client in self.get_clients():
            client.update_initial_settings()
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            client.set_size_of_receiving_buffer(new_buffer_size=1)
            client.make_requests([request] * 100)

        for client in self.get_clients():
            client.wait_for_connection_close(timeout=20, strict=True)


class TestHttp2FrameFlood(tester.TempestaTest):
    """
    Test ability to handle requests from the client
    under control frames flood.
    Also check that there is no kernel BUGS and WARNINGs
    under flood.
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nServer: Debian\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;

        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        cache 0;
    """
    }

    clients = [
        {
            "id": "ctrl_frames_flood",
            "type": "external",
            "binary": "ctrl_frames_flood",
            "ssl": True,
            "cmd_args": (
                "-address ${tempesta_ip}:443 -threads 4 -connections 100 -frame_count 100000"
            ),
        },
        {
            "id": "gflood",
            "type": "external",
            "binary": "gflood",
            "ssl": True,
            "cmd_args": (
                "-address ${tempesta_ip}:443 -host tempesta-tech.com "
                "-threads 4 -connections 10000 -streams 100 -headers_cnt 7"
            ),
        },
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def random_depends_on(self, stream_id: int) -> int:
        depends_on = random.randint(1, 199)
        if depends_on % 2 == 0:
            depends_on += 1
        if depends_on == stream_id:
            return self.random_depends_on(stream_id)
        return depends_on

    @staticmethod
    def random_stream_id(max_id: int) -> int:
        stream_id = random.randint(1, max_id)
        if stream_id % 2 == 0:
            stream_id = stream_id - 1 if stream_id == max_id else stream_id + 1
        return stream_id

    def test_cve_2019_9513(self):
        """
        CVE-2019-9513 “Resource Loop”
        Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service.
        The attacker creates multiple request streams and continually shuffles the priority of the streams in a way
        that causes substantial churn to the priority tree. This can consume excess CPU.

        Tempesta FW blocks a lot of priority frames.
        """
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        server.set_response("")

        self.start_all_services(client=False)

        request = client.create_request(uri="/", method="GET", headers=[])

        client.start()
        client.make_request(request)
        for stream_id in range(3, 200, 2):
            client.make_request(
                request,
                priority_weight=random.randint(1, 255),
                priority_depends_on=self.random_depends_on(stream_id),
                priority_exclusive=bool(random.randint(0, 1)),
            )

        for _ in range(1000):
            client.send_bytes(
                PriorityFrame(
                    stream_id=self.random_stream_id(199),
                    depends_on=self.random_depends_on(stream_id),
                    stream_weight=random.randint(1, 255),
                    exclusive=bool(random.randint(0, 1)),
                ).serialize()
            )
        client.wait_for_connection_close(strict=True)

    @dmesg.limited_rate_on_tempesta_node
    def test_cve_2024_2758(self):
        """
        CVE-2024-2758 "Continuation flood"
        Many HTTP/2 implementations do not properly limit or sanitize the amount of CONTINUATION frames sent within
        a single stream. An attacker that can send packets to a target server can send a stream of CONTINUATION
        frames that will not be appended to the header list in memory but will still be processed and decoded
        by the server or will be appended to the header list, causing an out of memory (OOM) crash.
        """
        self.start_all_services(client=False)

        client = self.get_client("gflood")

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(0, client.returncode)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="2019_9512",
                cmd_args=f"-ctrl_frame_type ping_frame",
                stat_name="cl_ping_frame_exceeded",
            ),
            marks.Param(
                name="2019_9515",
                cmd_args=f"-ctrl_frame_type settings_frame",
                stat_name="cl_settings_frame_exceeded",
            ),
            marks.Param(
                name="2023-44487",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type rst",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_window_update",
                cmd_args=f"-ctrl_frame_type window_update",
                stat_name="cl_wnd_update_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_window_update",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type window_update",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_priority",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type priority",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_flood_rst_batch",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type batch",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_headers_max_concurrent_streams_exceeded",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type headers_by_max_streams_exceeded",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_headers_invalid_dependency",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type headers_by_invalid_dependency",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_incorrect_frame_type",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type incorrect_frame_type",
                stat_name="cl_rst_frame_exceeded",
            ),
            marks.Param(
                name="2025-8671_by_incorrect_header",
                cmd_args=f"-ctrl_frame_type rapid_reset -rapid_reset_type incorrect_header",
                stat_name="cl_rst_frame_exceeded",
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_cve(self, name, cmd_args, stat_name):
        """
        CVE-2019-9512 “Ping Flood”
        Some HTTP/2 implementations are vulnerable to ping floods, potentially leading to a denial of service.
        The attacker sends continual pings to an HTTP/2 peer, causing the peer to build an internal queue of responses.
        Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.

        CVE-2019-9514 "Reset Flood"
        Some HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a denial of service.
        Servers that accept direct connections from untrusted clients could be remotely made to allocate an
        unlimited amount of memory, until the program crashes.
        The attacker opens a number of streams and sends an invalid request over each stream that should solicit
        a stream of RST_STREAM frames from the peer. Depending on how the peer queues the RST_STREAM frames,
        this can consume excess memory, CPU, or both.

        CVE-2019-9515 "Settings Flood"
        Some HTTP/2 implementations are vulnerable to a settings flood, potentially leading to a denial of service.
        The attacker sends a stream of SETTINGS frames to the peer. Since the RFC requires that the peer reply with
        one acknowledgement per SETTINGS frame, an empty SETTINGS frame is almost equivalent in behavior to a ping.
        Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.

        CVE-2023-44487 "Rapid Reset"
        The HTTP/2 protocol allows clients to indicate to the server that a previous stream should be canceled
        by sending RST_STREAM frame. The protocol does not require the client and server to coordinate
        the cancellation in any way, the client may do it unilaterally. The client may also assume that
        the cancellation will take effect immediately when the server receives the RST_STREAM frame,
        before any other data from that TCP connection is processed.

        CVE-2025-8671 "Made You Reset"
        By opening streams and then rapidly triggering the server to reset them using malformed frames or flow
        control errors, an attacker can exploit a discrepancy created between HTTP/2 streams accounting and the
        servers active HTTP requests. Streams reset by the server are considered closed, even though backend
        processing continues. This allows a client to cause the server to handle an unbounded number
        of concurrent HTTP/2 requests on a single connection.
        This is very similar to CVE-2019-9514 HTTP/2 Reset Flood
        """
        server = self.get_server("deproxy")
        flood_client = self.get_client("ctrl_frames_flood")
        tempesta = self.get_tempesta()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Server: Debian\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + (2000 * "a")
        )

        self.start_all_services(client=False)

        flood_client.options = flood_client.options + [cmd_args]
        flood_client.start()
        self.wait_while_busy(flood_client)
        flood_client.stop()

        self.assertEqual(0, flood_client.returncode)
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.__dict__[stat_name], 100)


class TestH2Headers(tester.TempestaTest):

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

    @staticmethod
    def randomword(length):
        letters = string.ascii_lowercase
        return "".join(random.choice(letters) for i in range(length))

    @dmesg.limited_rate_on_tempesta_node
    def test_2019_9516(self):
        """
        CVE-2019-9516 “0-Length Headers Leak”
        Some HTTP/2 implementations are vulnerable to a header leak, potentially leading to a denial of service.
        The attacker sends a stream of headers with a 0-length header name and 0-length header value,
        optionally Huffman encoded into 1-byte or greater headers. Some implementations allocate memory
        for these headers and keep the allocation alive until the session dies. This can consume excess memory.

        1. For 0-length header name, tempesta returns 400 and GOAWAY and
        closes the connection, so no further effect happens after.
        2. If we send a request followed by RST_STREAM, temepesta will close
        the connection when the response arrives from the backend,
        so no further effect too.
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(
            uri="/",
            method="GET",
            headers=[(self.randomword(100), self.randomword(100)) for _ in range(50)],
        )

        # create http2 connection and stream 1. The stream and connection are open.
        # It is necessary for check of a memory consumption
        client.make_request(client.create_request(method="GET", headers=[]), end_stream=False)

        with memworker.check_memory_consumptions(self):
            for stream_id in range(3, 20000, 2):
                client.stream_id = stream_id
                client.make_request(request, end_stream=False)

                # send trailer headers with invalid `x-forwarded-for` header
                # it is necessary for calling the RST_STREAM
                client.send_bytes(
                    HeadersFrame(
                        stream_id=stream_id,
                        data=client.h2_connection.encoder.encode(
                            [("x-forwarded-for", "1.1.1.1.1.1")]
                        ),
                        flags=["END_STREAM", "END_HEADERS"],
                    ).serialize(),
                    expect_response=True,
                )

            self.assertTrue(client.wait_for_response(120))

        # close first stream and http2 connection and finish test
        client.stream_id = 1
        client.make_request("data", end_stream=True)
        self.assertTrue(client.wait_for_response())
