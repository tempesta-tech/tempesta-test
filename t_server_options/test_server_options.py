__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from helpers import analyzer, dmesg, remote, tf_cfg
from test_suite import marks, tester

SERVER_IP = tf_cfg.cfg.get("Server", "ip")


class TestServerOptions(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

frang_limits {http_strict_host_checking false;}

%s

vhost main {
    proxy_pass main;
}
http_chain {-> main;}
""",
    }

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_forward_timeout_exceeded(self):
        """
        Tempesta forwards a request to a server during 3 seconds,
        but the server always drops the request.
        The server exceeds `server_forward_timeout 3` limit
        and the request will be evicted with a 504 response.
        """
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries 1000;
                server_forward_timeout 3;
                server_connect_retries 1000;
            }}
        """
        )

        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        self.start_all_services()

        client = self.get_client("deproxy")
        time_start = time.monotonic()
        client.send_request(client.create_request(method="GET", headers=[]), "504")
        time_end = time.monotonic()

        self.assertGreater(time_end - time_start, 2, "Tempesta evicted a request earlier.")
        self.assertTrue(
            self.loggers.dmesg.find("request evicted: timed out", cond=dmesg.amount_one),
            "An unexpected number of warnings were received",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_forward_timeout_not_exceeded(self):
        """
        Tempesta forwards a request to a server during 3 seconds.
        The server drops the request the first second and then returns a response.
        The server doesn't exceed `server_forward_timeout 3` limit
        and Tempesta forwards the response to client.
        """
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries 1000;
                server_forward_timeout 3;
                server_connect_retries 1000;
            }}
        """
        )

        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        self.start_all_services()

        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))
        time.sleep(1)
        server.drop_conn_when_request_received = False
        client.wait_for_response(timeout=5, strict=True)

        self.assertEqual(client.last_response.status, "200")
        self.assertTrue(
            self.loggers.dmesg.find("request evicted: timed out", cond=dmesg.amount_zero),
            "An unexpected number of warnings were received",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(name="exceeded_5", server_forward_retries=5),
            marks.Param(name="exceeded_0", server_forward_retries=0),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_forward_retries(self, name, server_forward_retries):
        """
        Tempesta forwards a request to a server 6/1 times,
        but the server always drops this request.
        The server exceeds `server_forward_retries 5/0` limit
        and the request will be evicted with a 504 response.
        """
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries {server_forward_retries};
                server_forward_timeout 60;
                server_connect_retries 1000;
            }}
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(client.create_request(method="GET", headers=[]), "504")

        self.assertTrue(
            self.loggers.dmesg.find(
                "request evicted: the number of retries exceeded", cond=dmesg.amount_one
            ),
            "An unexpected number of warnings were received",
        )
        self.assertEqual(
            len(server.requests),
            server_forward_retries + 1,
            "Tempesta forwarded an unexpected number of requests "
            "to server for `server_forward_retries`.",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_forward_retries_not_exceeded(self):
        """
        Tempesta forwards a request to a server 100 times,
        but the server drops first 50 requests and then returns a response.
        The server doesn't exceed `server_forward_retries 100` limit
        and Tempesta forwards the response to client.
        """
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries 100;
                server_forward_timeout 60;
                server_connect_retries 1000;
            }}
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))
        server.wait_for_requests(50, strict=True)
        server.drop_conn_when_request_received = False
        client.wait_for_response(timeout=5, strict=True)

        self.assertTrue(
            self.loggers.dmesg.find(
                "request evicted: the number of retries exceeded", cond=dmesg.amount_zero
            ),
            "An unexpected number of warnings were received",
        )
        self.assertEqual(client.last_response.status, "200")
        self.assertGreaterEqual(
            len(server.requests),
            51,
            "Tempesta forwarded an unexpected number of requests "
            "to server for `server_forward_retries`.",
        )

    def test_requests_after_nonidempotent_request_conn_n_1(self):
        """
        The client sends a nonidempotent request and few idempotent requests.
        Tempesta forwards the nonidempotent request to single connection
        but doesn't forward next idempotent requests to server
        because Tempesta has one available connection.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response("")

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=1;
            }}
            keepalive_timeout 2;
        """
        )

        self.start_all_services()
        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="POST", headers=[]))
        server.wait_for_requests(1, strict=True)  # it's necessary for stability

        request = client.create_request(method="GET", headers=[])
        client.make_requests([request] * 5)

        client.wait_for_connection_close(strict=True)
        self.assertIsNone(client.last_response)

    def test_requests_after_nonidempotent_request_conn_n_2(self):
        """
        The client sends a nonidempotent request and few idempotent requests.
        Tempesta forwards the nonidempotent request to first connection
        and forwards next idempotent requests to second connection.
        """
        server = self.get_server("deproxy")
        server.conns_n = 2
        server.set_response("")

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
            }}
        """
        )

        self.start_all_services()
        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="POST", headers=[]))

        server.wait_for_requests(1, strict=True)  # it's necessary for stability
        server.set_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        request = client.create_request(method="GET", headers=[])
        idempotent_req_n = 5
        client.make_requests([request] * idempotent_req_n)

        client.wait_for_response(n=idempotent_req_n, strict=True)
        self.assertEqual(
            {1, idempotent_req_n},
            set(con.nrreq for con in server.connections),
            "The server connections must receive:\n"
            "1 - one nonidempotent request;\n"
            f"2 - {idempotent_req_n} idempotent requests;",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_queue_size_exceeded(self):
        """
        The client sends the number of requests equal to `server_queue_size`
        and Tempesta forwards them. Tempesta marks the connection as dead
        and all next requests should receive a 502 response.
        All requests in the queue must be processed using one of the next methods:
            - evicted via `server_forward_retries`;
            - evicted via `server_forward_timeout`;
            - evicted via `server_connect_retries`;
            - dropped connection via `keepalive_timeout` with TCP FIN.
        This test use `keepalive_timeout` limit.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response("")

        server_queue_size = 3
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=1;
                server_queue_size {server_queue_size};
            }}
            keepalive_timeout 2;
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[])
        client.make_requests([request] * server_queue_size)
        server.wait_for_requests(server_queue_size, strict=True)
        client.make_requests([request] * 10)
        self.assertTrue(client.wait_for_connection_close())

        self.assertEqual(client.statuses, {502: 10})
        self.assertTrue(
            self.loggers.dmesg.find("request evicted:", cond=dmesg.amount_zero),
            "An unexpected number of warnings were received",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_queue_size_not_exceeded(self):
        """
        The client sends the number of requests equal to `server_queue_size`
        and Tempesta forwards them (client does not exceed the limit).
        And then client wait for responses.
        All requests in the queue must be processed using one of the next methods:
            - evicted via `server_forward_retries`;
            - evicted via `server_forward_timeout`;
            - evicted via `server_connect_retries`;
            - dropped connection via `keepalive_timeout` with TCP FIN.
        This test use `keepalive_timeout` limit.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response("")

        server_queue_size = 3
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=1;
                server_queue_size {server_queue_size};
            }}
            keepalive_timeout 2;
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[])
        client.make_requests([request] * server_queue_size)
        server.wait_for_requests(3, strict=True)
        self.assertTrue(client.wait_for_connection_close())

        self.assertEqual(client.statuses, {})
        self.assertTrue(
            self.loggers.dmesg.find(
                "request evicted: timed out, status 504", cond=dmesg.amount_zero
            ),
            "An unexpected number of warnings were received",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_queue_size_pipeline_disable(self):
        """
        Test for http 1.
        `server_queue_size 1` disables pipelined requests to connections.
        Tempesta doesn't send requests if connection doesn't return a response
        for the first request and `srv_group` has not other available connections.
        This test doesn't require for http2 because
        Tempesta will be return 502 responses for other requests.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response("")

        server_queue_size = 1
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=1;
                server_queue_size {server_queue_size};
            }}
            keepalive_timeout 2;
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy-1")
        request = client.create_request(method="GET", headers=[])
        client.make_requests([request] * 5)
        server.wait_for_requests(server_queue_size, strict=True)
        self.assertTrue(client.wait_for_connection_close())

        self.assertTrue(
            self.loggers.dmesg.find("request evicted:", cond=dmesg.amount_zero),
            "An unexpected number of warnings were received",
        )
        self.assertEqual(len(server.requests), 1)

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_retry_nonidempotent_enabled(self):
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries 2;
                server_retry_nonidempotent;
            }}
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(client.create_request(method="POST", headers=[]), "504")

        self.assertTrue(
            self.loggers.dmesg.find(
                "request evicted: the number of retries exceeded", cond=dmesg.amount_one
            ),
            "An unexpected number of warnings were received",
        )
        self.assertEqual(
            len(server.requests), 3, "Tempesta doesn't forward a nonidempotent request to server."
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_retry_nonidempotent_disabled(self):
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_forward_retries 2;
            }}
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(client.create_request(method="POST", headers=[]), "504")

        self.assertTrue(
            self.loggers.dmesg.find(
                "request evicted: the number of retries exceeded", cond=dmesg.amount_zero
            ),
            "An unexpected number of warnings were received",
        )
        self.assertEqual(
            len(server.requests), 1, "Tempesta forwards a nonidempotent request to server."
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_connect_retries_exceeded_conns_n_1(self):
        """
        Tempesta forwards a request to a server connection,
        but the server drops this connection and doesn't accept a new connection.
        Then Tempesta returns a 502 response to a client because
        the srv_group has not available connections.
        """
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 1

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=1;
                server_forward_retries 1000;
                server_forward_timeout 60;
                server_connect_retries 2;
            }}
        """
        )

        self.start_all_services()

        sniffer = analyzer.Sniffer(node=remote.tempesta, host="Tempesta", timeout=15, ports=[8000])
        sniffer.start()
        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))

        self.assertTrue(server.wait_for_requests(n=1))
        server.reset_new_connections()

        self.assertTrue(client.wait_for_response(timeout=15))
        self.assertEqual(client.last_response.status, "502")

        sniffer.stop()
        connect_tries = len([p for p in sniffer.packets if p[analyzer.TCP].flags & analyzer.SYN])
        self.assertGreaterEqual(
            connect_tries,
            9,
            "Tempesta must drop a request after 9 TCP SYN packets to the connection. "
            "6 default + 3 for `server_connect_retries`.",
        )

        self.assertTrue(
            self.loggers.dmesg.find(
                "request dropped: unable to find an available back end server",
                cond=dmesg.amount_one,
            ),
            "An unexpected number of warnings were received",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_connect_retries_exceeded_conns_n_2(self):
        """
        Tempesta forwards a request to a server connection,
        but the server drops this connection and doesn't accept a new connection.
        After 9 tries Tempesta schedule the request to other available connections.
        6 default + 3 for server_connect retries 2
        """
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2
        sniffer = analyzer.Sniffer(node=remote.tempesta, host="Tempesta", timeout=15, ports=[8000])

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_connect_retries 2;
            }}
        """
        )

        self.start_all_services()

        sniffer.start()
        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))

        self.assertTrue(server.wait_for_requests(1))
        server.reset_new_connections()
        server.drop_conn_when_request_received = False

        self.assertTrue(client.wait_for_response(15))
        self.assertEqual(client.last_response.status, "200")

        sniffer.stop()
        connect_tries = len([p for p in sniffer.packets if p[analyzer.TCP].flags & analyzer.SYN])

        self.assertGreaterEqual(
            connect_tries,
            9,
            "Tempesta must schedule a request to other server connection after 9 TCP SYN packets "
            "to the connection. 6 default + 3 for `server_connect_retries`.",
        )

        self.assertTrue(
            self.loggers.dmesg.find(
                "request dropped: unable to find an available back end server",
                cond=dmesg.amount_zero,
            ),
            "An unexpected number of warnings were received",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_server_connect_retries_not_exceeded(self):
        """
        Tempesta forwards a request to a server connection,
        but the server drops this connection and doesn't accept a new connection
        some time ~2 second.


        """
        server = self.get_server("deproxy")
        server.drop_conn_when_request_received = True
        server.conns_n = 2

        tempesta = self.get_tempesta()
        tempesta.config.defconfig = (
            tempesta.config.defconfig
            % f"""
            srv_group main {{
                server {SERVER_IP}:8000 conns_n=2;
                server_connect_retries 100;
            }}
        """
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))

        self.assertTrue(server.wait_for_requests(1))
        server.reset_new_connections()
        server.drop_conn_when_request_received = False

        time.sleep(2)
        # Do not call the start method here because it reset all variables
        server.run_start()

        self.assertTrue(client.wait_for_response(5))
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(len(server.connections), 2)
        self.assertTrue(
            self.loggers.dmesg.find(
                "request dropped: unable to find an available back end server",
                cond=dmesg.amount_zero,
            ),
            "An unexpected number of warnings were received",
        )
