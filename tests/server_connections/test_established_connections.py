"""All sockets must be closed after Tempesta shutdown"""

from framework.helpers import netfilter, remote
from framework.services import tempesta
from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestCloseOnShutdown(tester.TempestaTest):
    conns_n = tempesta.server_conns_default()  # 32 by default
    tempesta = {
        f"config": f"""
listen 80;
listen 443 proto=h2,https;

tls_certificate ${{tempesta_workdir}}/tempesta.crt;
tls_certificate_key ${{tempesta_workdir}}/tempesta.key;
tls_match_any_server_name;

frang_limits {{http_strict_host_checking false;}}

srv_group default {{
    server_forward_retries 1000;
    server_connect_retries 1000;
    server_forward_timeout 3;
    server_retry_nonidempotent;
    server ${{server_ip}}:8000 conns_n={conns_n};
}}
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    @staticmethod
    def _get_sock_count(server_ip_and_port: str, state: str = "") -> int:
        """Get count of sockets connected to given peer"""
        ss_filter = f"state {state}" if state else ""
        # Count only if  destination peer matches
        return int(
            remote.tempesta.run_cmd(f'ss -H -t {ss_filter} "dst {server_ip_and_port}" | wc -l')[0]
        )

    def _get_sock_estab_count(self, server_ip_and_port: str) -> int:
        """Get count of sockets in state TCP_ESTAB connected to given peer"""
        return self._get_sock_count(server_ip_and_port, "established")

    @staticmethod
    def get_server_ip_and_port(server) -> str:
        return f"{server.bind_addr}:{server.port}"

    async def check_established_sockets(
        self, server_ip_and_port: str, expected_n: int, msg: str | None = None
    ) -> None:
        await self.assertWaitUntilEqual(
            lambda: self._get_sock_estab_count(server_ip_and_port), expected_n, msg
        )

    async def check_total_sockets(
        self, server_ip_and_port: str, expected_n: int, msg: str | None = None
    ) -> None:
        await self.assertWaitUntilEqual(
            lambda: self._get_sock_count(server_ip_and_port), expected_n, msg
        )

    async def test_available(self):
        """
        Test check that Tempesta FW creates the correct number of connections and closes them successfully.
        """
        server = self.get_server("deproxy")
        server.conns_n = self.conns_n
        tfw = self.get_tempesta()

        msg = "Tempesta FW must not open connections before start."
        self.assertEqual(len(server.connections), 0, msg)
        await self.check_total_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=0, msg=msg
        )
        await self.check_established_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=0, msg=msg
        )

        await self.start_all_services(client=False)
        tfw.get_stats()

        msg = f"Tempesta FW must open {self.conns_n} connections to server."
        self.assertEqual(len(server.connections), self.conns_n, msg)
        self.assertEqual(tfw.stats.srv_conns_active, self.conns_n, msg)
        self.assertGreaterEqual(tfw.stats.srv_conn_attempts, self.conns_n, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, self.conns_n, msg)
        await self.check_total_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=self.conns_n, msg=msg
        )
        await self.check_established_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=self.conns_n, msg=msg
        )

        tfw.stop()
        msg = "Tempesta FW must close all connections after stop."
        self.assertEqual(len(server.connections), 0, msg)
        await self.check_total_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=0, msg=msg
        )
        await self.check_established_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=0, msg=msg
        )

    async def test_server_port_is_blocked(self):
        """
        All servers are behind firewall. All connection attempts will be silently dropped.
        """
        server = self.get_server("deproxy")
        server.conns_n = self.conns_n
        tfw = self.get_tempesta()

        with netfilter.block_ports_on_node(
            blocked_ports=[
                8000,
            ],
            node=remote.server,
        ):
            server.start()
            tfw.start()
            tfw.get_stats()
            await self.check_total_sockets(
                server_ip_and_port=self.get_server_ip_and_port(server),
                expected_n=self.conns_n,
                msg=f"Tempesta FW must create {self.conns_n} sockets to server.",
            )
            await self.check_established_sockets(
                server_ip_and_port=self.get_server_ip_and_port(server),
                expected_n=0,
                msg=f"Tempesta FW must create {self.conns_n} sockets to server, "
                f"but they must be blocked by iptables. So the expected established sockets is equal 0.",
            )

        msg = "Tempesta must not open connections to server."
        self.assertEqual(len(server.connections), 0, msg)
        self.assertEqual(tfw.stats.srv_conns_active, 0, msg)
        self.assertGreaterEqual(tfw.stats.srv_conn_attempts, 32, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, 0, msg)

    async def test_drop_server_connections(self):
        """
        See issue 114.
        Tempesta FW must not schedule requests to closed sockets with servers.
        """
        server = self.get_server("deproxy")
        tfw = self.get_tempesta()
        client = self.get_client("deproxy-1")

        server.conns_n = self.conns_n
        server.drop_conn_when_request_received = True

        await self.start_all_services(client=True)

        await client.send_request(client.create_request(method="GET", headers=[]), "504")

        self.assertTrue(
            await self.wait_all_connections(),
            "Tempesta FW must recreate all connections to server.",
        )
        tfw.get_stats()

        self.assertGreater(tfw.stats.cl_msg_received, 0, "Client don't work.")
        self.assertGreater(
            tfw.stats.cl_msg_forwarded, 0, "Tempesta FW don't forward requests to servers."
        )

        msg = f"Tempesta FW must open {self.conns_n} connections to server."
        self.assertEqual(len(server.connections), self.conns_n, msg)
        self.assertEqual(tfw.stats.srv_conns_active, self.conns_n, msg)
        self.assertGreaterEqual(tfw.stats.srv_conn_attempts, self.conns_n, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, self.conns_n, msg)

        msg = f"Tempesta FW must not create more sockets than connections, {self.conns_n = }."
        await self.check_total_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=self.conns_n, msg=msg
        )
        await self.check_established_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server), expected_n=self.conns_n, msg=msg
        )

    async def test_not_started_server(self):
        """HTTP Server is not started on available server."""
        server = self.get_server("deproxy")
        server.conns_n = self.conns_n
        tfw = self.get_tempesta()
        tfw.start()
        tfw.get_stats()

        msg = "Tempesta must not open connections to server."
        self.assertEqual(len(server.connections), 0, msg)
        self.assertEqual(tfw.stats.srv_conns_active, 0, msg)
        self.assertGreaterEqual(tfw.stats.srv_conn_attempts, 32, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, 0, msg)

        await self.check_total_sockets(
            server_ip_and_port=self.get_server_ip_and_port(server),
            expected_n=0,
            msg='"Tempesta FW must not create sockets to non-exists server"',
        )

    async def test_sometimes_available(self):
        """Test check that Tempesta FW recreate connection to server after unblock."""
        server = self.get_server("deproxy")
        server.conns_n = self.conns_n
        tfw = self.get_tempesta()
        server.start()
        self.deproxy_manager.start()

        with netfilter.block_ports_on_node(
            blocked_ports=[
                8000,
            ],
            node=remote.server,
        ):
            tfw.start()
            tfw.get_stats()
            await self.check_total_sockets(
                server_ip_and_port=self.get_server_ip_and_port(server),
                expected_n=self.conns_n,
                msg=f"Tempesta FW must create {self.conns_n} sockets to server.",
            )
            await self.check_established_sockets(
                server_ip_and_port=self.get_server_ip_and_port(server),
                expected_n=0,
                msg=f"Tempesta FW must create {self.conns_n} sockets to server, "
                f"but they must be blocked by iptables. So the expected established sockets is equal 0.",
            )

        msg = "Tempesta must not open connections to server."
        self.assertEqual(len(server.connections), 0, msg)
        self.assertEqual(tfw.stats.srv_conns_active, 0, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, 0, msg)

        msg = "Tempesta FW don't recreate connections to server after unblock firewall"
        self.assertTrue(await self.wait_all_connections(), msg)

        tfw.get_stats()
        self.assertEqual(len(server.connections), self.conns_n, msg)
        self.assertEqual(tfw.stats.srv_conns_active, self.conns_n, msg)
        self.assertGreaterEqual(tfw.stats.srv_established_connections, 0, msg)
