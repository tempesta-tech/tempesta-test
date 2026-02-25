__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import threading

from framework.helpers import analyzer, dmesg, error, port_checks, remote
from framework.helpers.analyzer import PSH, TCP
from framework.helpers.cert_generator_x509 import CertGenerator
from framework.helpers.dmesg import amount_positive
from framework.helpers.tf_cfg import cfg
from framework.test_suite import marks, tester

SERVER_IP = cfg.get("Server", "ip")
TEMPESTA_WORKDIR = cfg.get("Tempesta", "workdir")
DMESG_WARNING = "An unexpected number of warnings were received"


class TestListenCommonReconf(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta_orig = {
        "config": """
        listen 443 proto=http;
        """
    }

    tempesta_busy_socks = {
        "config": """
        listen 443 proto=http;
        listen 8000 proto=http;
        listen 4433 proto=http;
        """
    }

    async def test_stop(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        await self.start_tempesta()

        remote.tempesta.run_cmd("sysctl -e -w net.tempesta.state=stop")
        tempesta.run_start()

    async def test_reconf_busy_socks(self):
        """The user is trying to add listen to a busy port by another service."""
        tempesta = self.get_tempesta()
        port_checker = port_checks.FreePortsChecker()

        self.start_all_servers()

        # Tempesta listen 443 port and Nginx listen 8000 port
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        await self.start_tempesta()

        # Tempesta listen 443, 8000, 4433 port and Nginx listen 8000 port
        tempesta.config.set_defconfig(self.tempesta_busy_socks["config"])
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.reload()

        port_checker.node = remote.tempesta
        port_checker.add_port_to_checks(ip=cfg.get("Tempesta", "ip"), port=443)
        port_checker.check_ports_status()


@marks.parameterize_class(
    [
        {"name": "Http", "proto": "http"},
        {"name": "Https", "proto": "https"},
        {"name": "H2", "proto": "h2"},
        {"name": "H2AndHttps", "proto": "h2,https"},
    ]
)
class TestListenReconf(tester.TempestaTest):
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
            "id": "http",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
        },
        {
            "id": "https",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "h2,https",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    base_tempesta_config = f"""
server {SERVER_IP}:8000;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{http_strict_host_checking false;}}
"""
    proto: str

    @classmethod
    def setUpClass(cls):
        cert_path = f"{TEMPESTA_WORKDIR}/tempesta.crt"
        key_path = f"{TEMPESTA_WORKDIR}/tempesta.key"
        cgen = CertGenerator(cert_path, key_path, True)
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())
        super().setUpClass()

    async def _start_all_services_and_reload_tempesta(self, first_config: str, second_config: str):
        tempesta = self.get_tempesta()

        tempesta.config.set_defconfig(first_config + self.base_tempesta_config)
        await self.start_all_services(client=False)

        tempesta.config.set_defconfig(second_config + self.base_tempesta_config)
        tempesta.reload()

    @marks.Parameterize.expand(
        [
            marks.Param(name="http", proto="http"),
            marks.Param(name="https", proto="https"),
            marks.Param(name="h2", proto="h2"),
            marks.Param(name="h2_https", proto="h2,https"),
        ]
    )
    async def test_reconf_proto(self, name, proto):
        await self._start_all_services_and_reload_tempesta(
            first_config=f"listen 443 proto={self.proto};\n",
            second_config=f"listen 443 proto={proto};\n",
        )

        client = self.get_client(proto)
        request = client.create_request(method="GET", headers=[])
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening proto after reload."):
            await client.send_request(request, "200")

    async def test_reconf_port(self):
        await self._start_all_services_and_reload_tempesta(
            first_config=f"listen 443 proto={self.proto};\n",
            second_config=f"listen 4433 proto={self.proto};\n",
        )

        client = self.get_client(self.proto)
        request = client.create_request(method="GET", headers=[])
        client.port = 4433
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening port after reload."):
            await client.send_request(request, "200")

        client.port = 443
        client.restart()

        with self.subTest(msg=f"Tempesta continued listening to the old port."):
            with self.assertRaises(AssertionError):
                await client.send_request(request, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="default_to_ipv4_port_default",
                first_config="",
                second_config="listen 127.0.0.1 proto={0};\n",
                old_ip="0.0.0.0",
                new_ip="127.0.0.1",
                port=80,
            ),
            marks.Param(
                name="ipv4_to_ipv4_port_default",
                first_config="listen 127.0.0.1 proto={0};\n",
                second_config="listen 127.0.1.100 proto={0};\n",
                old_ip="127.0.0.1",
                new_ip="127.0.1.100",
                port=80,
            ),
            marks.Param(
                name="ipv4_to_ipv4_port_443",
                first_config="listen 127.0.0.1:443 proto={0};\n",
                second_config="listen 127.0.1.100:443 proto={0};\n",
                old_ip="127.0.0.1",
                new_ip="127.0.1.100",
                port=443,
            ),
        ]
    )
    async def test_reconf_ip(self, name, first_config, second_config, old_ip, new_ip, port):
        await self._start_all_services_and_reload_tempesta(
            first_config.format(self.proto), second_config.format(self.proto)
        )

        client = self.get_client(self.proto)
        request = client.create_request(method="GET", headers=[])
        client.conn_addr = new_ip
        client.port = port
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening IP after reload."):
            await client.send_request(request, "200")

        client.conn_addr = old_ip
        client.restart()

        with self.subTest(msg=f"Tempesta continued listening to old IP after reload."):
            with self.assertRaises(AssertionError):
                await client.send_request(request, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="add_listen",
                first_config="listen 443 proto={0};\n",
                second_config="listen 443 proto={0};\nlisten 444 proto={0};\n",
                expected_response_on_444_port=True,
            ),
            marks.Param(
                name="remove_listen",
                first_config="listen 443 proto={0};\nlisten 444 proto={0};\n",
                second_config="listen 443 proto={0};\n",
                expected_response_on_444_port=False,
            ),
        ]
    )
    async def test_reconf(self, name, first_config, second_config, expected_response_on_444_port):
        await self._start_all_services_and_reload_tempesta(
            first_config.format(self.proto),
            second_config.format(self.proto),
        )

        client = self.get_client(self.proto)
        request = client.create_request(method="GET", headers=[])

        client.start()
        await client.send_request(request, "200")

        client.port = 444
        client.restart()
        client.make_request(request)
        await client.wait_for_response(strict=expected_response_on_444_port, timeout=1)


class TestListenStartFail(tester.TempestaTest):
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
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf ${tempesta_ip}:443",
        },
    ]

    stop = False

    async def __heavy_load(self):
        curl = self.get_client("curl")
        while not self.stop:
            curl.start()
            await self.wait_while_busy(curl)
            curl.stop()

    async def __finish_heavy_load(self):
        self.stop = True
        for task in self.tasks:
            await task

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.tasks = []
        self.addAsyncCleanup(self.__finish_heavy_load)

    async def test_start_failed_under_heavy_load(self):
        """
        Tempesta FW start listen several ports, one of it is busy
        (deproxy server already listen on port 8000). Because of it
        Tempesta FW failed to start, stop and unload all modules.
        In separate thread client connect and send requests to one of
        the ports already listen by Tempesta FW. This test checks that
        Tempesta FW correctly stop listen all ports under load, during
        unsuccessful start.
        """
        server = self.get_server("deproxy")
        server.start()
        self.deproxy_manager.start()

        self.tasks.append(asyncio.create_task(self.__heavy_load()))

        self.get_tempesta().config.set_defconfig(
            f"""
            listen 8000 proto=http;
            listen 443 proto=https;
            tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
            tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
            tls_match_any_server_name;
            frang_limits {{http_strict_host_checking false;}}
        """
        )
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(
            error.ProcessBadExitStatusException,
            msg="Tempesta FW successfully start, although one of the port is already listened by deproxy server",
        ):
            self.get_tempesta().start()


class TestServerReconf(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    async def _start_all(self, servers: list, client: bool):
        for server in servers:
            server.start()
        await self.start_tempesta()
        if client:
            self.start_all_clients()
        self.deproxy_manager.start()

        for server in servers:
            await server.wait_for_connections()

    def _set_tempesta_config_with_1_srv_group(self):
        self.get_tempesta().config.set_defconfig(
            f"""
block_action attack reply;
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
"""
        )

    def _set_tempesta_config_with_2_srv_group(self):
        self.get_tempesta().config.set_defconfig(
            f"""
block_action attack reply;

srv_group grp1 {{
    server {SERVER_IP}:8000;
}}
srv_group grp2 {{
    server {SERVER_IP}:8001;
}}

vhost grp1 {{
    proxy_pass grp1;
}}
vhost grp2 {{
    proxy_pass grp2;
}}

http_chain {{
    host == "grp1" -> grp1;
    host == "grp2" -> grp2;
    -> block;
}}
"""
        )

    def _set_tempesta_config_with_1_srv_in_srv_group(self):
        self.get_tempesta().config.set_defconfig(
            f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
"""
        )

    def _set_tempesta_config_with_2_srv_in_srv_group(self):
        self.get_tempesta().config.set_defconfig(
            f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
    server {SERVER_IP}:8001;
}}
vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
"""
        )

    def _set_tempesta_config_with_1_srv_in_default_srv_group(self):
        self.get_tempesta().config.set_defconfig(f"server {SERVER_IP}:8000;\n")

    def _set_tempesta_config_with_2_srv_in_default_srv_group(self):
        self.get_tempesta().config.set_defconfig(
            f"server {SERVER_IP}:8000;\nserver {SERVER_IP}:8001;\n"
        )

    @marks.Parameterize.expand(
        [
            marks.Param(name="increase", conns_n_1=32, conns_n_2=64),
            marks.Param(name="decrease", conns_n_1=32, conns_n_2=16),
            marks.Param(name="increase_from_default", conns_n_1=0, conns_n_2=64),
            marks.Param(name="decrease_from_default", conns_n_1=0, conns_n_2=16),
        ]
    )
    async def test_conns_n(self, name, conns_n_1, conns_n_2):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy-1")
        tempesta = self.get_tempesta()

        tempesta.config.set_defconfig(
            f"server {SERVER_IP}:8000" + f"{f' conns_n={conns_n_1}' if conns_n_1 else ''};\n"
        )
        server.conns_n = conns_n_1

        await self._start_all(servers=[server], client=False)

        tempesta.config.set_defconfig(f"server {SERVER_IP}:8000 conns_n={conns_n_2};\n")
        server.conns_n = conns_n_2

        tempesta.reload()
        self.assertTrue(
            await server.wait_for_connections(),
            "Tempesta did not change number of connections with server after reload.",
        )

        client.start()
        await client.send_request(client.create_request(method="GET", headers=[]), "200")

    @marks.Parameterize.expand(
        [
            marks.Param(name="increase", conns_n_1=32, conns_n_2=64),
            marks.Param(name="decrease", conns_n_1=32, conns_n_2=16),
        ]
    )
    async def test_conns_n_for_srv_group(self, name, conns_n_1, conns_n_2):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy-1")
        tempesta = self.get_tempesta()

        tempesta.config.set_defconfig(
            f"""
srv_group grp1 {{
    server {SERVER_IP}:8000 conns_n={conns_n_1};
}}
vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
            """
        )
        server.conns_n = conns_n_1

        await self._start_all(servers=[server], client=False)

        tempesta.config.set_defconfig(
            f"""
srv_group grp1 {{
    server {SERVER_IP}:8000 conns_n={conns_n_2};
}}
vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
            """
        )
        server.conns_n = conns_n_2

        tempesta.reload()
        self.assertTrue(
            await server.wait_for_connections(),
            "Tempesta did not change number of connections with server after reload.",
        )

        client.start()
        await client.send_request(client.create_request(method="GET", headers=[]), "200")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="server_from_default_srv_group",
                first_config=_set_tempesta_config_with_2_srv_in_default_srv_group,
                second_config=_set_tempesta_config_with_1_srv_in_default_srv_group,
            ),
            marks.Param(
                name="server_from_srv_group",
                first_config=_set_tempesta_config_with_2_srv_in_srv_group,
                second_config=_set_tempesta_config_with_1_srv_in_srv_group,
            ),
            marks.Param(
                name="server_from_srv_group",
                first_config=_set_tempesta_config_with_2_srv_group,
                second_config=_set_tempesta_config_with_1_srv_group,
            ),
        ]
    )
    async def test_remove(self, name, first_config, second_config):
        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        first_config(self)
        await self._start_all(servers=[server_1, server_2], client=True)
        second_config(self)

        self.get_tempesta().reload()
        self.assertTrue(
            await server_1.wait_for_connections(),
            "Tempesta removed connections to a server/srv_group after reload. "
            + "But this server/srv_group was not removed.",
        )
        self.assertEqual(
            len(server_2.connections),
            0,
            "Tempesta did not remove connections to a deleted server/srv_group after reload. "
            + "But this server/srv_group was removed.",
        )

        request = client.create_request(method="GET", headers=[], authority="grp1")
        for _ in range(10):
            client.restart()
            await client.send_request(request, "200")

        self.assertIsNotNone(
            server_1.last_request,
            "Tempesta did not forward a request to a old server/srv_group after reload. "
            + "But this server/srv_group was not removed.",
        )
        self.assertIsNone(
            server_2.last_request,
            "Tempesta forwarded a request to a deleted server/srv_group after reload. "
            + "But this server/srv_group was removed.",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="new_server_to_default_srv_group",
                first_config=_set_tempesta_config_with_1_srv_in_default_srv_group,
                second_config=_set_tempesta_config_with_2_srv_in_default_srv_group,
            ),
            marks.Param(
                name="new_server_to_srv_group",
                first_config=_set_tempesta_config_with_1_srv_in_srv_group,
                second_config=_set_tempesta_config_with_2_srv_in_srv_group,
            ),
            marks.Param(
                name="new_server_group",
                first_config=_set_tempesta_config_with_1_srv_group,
                second_config=_set_tempesta_config_with_2_srv_group,
            ),
        ]
    )
    async def test_add(self, name, first_config, second_config):
        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        first_config(self)
        await self._start_all(servers=[server_1], client=True)
        second_config(self)

        self.get_tempesta().reload()
        server_2.start()
        self.assertTrue(
            await server_1.wait_for_connections(),
            "Tempesta removed connections to a old server/srv_group after reload. "
            + "But this server/srv_group was not removed.",
        )
        self.assertTrue(
            await server_2.wait_for_connections(),
            "Tempesta did not create connections to a new server/srv_group after reload.",
        )

        for authority in ["grp1", "grp2"] * 5:
            client.restart()
            await client.send_request(
                client.create_request(method="GET", headers=[], authority=authority), "200"
            )

        self.assertIsNotNone(
            server_1.last_request,
            "Tempesta did not forward a request to a old server/srv_group after reload."
            + "But this server/srv_group was not removed.",
        )
        self.assertIsNotNone(
            server_2.last_request,
            "Tempesta did not forward a request to a new server/srv_group after reload.",
        )


class TestServerOptionsReconf(tester.TempestaTest):
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
    ]

    sniffer_timeout = 5

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.dmesg = dmesg.DmesgFinder(disable_ratelimit=True)
        self.sniffer = analyzer.Sniffer(
            node=remote.tempesta, host="Tempesta", timeout=self.sniffer_timeout, ports=[8000]
        )

    def _set_tempesta_config_with_server_retry_nonidempotent(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{
    http_strict_host_checking false;
    http_methods GET;
}}
srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 3;
    server_retry_nonidempotent;
}}

location prefix "/" {{
    nonidempotent GET prefix "/";
}}
"""
        )

    def _set_tempesta_config_without_server_retry_nonidempotent(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{
    http_strict_host_checking false;
    http_methods GET;
}}
srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 3;
}}

location prefix "/" {{
    nonidempotent GET prefix "/";
}}
"""
        )

    def _set_tempesta_config_without_health(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

server_failover_http 502 5 10;

health_check h_monitor1 {{
    request		"GET / HTTP/1.0";
    request_url	"/status/";
    resp_code	200;
    resp_crc32	auto;
    timeout		10;
}}

srv_group default {{
    server {SERVER_IP}:8000;
}}
"""
        )

    def _set_tempesta_config_with_health(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

server_failover_http 502 5 10;

health_check h_monitor1 {{
    request		"GET / HTTP/1.0";
    request_url	"/status/";
    resp_code	200;
    resp_crc32	auto;
    timeout		10;
}}

srv_group default {{
    server {SERVER_IP}:8000;
    health h_monitor1;
}}
"""
        )

    def _set_tempesta_config_server_forward_timeout_enabled(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 1000;
    server_forward_timeout 1;
}}
"""
        )

    def _set_tempesta_config_server_forward_timeout_disabled(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 1000;
    server_forward_timeout 60;
}}
"""
        )

    def _set_tempesta_config_server_queue_size_2(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000 conns_n=1;
    server_forward_retries 1000;
    server_queue_size 0;
}}
"""
        )

    def _set_tempesta_config_server_queue_size_1(self):
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000 conns_n=1;
    server_forward_retries 1000;
    server_queue_size 1;
}}
"""
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="from_10",
                old_srv_conn_retries="server_connect_retries 10;",
            ),
            marks.Param(
                name="from_default",
                old_srv_conn_retries="",
            ),
            marks.Param(
                name="from_0",
                old_srv_conn_retries="server_connect_retries 0;",
            ),
        ]
    )
    async def test_reconf_server_connect_retries(self, name, old_srv_conn_retries):
        new_srv_conn_retries = 3
        tempesta = self.get_tempesta()
        server = self.get_server("deproxy")
        server.conns_n = 2
        server.drop_conn_when_request_received = True

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000 conns_n=2;
    {old_srv_conn_retries}
}}
"""
        )

        await self.start_all_services()

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000 conns_n=2;
    server_connect_retries {new_srv_conn_retries};
}}
"""
        )

        tempesta.reload()

        client = self.get_client("deproxy")
        client.make_request(client.create_request(method="GET", headers=[]))

        self.assertTrue(await server.wait_for_requests(1))
        server.reset_new_connections()
        server.drop_conn_when_request_received = False

        self.assertTrue(await client.wait_for_response(15))
        self.assertEqual(client.last_response.status, "200")

        self.loggers.dmesg.update()
        self.assertFalse(
            self.loggers.dmesg.log_findall(
                "request dropped: unable to find an available back end server",
            ),
            "An unexpected number of warnings were received",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(name="from_default", old_srv_forward_retries=""),
            marks.Param(name="from_0", old_srv_forward_retries="server_forward_retries 0;"),
            marks.Param(name="from_1", old_srv_forward_retries="server_forward_retries 1;"),
            marks.Param(name="from_x", old_srv_forward_retries="server_forward_retries 10;"),
        ]
    )
    async def test_reconf_server_forward_retries(self, name, old_srv_forward_retries):
        server_forward_retries = 3

        client = self.get_client("deproxy")
        tempesta = self.get_tempesta()
        self.get_server("deproxy").drop_conn_when_request_received = True

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000;
    {old_srv_forward_retries}
}}
"""
        )

        await self.start_all_services()

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries {server_forward_retries};
}}
"""
        )

        await self.sniffer.start()
        tempesta.reload()
        await client.send_request(client.create_request(method="GET", headers=[]), "504")
        self.sniffer.stop()

        self.assertTrue(
            await self.dmesg.find(
                "Warning: request evicted: the number of retries exceeded, status 504:"
            ),
            DMESG_WARNING,
        )

        forward_tries = len([p for p in self.sniffer.packets if p[TCP].flags & PSH])
        self.assertEqual(
            server_forward_retries + 1,
            forward_tries,
            "Tempesta made forward attempts not equal to `server_forward_retries` after reload.",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="enabled",
                first_config=_set_tempesta_config_server_forward_timeout_disabled,
                second_config=_set_tempesta_config_server_forward_timeout_enabled,
                dmesg_cond=dmesg.amount_one,
                expect_response=True,
            ),
            marks.Param(
                name="disabled",
                first_config=_set_tempesta_config_server_forward_timeout_enabled,
                second_config=_set_tempesta_config_server_forward_timeout_disabled,
                dmesg_cond=dmesg.amount_zero,
                expect_response=False,
            ),
        ]
    )
    async def test_reconf_server_forward_timeout(
        self, name, first_config, second_config, dmesg_cond, expect_response
    ):
        client = self.get_client("deproxy")
        self.get_server("deproxy").drop_conn_when_request_received = True

        first_config(self)
        await self.start_all_services()
        second_config(self)
        self.get_tempesta().reload()

        client.make_request(client.create_request(method="GET", headers=[]))
        await client.wait_for_response(timeout=2, strict=expect_response)

        self.assertTrue(
            await self.dmesg.find("request evicted: timed out, status", cond=dmesg_cond),
            DMESG_WARNING,
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="enabled",
                first_config=_set_tempesta_config_without_server_retry_nonidempotent,
                second_config=_set_tempesta_config_with_server_retry_nonidempotent,
                expected_warning="the number of retries exceeded",
            ),
            marks.Param(
                name="disabled",
                first_config=_set_tempesta_config_with_server_retry_nonidempotent,
                second_config=_set_tempesta_config_without_server_retry_nonidempotent,
                expected_warning="non-idempotent requests aren't re-forwarded or re-scheduled",
            ),
        ]
    )
    async def test_reconf_server_retry_nonidempotent(
        self, name, first_config, second_config, expected_warning
    ):
        client = self.get_client("deproxy")
        self.get_server("deproxy").drop_conn_when_request_received = True

        first_config(self)
        await self.start_all_services()
        second_config(self)
        self.get_tempesta().reload()

        await client.send_request(client.create_request(method="GET", headers=[]), "504")
        self.assertTrue(await self.dmesg.find(expected_warning), DMESG_WARNING)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="enabled",
                first_config=_set_tempesta_config_without_health,
                second_config=_set_tempesta_config_with_health,
                dmesg_cond=dmesg.amount_one,
            ),
            marks.Param(
                name="disabled",
                first_config=_set_tempesta_config_with_health,
                second_config=_set_tempesta_config_without_health,
                dmesg_cond=dmesg.amount_zero,
            ),
        ]
    )
    async def test_reconf_health(self, name, first_config, second_config, dmesg_cond):
        client = self.get_client("deproxy")
        self.get_server("deproxy").set_response(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        )

        first_config(self)
        await self.start_all_services()
        second_config(self)
        self.get_tempesta().reload()

        request = client.create_request(method="GET", headers=[], uri="/status/")
        client.make_requests(requests=[request] * 6)  # server_failover_http 502 5 10
        await client.wait_for_response(strict=True)

        self.assertTrue(
            await self.dmesg.find(
                pattern="server has been suspended: limit for bad responses is exceeded",
                cond=dmesg_cond,
            ),
            DMESG_WARNING,
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="enabled",
                first_config=_set_tempesta_config_server_queue_size_1,
                second_config=_set_tempesta_config_server_queue_size_2,
                expect_502_statuses=0,
            ),
            marks.Param(
                name="disabled",
                first_config=_set_tempesta_config_server_queue_size_2,
                second_config=_set_tempesta_config_server_queue_size_1,
                expect_502_statuses=5,
            ),
        ]
    )
    async def test_reconf_server_queue_size(
        self, name, first_config, second_config, expect_502_statuses
    ):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.conns_n = 1
        self.get_server("deproxy").delay_before_sending_response = 1

        first_config(self)
        await self.start_all_services()
        second_config(self)
        self.get_tempesta().reload()

        request = client.create_request(method="GET", headers=[], uri="/")
        client.make_requests(requests=[request] * 5)
        await client.wait_for_response(strict=True, timeout=10)

        tempesta = self.get_tempesta()
        tempesta.get_stats()

        get_502_statuses = client.statuses.get(502, 0)

        self.assertLessEqual(
            get_502_statuses,
            expect_502_statuses,
        )
        self.assertEqual(tempesta.stats.cl_msg_other_errors, get_502_statuses)

        self.assertFalse(client.conn_is_closed)


class TestVhostReconf(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nVhost: grp1\r\n\r\n",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nVhost: grp2\r\n\r\n",
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
    ]

    def _set_tempesta_config_with_1_vhost(self):
        self.get_tempesta().config.set_defconfig(
            f"""
    listen 443 proto=h2;
    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;    
    frang_limits {{http_strict_host_checking false;}}    
    
    block_action attack reply;
    srv_group grp1 {{
        server {SERVER_IP}:8000;
    }}

    vhost grp1 {{
        proxy_pass grp1;
    }}

    http_chain {{
        -> grp1;
    }}
    """
        )

    def _set_tempesta_config_with_2_vhost(self):
        self.get_tempesta().config.set_defconfig(
            f"""
    listen 443 proto=h2;
    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;
    frang_limits {{http_strict_host_checking false;}}
    
    block_action attack reply;

    srv_group grp1 {{
        server {SERVER_IP}:8000;
    }}
    srv_group grp2 {{
        server {SERVER_IP}:8001;
    }}

    vhost grp1 {{
        proxy_pass grp1;
    }}
    vhost grp2 {{
        proxy_pass grp2;
    }}

    http_chain {{
        host == "grp1" -> grp1;
        host == "grp2" -> grp2;
        -> block;
    }}
    """
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="add_vhost",
                first_config=_set_tempesta_config_with_1_vhost,
                second_config=_set_tempesta_config_with_2_vhost,
                server_headers=("grp1", "grp2"),
            ),
            marks.Param(
                name="remove_vhost",
                first_config=_set_tempesta_config_with_2_vhost,
                second_config=_set_tempesta_config_with_1_vhost,
                server_headers=("grp1", "grp1"),
            ),
        ]
    )
    async def test(self, name, first_config, second_config, server_headers):
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")
        self.get_server("deproxy-1").start()
        self.get_server("deproxy-2").start()
        self.deproxy_manager.start()

        first_config(self)
        tempesta.start()
        second_config(self)
        tempesta.reload()
        await self.wait_all_connections()

        for authority, server_header in zip(["grp1", "grp2"], server_headers):
            client.restart()
            await client.send_request(
                client.create_request(method="GET", headers=[], authority=authority), "200"
            )
            self.assertEqual(client.last_response.headers.get("Vhost"), server_header)

    async def test_change_vhost_name(self):
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy-1")

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;        
frang_limits {{http_strict_host_checking false;}}
block_action attack reply;
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
"""
        )
        server.start()
        tempesta.start()
        self.deproxy_manager.start()
        await server.wait_for_connections()
        client.start()

        tempesta.config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{http_strict_host_checking false;}}
block_action attack reply;
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost grp2 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp2;
}}
"""
        )

        tempesta.reload()

        await client.send_request(
            client.create_request(method="GET", headers=[], authority="grp2"), "200"
        )
        self.assertIsNotNone(server.last_request)


class TestProxyPassReconf(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nVhost: grp1\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nVhost: grp2\r\nContent-Length: 0\r\n\r\n",
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
    ]

    def _set_tempesta_config_with_proxy_pass(self, proxy_pass: str) -> None:
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{http_strict_host_checking false;}}  
block_action attack reply;

server {SERVER_IP}:8000;

srv_group grp1 {{
    server {SERVER_IP}:8001;
}}

vhost grp1 {{
    proxy_pass {proxy_pass};
}}

http_chain {{
    host == "grp1" -> grp1;
    -> block;
}}
"""
        )

    def _set_tempesta_config_with_backup_group(self, backup_group: str) -> None:
        self.get_tempesta().config.set_defconfig(
            f"""
listen 443 proto=h2;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{http_strict_host_checking false;}}  
block_action attack reply;

server {SERVER_IP}:8000;

srv_group grp1 {{
    server {SERVER_IP}:8001;
}}

srv_group grp2 {{
    server {SERVER_IP}:8001;
}}

vhost grp1 {{
    proxy_pass grp1 backup={backup_group};
}}

http_chain {{
    host == "grp1" -> grp1;
    -> block;
}}
"""
        )

    async def test_reconf_group(self):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy-1")

        self._set_tempesta_config_with_proxy_pass(proxy_pass="grp1")
        await self.start_all_services()
        self._set_tempesta_config_with_proxy_pass(proxy_pass="default")
        self.get_tempesta().reload()

        await client.send_request(
            client.create_request(method="GET", headers=[], authority="grp1"), "200"
        )
        await client.send_request(
            client.create_request(method="GET", headers=[], authority="grp2"), "403"
        )
        self.assertEqual(len(server.requests), 1)

    async def test_reconf_backup_group(self):
        client = self.get_client("deproxy")
        default_server = self.get_server("deproxy-1")
        server_grp1 = self.get_server("deproxy-2")

        self._set_tempesta_config_with_backup_group(backup_group="grp2")
        await self.start_all_services()
        self._set_tempesta_config_with_backup_group(backup_group="default")
        self.get_tempesta().reload()

        server_grp1.stop()
        # Remove after #2111 in Tempesta
        await asyncio.sleep(1)

        await client.send_request(
            client.create_request(method="GET", headers=[], authority="grp1"), "200"
        )
        self.assertIsNotNone(default_server.last_request)


class TestLocationReconf(tester.TempestaTest):
    """
    The syntax from wiki:
    location <OP> "<string>" {
        <directive>;
        ...
        <directive>;
    }
    """

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
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def _set_tempesta_config_with_1_location(self):
        self.get_tempesta().config.set_defconfig(
            f"""
    listen 443 proto=h2;
    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;        

    block_action attack reply;
    
    server {SERVER_IP}:8000;

    location prefix "/static/" {{
        resp_hdr_add x-my-hdr /static/;
    }}
    """
        )

    def _set_tempesta_config_with_2_location(self):
        self.get_tempesta().config.set_defconfig(
            f"""
    listen 443 proto=h2;
    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;

    block_action attack reply;

    server {SERVER_IP}:8000;

    location prefix "/static/" {{
        resp_hdr_add x-my-hdr /static/;
    }}
    location prefix "/dynamic/" {{
        resp_hdr_add x-my-hdr /dynamic/;
    }}
    """
        )

    def _set_tempesta_config_with_directive(self, directive: str):
        self.get_tempesta().config.set_defconfig(
            f"""
    listen 443 proto=h2;
    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;        

    block_action attack reply;

    server {SERVER_IP}:8000;

    location prefix "/static/" {{
        {directive}
    }}
    """
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="add_location",
                first_config=_set_tempesta_config_with_1_location,
                second_config=_set_tempesta_config_with_2_location,
                expected_headers=("/static/", "/dynamic/"),
            ),
            marks.Param(
                name="remove_location",
                first_config=_set_tempesta_config_with_2_location,
                second_config=_set_tempesta_config_with_1_location,
                expected_headers=("/static/", None),
            ),
        ]
    )
    async def test(self, name, first_config, second_config, expected_headers):
        first_config(self)
        self.disable_deproxy_auto_parser()
        await self.start_all_services()
        second_config(self)
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        for uri, expected_header in zip(["/static/", "/dynamic/"], expected_headers):
            client.restart()
            await client.send_request(
                client.create_request(method="GET", headers=[], uri=uri), "200"
            )
            self.assertEqual(client.last_response.headers.get("x-my-hdr"), expected_header)


class TestHttpTablesReconf(tester.TempestaTest):
    """
    The syntax from wiki:
    http_chain NAME {
        [ FIELD [FIELD_NAME] == (!=) ARG ] -> ACTION [ = VAL];
        ...
    }
    """

    backends = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def _set_tempesta_config_with_http_rule(self, rule: str) -> None:
        self.get_tempesta().config.set_defconfig(
            f"""
        block_action error reply;
        block_action attack reply;

        srv_group grp1 {{
            server {SERVER_IP}:8000;
        }}
        srv_group grp2 {{
            server {SERVER_IP}:8001;
        }}

        vhost grp1 {{
            proxy_pass grp1;
        }}
        vhost grp2 {{
            proxy_pass grp2;
        }}

        http_chain {{
            {rule};
            -> grp2;
        }}
        """
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="field_arg",
                first_rule='cookie "__cookie" == "value_1" -> grp1',
                second_rule='cookie "__cookie" == "value_2" -> grp1',
                cookies=["__cookie=value_1", "__cookie=value_2", "__cookie=value_2"],
            ),
            marks.Param(
                name="field_name",
                first_rule='cookie "__old" == "value_1" -> grp1',
                second_rule='cookie "__new" == "value_1" -> grp1',
                cookies=["__old=value_1", "__new=value_1", "__new=value_1"],
            ),
            marks.Param(
                name="condition",
                first_rule='cookie "__old" == "value_1" -> grp1',
                second_rule='cookie "__old" != "value_1" -> grp1',
                cookies=["__old=value_1", "__old=value_2", "__old=value_2"],
            ),
        ]
    )
    async def test_reconf(self, name, first_rule, second_rule, cookies):
        self._set_tempesta_config_with_http_rule(rule=first_rule)
        await self.start_all_services()
        self._set_tempesta_config_with_http_rule(rule=second_rule)
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        for cookie in cookies:
            await client.send_request(
                request=client.create_request(method="GET", headers=[("cookie", cookie)]),
                expected_status_code="200",
            )

        self.assertEqual(len(server_1.requests), 2)
        self.assertEqual(len(server_2.requests), 1)

    async def test_reconf_action(self):
        self._set_tempesta_config_with_http_rule(rule='cookie "__old" == "value_1" -> grp1')
        await self.start_all_services()
        self._set_tempesta_config_with_http_rule(rule='cookie "__old" == "value_1" -> block')
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        for cookie in ["__old=value_2", "__old=value_1"]:
            await client.send_request(
                request=client.create_request(method="GET", headers=[("cookie", cookie)]),
            )

        self.assertEqual(len(server_1.requests), 0)
        self.assertEqual(len(server_2.requests), 1)

    async def test_reconf_val(self):
        self._set_tempesta_config_with_http_rule(rule='uri == "*/services.html" -> 303=/services_1')
        await self.start_all_services()
        self._set_tempesta_config_with_http_rule(rule='uri == "*/services.html" -> 303=/services_2')
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        await client.send_request(
            request=client.create_request(method="GET", headers=[], uri="/services.html"),
            expected_status_code="303",
        )

        self.assertEqual(client.last_response.headers.get("location"), "/services_2")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="add_rule",
                first_rule='uri == "*/services.html" -> 303 = /services',
                second_rule='method == "HEAD" -> block;\nuri == "*/services.html" -> 303 = /services',
                expected_status="403",
            ),
            marks.Param(
                name="remove_rule",
                first_rule='method == "HEAD" -> block;\nuri == "*/services.html" -> 303 = /services',
                second_rule='uri == "*/services.html" -> 303 = /services',
                expected_status="303",
            ),
        ]
    )
    async def test(self, name, first_rule, second_rule, expected_status):
        self._set_tempesta_config_with_http_rule(rule=first_rule)
        await self.start_all_services()
        self._set_tempesta_config_with_http_rule(rule=second_rule)
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        await client.send_request(
            request=client.create_request(method="GET", headers=[], uri="/services.html"),
            expected_status_code="303",
        )
        await client.send_request(
            request=client.create_request(method="HEAD", headers=[], uri="/services.html"),
            expected_status_code=expected_status,
        )


class TestNegativeReconf(tester.TempestaTest):
    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "4443", "ssl": True}
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    base_tempesta_config = f"""
listen 4443 proto=https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;
frang_limits {{http_strict_host_checking false;}}
"""

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="server",
                valid_config=f"server {SERVER_IP}:8000;\n",
                invalid_config=f"server {SERVER_IP}:8000:443;\n",
            ),
            marks.Param(
                name="srv_group",
                valid_config=f"srv_group default {{\nserver {SERVER_IP}:8000;\n}}\n",
                invalid_config=f"srv_group default grp2 {{\nserver {SERVER_IP}:8000;\n}}\n",
            ),
            marks.Param(
                name="srv_group_options",
                valid_config=f"""
srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 1000;
}}
            """,
                invalid_config=f"""
srv_group default {{
    server {SERVER_IP}:8000;
    server_forward_retries 1000 100;
}}
            """,
            ),
            marks.Param(
                name="vhost",
                valid_config=f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost grp1 {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
            """,
                invalid_config=f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}

vhost prefix "/" {{
    proxy_pass grp1;
}}

http_chain {{
    -> grp1;
}}
            """,
            ),
            marks.Param(
                name="proxy_pass",
                valid_config=f"""
server {SERVER_IP}:8000;
srv_group grp1 {{
    server {SERVER_IP}:8001;
}}
vhost grp1 {{
    proxy_pass grp1 backup=default;
}}
http_chain {{
    -> grp1;
}}
            """,
                invalid_config=f"""
server {SERVER_IP}:8000;
srv_group grp1 {{
    server {SERVER_IP}:8001;
}}
vhost grp1 {{
    proxy_pass grp1 backup=;
}}
http_chain {{
    -> grp1;
}}
            """,
            ),
            marks.Param(
                name="location",
                valid_config=f"""
server {SERVER_IP}:8000;
location prefix "/static/" {{
    resp_hdr_add x-my-hdr /;
}}
            """,
                invalid_config=f"""
server {SERVER_IP}:8000;
location {{
    resp_hdr_add x-my-hdr /;
}}
            """,
            ),
            marks.Param(
                name="http_chain",
                valid_config=f"""
srv_group default {{
    server {SERVER_IP}:8000;
}}
srv_group grp1 {{
    server {SERVER_IP}:8001;
}}
vhost default {{
    proxy_pass default;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    cookie "__cookie" == "value_1" -> grp1;
    -> default;
}}
            """,
                invalid_config=f"""
srv_group default {{
    server {SERVER_IP}:8000;
}}
srv_group grp1 {{
    server {SERVER_IP}:8001;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    cookie "__cookie" == "value_1";
    -> default;
}}
            """,
            ),
            marks.Param(
                name="server_1",
                valid_config=f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    -> grp1;
}}
            """,
                invalid_config=f"""
srv_group grp1 {{
    server_error {SERVER_IP}:8000;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    -> grp1;
}}
            """,
            ),
            marks.Param(
                name="listen",
                valid_config=f"""
srv_group grp1 {{
    server {SERVER_IP}:8000;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    -> grp1;
}}
            """,
                invalid_config=f"""
listen aaaaa;

srv_group grp1 {{
    server {SERVER_IP}:8000;
}}
vhost grp1 {{
    proxy_pass grp1;
}}
http_chain {{
    -> grp1;
}}
            """,
            ),
        ]
    )
    async def test_negative_reconf(self, name, valid_config, invalid_config):
        tempesta = self.get_tempesta()
        self.oops_ignore = ["ERROR"]

        tempesta.config.set_defconfig(self.base_tempesta_config + valid_config)
        tempesta.start()
        tempesta.config.set_defconfig(self.base_tempesta_config + invalid_config)
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.reload()

        port_checker = port_checks.FreePortsChecker()
        with self.assertRaises(Exception):
            port_checker.node = remote.tempesta
            port_checker.add_port_to_checks(ip=cfg.get("Tempesta", "ip"), port=4443)
            port_checker.check_ports_status(verbose=False)

        self.assertTrue(
            await self.loggers.dmesg.find("ERROR: configuration parsing error", amount_positive)
        )

        await self.start_all_services()
        client = self.get_client("deproxy")
        await client.send_request(client.create_request(method="GET", headers=[], uri="/"), "200")


class TestCtrlFrameMultiplier(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

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
            server ${server_ip}:8000;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="invalid_1", config="ctrl_frame_rate_multiplier 131072;\n"),
            marks.Param(name="invalid_2", config="ctrl_frame_rate_multiplier 0;\n"),
        ]
    )
    async def test(self, name, config):
        await self.start_all_services()
        tempesta = self.get_tempesta()
        new_config = tempesta.config.defconfig + config
        tempesta.config.set_defconfig(new_config)
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.reload()

    def _ping(self, client):
        client.h2_connection.ping(opaque_data=b"\x00\x01\x02\x03\x04\x05\x06\x07")
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

    async def test_decrease(self):
        tempesta = self.get_tempesta()
        old_config = tempesta.config.defconfig
        new_config = old_config + "ctrl_frame_rate_multiplier 256;\n"
        tempesta.config.set_defconfig(new_config)
        await self.start_all_services()

        client = self.get_client("deproxy")
        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        self.assertTrue(await client.wait_for_ack_settings())

        for _ in range(0, 10000):
            self._ping(client)

        tempesta.config.set_defconfig(old_config)
        tempesta.reload()
        self.assertTrue(await client.wait_for_connection_close())
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_ping_frame_exceeded, 1)
