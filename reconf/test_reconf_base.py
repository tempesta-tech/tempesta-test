__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from framework import tester
from framework.parameterize import param, parameterize, parameterize_class
from framework.x509 import CertGenerator
from helpers import remote
from helpers.tf_cfg import cfg

SERVER_IP = cfg.get("Server", "ip")
GENERAL_WORKDIR = cfg.get("General", "workdir")


class TestTempestaReconfiguring(tester.TempestaTest):
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
        listen 444 proto=http;
        listen 445 proto=http;
        """
    }

    tempesta_alt_gt_socks = {
        "config": """
        listen 443 proto=http;
        listen 444 proto=http;
        listen 446 proto=http;
        listen 447 proto=http;
        """
    }

    tempesta_alt_le_socks = {
        "config": """
        listen 443 proto=http;
        listen 446 proto=http;
        """
    }

    tempesta_alt_bad_socks = {
        "config": """
        listen 500 proto=http;
        listen 501 proto=http;
        listen 502 proto=http;
        listen 503 proto=http;
        listen 504 proto=http;
        listen 8000 proto=http;
        listen 505 proto=http;
        listen 506 proto=http;
        listen 507 proto=http;
        listen 508 proto=http;
        listen 509 proto=http;
        """
    }

    def test_stop(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        os.system("sysctl -e -w net.tempesta.state=stop")
        tempesta.run_start()


@parameterize_class(
    [
        {"name": "Http", "proto": "http"},
        {"name": "Https", "proto": "https"},
        {"name": "H2", "proto": "h2"},
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
    ]

    server_config = f"""
server {SERVER_IP}:8000;
tls_certificate {GENERAL_WORKDIR}/tempesta.crt;
tls_certificate_key {GENERAL_WORKDIR}/tempesta.key;
tls_match_any_server_name;
"""
    proto: str

    @classmethod
    def setUpClass(cls):
        cert_path = f"{GENERAL_WORKDIR}/tempesta.crt"
        key_path = f"{GENERAL_WORKDIR}/tempesta.key"
        cgen = CertGenerator(cert_path, key_path, True)
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())
        super().setUpClass()

    def _start_all_services_and_reload_tempesta(self, first_config: str, second_config: str):
        tempesta = self.get_tempesta()

        tempesta.config.set_defconfig(first_config + self.server_config)
        self.start_all_services(client=False)

        tempesta.config.set_defconfig(second_config + self.server_config)
        tempesta.reload()

    @parameterize.expand([param("http"), param("https"), param("h2")])
    def test_reconf_proto(self, proto):
        self._start_all_services_and_reload_tempesta(
            first_config=f"listen 443 proto={self.proto};\n",
            second_config=f"listen 443 proto={proto};\n",
        )

        client = self.get_client(proto)
        request = client.create_request(method="GET", headers=[])
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening proto after reload."):
            client.send_request(request, "200")

    def test_reconf_port(self):
        self._start_all_services_and_reload_tempesta(
            first_config=f"listen 443 proto={self.proto};\n",
            second_config=f"listen 4433 proto={self.proto};\n",
        )

        client = self.get_client(self.proto)
        request = client.create_request(method="GET", headers=[])
        client.port = 4433
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening port after reload."):
            client.send_request(request, "200")

        client.port = 443
        client.restart()

        with self.subTest(msg=f"Tempesta continued listening to the old port."):
            with self.assertRaises(AssertionError):
                client.send_request(request, "200")

    @parameterize.expand(
        [
            param(
                name="default_to_ipv4_port_default",
                first_config="",
                second_config="listen 127.0.0.1 proto={0};\n",
                old_ip="",
                new_ip="127.0.0.1",
                port=80,
            ),
            param(
                name="ipv4_to_ipv4_port_default",
                first_config="listen 127.0.0.1 proto={0};\n",
                second_config="listen 127.0.1.100 proto={0};\n",
                old_ip="127.0.0.1",
                new_ip="127.0.1.100",
                port=80,
            ),
            param(
                name="ipv4_to_ipv4_port_443",
                first_config="listen 127.0.0.1:443 proto={0};\n",
                second_config="listen 127.0.1.100:443 proto={0};\n",
                old_ip="127.0.0.1",
                new_ip="127.0.1.100",
                port=443,
            ),
        ]
    )
    def test_reconf_ip(self, name, first_config, second_config, old_ip, new_ip, port):
        self._start_all_services_and_reload_tempesta(
            first_config.format(self.proto), second_config.format(self.proto)
        )

        client = self.get_client(self.proto)
        request = client.create_request(method="GET", headers=[])
        client.conn_addr = new_ip
        client.port = port
        client.start()

        with self.subTest(msg=f"Tempesta did not change listening IP after reload."):
            client.send_request(request, "200")

        client.conn_addr = old_ip
        client.restart()

        with self.subTest(msg=f"Tempesta continued listening to old IP after reload."):
            with self.assertRaises(AssertionError):
                client.send_request(request, "200")


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

    def _start_all(self, servers: list, client: bool):
        for server in servers:
            server.start()
        self.start_tempesta()
        if client:
            self.start_all_clients()
        self.deproxy_manager.start()

        for server in servers:
            server.wait_for_connections()

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

    @parameterize.expand(
        [
            param(name="increase", conns_n_1=32, conns_n_2=64),
            param(name="decrease", conns_n_1=32, conns_n_2=16),
            param(name="increase_from_default", conns_n_1=0, conns_n_2=64),
            param(name="decrease_from_default", conns_n_1=0, conns_n_2=16),
        ]
    )
    def test_conns_n(self, name, conns_n_1, conns_n_2):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy-1")
        tempesta = self.get_tempesta()

        tempesta.config.set_defconfig(
            f"server {SERVER_IP}:8000" + f"{f' conns_n={conns_n_1}' if conns_n_1 else ''};\n"
        )
        server.conns_n = conns_n_1

        self._start_all(servers=[server], client=False)

        tempesta.config.set_defconfig(f"server {SERVER_IP}:8000 conns_n={conns_n_2};\n")
        server.conns_n = conns_n_2

        tempesta.reload()
        self.assertTrue(
            server.wait_for_connections(),
            "Tempesta did not change number of connections with server after reload.",
        )

        client.start()
        client.send_request(client.create_request(method="GET", headers=[]), "200")

    @parameterize.expand(
        [
            param(
                name="server_from_default_srv_group",
                first_config=_set_tempesta_config_with_2_srv_in_default_srv_group,
                second_config=_set_tempesta_config_with_1_srv_in_default_srv_group,
            ),
            param(
                name="server_from_srv_group",
                first_config=_set_tempesta_config_with_2_srv_in_srv_group,
                second_config=_set_tempesta_config_with_1_srv_in_srv_group,
            ),
            param(
                name="server_from_srv_group",
                first_config=_set_tempesta_config_with_2_srv_group,
                second_config=_set_tempesta_config_with_1_srv_group,
            ),
        ]
    )
    def test_remove(self, name, first_config, second_config):
        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        first_config(self)
        self._start_all(servers=[server_1, server_2], client=True)
        second_config(self)

        self.get_tempesta().reload()
        self.assertTrue(
            server_1.wait_for_connections(),
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
            client.send_request(request, "200")

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

    @parameterize.expand(
        [
            param(
                name="new_server_to_default_srv_group",
                first_config=_set_tempesta_config_with_1_srv_in_default_srv_group,
                second_config=_set_tempesta_config_with_2_srv_in_default_srv_group,
            ),
            param(
                name="new_server_to_srv_group",
                first_config=_set_tempesta_config_with_1_srv_in_srv_group,
                second_config=_set_tempesta_config_with_2_srv_in_srv_group,
            ),
            param(
                name="new_server_group",
                first_config=_set_tempesta_config_with_1_srv_group,
                second_config=_set_tempesta_config_with_2_srv_group,
            ),
        ]
    )
    def test_add(self, name, first_config, second_config):
        client = self.get_client("deproxy")
        server_1 = self.get_server("deproxy-1")
        server_2 = self.get_server("deproxy-2")

        first_config(self)
        self._start_all(servers=[server_1], client=True)
        second_config(self)

        self.get_tempesta().reload()
        server_2.start()
        self.assertTrue(
            server_1.wait_for_connections(),
            "Tempesta removed connections to a server/srv_group after reload. "
            + "But this server/srv_group was not removed.",
        )
        self.assertTrue(
            server_1.wait_for_connections(),
            "Tempesta did not create connections to a new server/srv_group after reload.",
        )

        for authority in ["grp1", "grp2"] * 5:
            client.restart()
            client.send_request(
                client.create_request(method="GET", headers=[], authority=authority), "200"
            )

        self.assertIsNotNone(
            server_1.last_request,
            "Tempesta did not forward a request to a server/srv_group after reload."
            + "But this server/srv_group was not removed.",
        )
        self.assertIsNotNone(
            server_2.last_request,
            "Tempesta did not forward a request to a new server/srv_group after reload.",
        )
