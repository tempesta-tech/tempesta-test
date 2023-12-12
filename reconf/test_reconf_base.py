__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from framework import tester
from framework.parameterize import param, parameterize, parameterize_class
from framework.x509 import CertGenerator
from helpers import remote
from helpers.tf_cfg import cfg


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

    general_workdir = cfg.get("General", "workdir")
    server_config = f"""
server {cfg.get('Server', 'ip')}:8000;
tls_certificate {general_workdir}/tempesta.crt;
tls_certificate_key {general_workdir}/tempesta.key;
tls_match_any_server_name;
"""
    proto: str

    @classmethod
    def setUpClass(cls):
        cert_path = f"{cls.general_workdir}/tempesta.crt"
        key_path = f"{cls.general_workdir}/tempesta.key"
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
