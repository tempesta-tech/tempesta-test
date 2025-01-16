"""
Tests for JA5 Hash Filtering and Configuration Parsing
"""

import string
import typing
from dataclasses import dataclass

from helpers import remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
from helpers.error import ProcessBadExitStatusException
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass()
class DmesgJa5RequestRecord:
    ja5h: str
    ja5t: str


def gen_curl_ja5t_cmd(
    alpn: typing.Literal["http2", "http1.1"] = "http2",
    tls: typing.Literal["tlsv1.2", "tlsv1.3"] = "tlsv1.2",
    ciphers: str = "DHE-RSA-AES128-GCM-SHA256",
    curves: str = "prime256v1",
    connect_to: str = "tempesta-tech.com:443:${tempesta_ip}:443",
    url: str = "https://tempesta-tech.com/",
):
    return (
        f"--{alpn} -k --{tls} --ciphers {ciphers} --curves {curves} --connect-to {connect_to} {url}"
    )


def gen_curl_ja5h_cmd(
    http_version: typing.Literal["http2", "http1.1"] = "http2",
    method: str = "GET",
    headers: list[str] = (),
):
    headers = " ".join([f'-H "{header}"' for header in headers])
    return f"-k --{http_version} -X{method} {headers} --connect-to tempesta-tech.com:443:${{tempesta_ip}}:443 https://tempesta-tech.com/"


class BaseJa5TestSuite(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "".join(
                "HTTP/1.1 200 OK\r\n" "Content-Length: 10\r\n\r\n" "0123456789",
            ),
        }
    ]
    tempesta_tmpl = """
        listen 443 proto=https,h2;

        access_log dmesg;
        tls_certificate $tls_cert_path;
        tls_certificate_key $tls_key_path;
        tls_match_any_server_name;

        ja5t {
           hash $ja5t_hash 1 1;
        }
        ja5h {
           hash $ja5h_hash 1 1;
        }
        srv_group default {
            server $deproxy_ip:8000;
        }
        srv_group srv_grp1 {
            server $deproxy_ip:8000;
        }
        vhost default {
            proxy_pass default;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> default;
        }
    """

    limited_client: str = ""
    different_client: str = ""

    response_ok: bytes = b"0123456789"
    response_fail: bytes = b""

    just_valid_ja5t_hash_string: str = "b7007c90000"
    just_valid_ja5h_hash_string: str = "55cbf8cce0170011"

    def gen_and_install_cert(self) -> None:
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()

    def copy_certificates(self) -> tuple[str, str]:
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())

        return cert_path, key_path

    def prepare_tempesta(self, **kwargs) -> None:
        self.gen_and_install_cert()
        cert_path, key_path = self.copy_certificates()

        self.tempesta = {
            "config": string.Template(self.tempesta_tmpl).substitute(
                tls_cert_path=cert_path,
                tls_key_path=key_path,
                ja5t_hash=self.just_valid_ja5t_hash_string,
                ja5h_hash=self.just_valid_ja5h_hash_string,
                deproxy_ip=tf_cfg.cfg.get("Server", "ip"),
                **kwargs,
            ),
            "custom_cert": True,
        }

    def get_fingerprints(self) -> list[str or None]:
        self.oops.update()
        return self.oops.log_findall('.*"ja5t=(\w+)" "ja5h=(\w+)"')

    def get_client_fingerprint(self, name: str) -> DmesgJa5RequestRecord:
        client = self.get_client(name)
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.stdout, self.response_ok)

        fingerprints = self.get_fingerprints()

        if not fingerprints:
            raise ValueError("Can not receive client ja5 fingerprint")

        return DmesgJa5RequestRecord(
            ja5t=fingerprints[-1][0],
            ja5h=fingerprints[-1][1],
        )

    @staticmethod
    def reload_server(tempesta_instance):
        tempesta_instance.restart()

    def update_config_with_ja5_hash_limit(self, ja5_hash: str):
        cert_path, key_path = self.copy_certificates()
        self.tempesta = {
            "config": string.Template(self.tempesta_tmpl).substitute(
                tls_cert_path=cert_path,
                tls_key_path=key_path,
                ja5t_hash=ja5_hash,
                ja5h_hash=self.just_valid_ja5h_hash_string,
                deproxy_ip=tf_cfg.cfg.get("Server", "ip"),
            ),
            "custom_cert": True,
        }
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(
            string.Template(self.tempesta_tmpl).substitute(
                tls_cert_path=cert_path,
                tls_key_path=key_path,
                ja5t_hash=ja5_hash,
                ja5h_hash=self.just_valid_ja5h_hash_string,
                deproxy_ip=tf_cfg.cfg.get("Server", "ip"),
            ),
            custom_cert=True,
        )
        self.reload_server(tempesta)


class BaseParametrizedFilterTestSuite(BaseJa5TestSuite):
    @staticmethod
    def __gen_client(name: str, value: int, cmd: str):
        return {
            "id": f"{name}-{value}",
            "type": "external",
            "binary": "curl",
            "cmd_args": cmd,
        }

    @staticmethod
    def get_hash(fingerprint: DmesgJa5RequestRecord) -> str:
        return fingerprint.ja5t

    def update_config_with_ja5_hash_limit(self, ja5t_hash: str = None, ja5h_hash: str = None):
        cert_path, key_path = self.copy_certificates()
        self.tempesta = {
            "config": string.Template(self.tempesta_tmpl).substitute(
                tls_cert_path=cert_path,
                tls_key_path=key_path,
                ja5t_hash=ja5t_hash or self.just_valid_ja5t_hash_string,
                ja5h_hash=ja5h_hash or self.just_valid_ja5h_hash_string,
                deproxy_ip=tf_cfg.cfg.get("Server", "ip"),
            ),
            "custom_cert": True,
        }
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(
            string.Template(self.tempesta_tmpl).substitute(
                tls_cert_path=cert_path,
                tls_key_path=key_path,
                ja5t_hash=ja5t_hash or self.just_valid_ja5t_hash_string,
                ja5h_hash=ja5h_hash or self.just_valid_ja5h_hash_string,
                deproxy_ip=tf_cfg.cfg.get("Server", "ip"),
            ),
            custom_cert=True,
        )
        self.reload_server(tempesta)

    def set_config_ja5_hash(self, hash_value: str):
        self.update_config_with_ja5_hash_limit(ja5t_hash=hash_value)

    def setUp(self):
        self.prepare_tempesta()

        self.clients = [
            self.__gen_client("limited", value, self.limited_client) for value in range(2)
        ]
        self.clients += [
            self.__gen_client("different", value, self.different_client) for value in range(2)
        ]
        super().setUp()

    def count_equal(self, clients: list, prefix: str, value: bytes) -> int:
        clients = list(map(self.get_client, [name for name in clients if name.startswith(prefix)]))
        return len(list(filter(lambda item: item.stdout == value, clients)))

    def run_test(self):
        self.start_all_services(client=False)
        self.deproxy_manager.start()
        self.start_tempesta()

        client_names = list(map(lambda __client: __client["id"], self.clients))
        clients = list(map(self.get_client, client_names))
        fingerprints = list(map(self.get_client_fingerprint, client_names))

        self.assertEqual(self.get_hash(fingerprints[0]), self.get_hash(fingerprints[1]))
        self.assertEqual(self.get_hash(fingerprints[-1]), self.get_hash(fingerprints[-2]))
        self.assertNotEqual(self.get_hash(fingerprints[0]), self.get_hash(fingerprints[-1]))

        self.set_config_ja5_hash(self.get_hash(fingerprints[0]))

        list(map(lambda __client: __client.start(), clients))
        list(map(self.wait_while_busy, clients))
        list(map(lambda __client: __client.stop(), clients))

        self.assertEqual(
            self.count_equal(client_names, "limited", self.response_ok),
            1,
            "One should be blocked",
        )
        self.assertEqual(
            self.count_equal(client_names, "different", self.response_ok),
            2,
            "All should be passed",
        )


@marks.parameterize_class(
    [
        # {
        #     "name": "tls",
        #     "limited_client": gen_curl_ja5t_cmd(tls='tlsv1.2', ciphers='DHE-RSA-AES128-GCM-SHA256'),
        #     "different_client": gen_curl_ja5t_cmd(tls='tlsv1.3', ciphers='TLS_AES_128_GCM_SHA256')
        # },
        # {
        #     "name": "curves",
        #     "limited_client": gen_curl_ja5t_cmd(curves='prime256v1'),
        #     "different_client": gen_curl_ja5t_cmd(curves='x25519')
        # },
        {
            "name": "ciphers",
            "limited_client": gen_curl_ja5t_cmd(ciphers="DHE-RSA-AES128-GCM-SHA256"),
            "different_client": gen_curl_ja5t_cmd(ciphers="DHE-RSA-AES256-GCM-SHA384"),
        },
        {
            "name": "vhost",
            "limited_client": gen_curl_ja5t_cmd(
                connect_to="tempesta-tech.com:443:${tempesta_ip}:443",
                url="https://tempesta-tech.com/",
            ),
            "different_client": gen_curl_ja5t_cmd(
                connect_to="tempesta-tech-2.com:443:${tempesta_ip}:443",
                url="https://tempesta-tech-2.com/",
            ),
        },
        {
            "name": "alpn",
            "limited_client": gen_curl_ja5t_cmd(alpn="http2"),
            "different_client": gen_curl_ja5t_cmd(alpn="http1.1"),
        },
    ]
)
class TestJa5TFiltersTestSuite(BaseParametrizedFilterTestSuite):
    tempesta_tmpl = """
        listen 443 proto=https;

        access_log dmesg;
        tls_certificate $tls_cert_path;
        tls_certificate_key $tls_key_path;
        tls_match_any_server_name;

        ja5t {
           hash $ja5t_hash 1 1;
        }
        ja5h {
           hash $ja5h_hash 1 1;
        }
        srv_group default {
            server $deproxy_ip:8000;
        }
        srv_group srv_grp1 {
            server $deproxy_ip:8000;
        }
        vhost default {
            proxy_pass default;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> default;
        }
    """

    def test_ja5t_hash_difference(self):
        self.run_test()


@marks.parameterize_class(
    [
        {
            "name": "http",
            "limited_client": gen_curl_ja5h_cmd(http_version="http1.1"),
            "different_client": gen_curl_ja5h_cmd(http_version="http2"),
        },
        {
            "name": "method",
            "limited_client": gen_curl_ja5h_cmd(method="GET"),
            "different_client": gen_curl_ja5h_cmd(method="POST"),
        },
        {
            "name": "headers",
            "limited_client": gen_curl_ja5h_cmd(headers=["Authorization: Bearer HELLO"]),
            "different_client": gen_curl_ja5h_cmd(
                headers=[
                    "Authorization: Bearer HELLO",
                    "X-APP-ID: application-dev-1",
                ]
            ),
        },
        {
            "name": "referer",
            "limited_client": gen_curl_ja5h_cmd(headers=["Referer: tempesta-tech.com"]),
            "different_client": gen_curl_ja5h_cmd(),
        },
        # {
        #     "name": "cookies",
        #     "limited_client": gen_curl_ja5h_cmd(headers=[
        #         'Set-Cookie: session=testing;user-id=10; Secure'
        #     ]),
        #     "different_client": gen_curl_ja5h_cmd(headers=[
        #         'Set-Cookie: session=testing;user-id=10;additional=1; Secure; HttpOnly'
        #     ]),
        # },
    ]
)
class TestJa5HFiltersTestSuite(BaseParametrizedFilterTestSuite):
    def set_config_ja5_hash(self, hash_value: str):
        self.update_config_with_ja5_hash_limit(ja5h_hash=hash_value)

    @staticmethod
    def get_hash(fingerprint: DmesgJa5RequestRecord) -> str:
        return fingerprint.ja5h

    def test_ja5h_hash_difference(self):
        self.run_test()


class TestJa5HashDoesNotMatchedWithFiltered(BaseJa5TestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_ja5t_cmd(),
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_ja5t_cmd(),
        },
    ]

    def setUp(self):
        self.prepare_tempesta()
        super().setUp()

    def test_limits(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()

        limited_1 = self.get_client("limited-1")
        limited_2 = self.get_client("limited-2")

        limited_1.start()
        limited_2.start()

        self.wait_while_busy(limited_1)
        self.wait_while_busy(limited_2)

        limited_1.stop()
        limited_2.stop()

        self.assertEqual(limited_1.stdout, self.response_ok)
        self.assertEqual(limited_2.stdout, self.response_ok)


@marks.parameterize_class(
    [
        {
            "name": "invalid_ja5t_config_value",
            "ja5t_block": "ja5t {hash invalid_hash 5 5;}",
        },
        {
            "name": "invalid_ja5t_table_size",
            "ja5t_block": "ja5t storage_size=500 {hash a7007c90000 5 5;}",
        },
        {
            "name": "invalid_ja5h_config_value",
            "ja5t_block": "ja5h {hash invalid_hash 5 5;}",
        },
        {
            "name": "invalid_ja5h_table_size",
            "ja5t_block": "ja5h storage_size=500 {hash 55cbf8cce0170011 5 5;}",
        },
    ]
)
class TestJa5ConfigTestSuite(BaseJa5TestSuite):
    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;

        access_log dmesg;
        tls_certificate $tls_cert_path;
        tls_certificate_key $tls_key_path;
        tls_match_any_server_name;

        $ja5_block

        srv_group srv_grp1 {
            server $deproxy_ip:8000;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> block;
        }
    """
    ja5t_block: str = ""

    def setUp(self):
        self.prepare_tempesta(ja5_block=self.ja5t_block)
        super().setUp()

    def test_config(self):
        self.assertRaises(ProcessBadExitStatusException, self.start_tempesta)

    def cleanup_check_dmesg(self):
        self.assertRaises(Exception, super().cleanup_check_dmesg)


class TestJa5TApplicationConfigOnTheFlyReload(BaseJa5TestSuite):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_ja5t_cmd(),
        },
    ]

    def setUp(self):
        self.prepare_tempesta()
        super().setUp()

    @staticmethod
    def reload_server(tempesta_instance):
        tempesta_instance.reload()

    def test_restart_ok(self):
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().restart()

    def test_hot_reload(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()

        client = self.get_client("curl")
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.stdout, self.response_ok)

        fingerprint = self.get_client_fingerprint("curl")
        self.update_config_with_ja5_hash_limit(ja5_hash=fingerprint.ja5t)

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.stdout, self.response_fail)
