"""
Tests for JA5 Hash Filtering and Configuration Parsing
"""

import re

from helpers import remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
from helpers.error import ProcessBadExitStatusException
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseJa5FilterTestSuite(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "".join(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 10\r\n"
                "Connection: keep-alive\r\n\r\n"
                "0123456789",
            ),
        }
    ]
    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;

        access_log dmesg;
        tls_certificate %s;
        tls_certificate_key %s;
        tls_match_any_server_name;

        ja5t {
            hash %s 5 5;
        }
        srv_group srv_grp1 {
            server %s:8000;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> block;
        }
    """

    def __copy_certificates(self) -> tuple[str, str]:
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())

        return cert_path, key_path

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()

        cert_path, key_path = self.__copy_certificates()

        any_valid_ja5_hash = "a7007c90000"
        self.tempesta = {
            "config": self.tempesta_tmpl
            % (cert_path, key_path, any_valid_ja5_hash, tf_cfg.cfg.get("Server", "ip")),
            "custom_cert": True,
        }

        super().setUp()

    @staticmethod
    def get_handshakes_amount(text: str) -> int:
        value = re.search(r"HANDSHAKES\s+(\d+)", text)

        if not value:
            return 0

        return int(value.group(1))

    @staticmethod
    def get_errors_amount(text: str) -> int:
        value = re.search(r"Errors\s+(\d+)", text)

        if not value:
            return 0

        return int(value.group(1))

    def get_fingerprints(self) -> list[str or None]:
        self.oops.update()
        return self.oops.log_findall("JA5 Fingerprint ([\w]+):")

    def get_client_fingerprint(self, name: str) -> str:
        client = self.get_client(name)
        client.start()
        self.wait_while_busy(client)
        client.stop()

        fingerprints = self.get_fingerprints()

        if not fingerprints:
            raise ValueError("Can not receive client ja5 fingerprint")

        return fingerprints[-1]

    def update_config_with_ja5_hash_limit(self, ja5_hash: str):
        cert_path, key_path = self.__copy_certificates()
        self.tempesta = {
            "config": self.tempesta_tmpl
            % (cert_path, key_path, ja5_hash, tf_cfg.cfg.get("Server", "ip")),
            "custom_cert": True,
        }
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(
            self.tempesta_tmpl % (cert_path, key_path, ja5_hash, tf_cfg.cfg.get("Server", "ip")),
            custom_cert=True,
        )
        tempesta.restart()

    def run_tests(self):
        self.start_all_servers()
        self.start_tempesta()

        limited_1_fingerprint = self.get_client_fingerprint("limited-1")
        limited_2_fingerprint = self.get_client_fingerprint("limited-2")
        different_fingerprint = self.get_client_fingerprint("different")

        self.assertEqual(limited_1_fingerprint, limited_2_fingerprint)
        self.assertNotEqual(limited_2_fingerprint, different_fingerprint)

        self.update_config_with_ja5_hash_limit(limited_1_fingerprint)

        limited_1 = self.get_client("limited-1")
        limited_2 = self.get_client("limited-2")
        different = self.get_client("different")

        limited_1.start()
        limited_2.start()
        different.start()

        self.wait_while_busy(limited_1)
        self.wait_while_busy(limited_2)
        self.wait_while_busy(different)

        limited_1.stop()
        limited_2.stop()
        different.stop()

        limited_1_stdout = limited_1.stdout.decode()
        handshakes = self.get_handshakes_amount(limited_1_stdout)
        errors = self.get_errors_amount(limited_1_stdout)
        self.assertTrue(0 < handshakes < 4, "Few connection should be accepted successfully")
        self.assertEqual(errors, 1, "Connection should be dropped once")

        limited_2_stdout = limited_2.stdout.decode()
        handshakes = self.get_handshakes_amount(limited_2_stdout)
        errors = self.get_errors_amount(limited_2_stdout)
        self.assertTrue(0 < handshakes < 4, "Few connection should be accepted successfully")
        self.assertEqual(errors, 1, "Connection should be dropped once")

        different_stdout = different.stdout.decode()
        handshakes = self.get_handshakes_amount(different_stdout)
        errors = self.get_errors_amount(different_stdout)
        self.assertEqual(handshakes, 6, "")
        self.assertEqual(errors, 0, "")


class TestJa5DifferentTLSVersion(BaseJa5FilterTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d --tls 1.2 -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d --tls 1.2 -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "different",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d --tls 1.3 -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 6 -T 1 ${tempesta_ip} 443",
        },
    ]

    test_filters = BaseJa5FilterTestSuite.run_tests


class TestJa5DifferentCurves(BaseJa5FilterTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "different",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime239v3 -n 6 -T 1 ${tempesta_ip} 443",
        },
    ]

    test_filters = BaseJa5FilterTestSuite.run_tests


class TestJa5DifferentCiphers(BaseJa5FilterTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "different",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-CCM -C prime256v1 -n 6 -T 1 ${tempesta_ip} 443",
        },
    ]

    test_filters = BaseJa5FilterTestSuite.run_tests


class TestJa5DifferentVHostFound(BaseJa5FilterTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "different",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d --sni tempesta-tech.com -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 6 -T 1 ${tempesta_ip} 443",
        },
    ]

    test_filters = BaseJa5FilterTestSuite.run_tests


class TestJa5HashDoesNotMatched(BaseJa5FilterTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": "-d -c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -n 4 -T 1 ${tempesta_ip} 443",
        },
    ]

    def test_limits(self):
        self.start_all_servers()
        self.start_tempesta()

        limited_1 = self.get_client("limited-1")
        limited_2 = self.get_client("limited-2")

        limited_1.start()
        limited_2.start()

        self.wait_while_busy(limited_1)
        self.wait_while_busy(limited_2)

        limited_1.stop()
        limited_2.stop()

        limited_1_stdout = limited_1.stdout.decode()
        handshakes = self.get_handshakes_amount(limited_1_stdout)
        errors = self.get_errors_amount(limited_1_stdout)
        self.assertEqual(
            handshakes,
            4,
        )
        self.assertEqual(
            errors,
            0,
        )

        limited_2 = limited_2.stdout.decode()
        handshakes = self.get_handshakes_amount(limited_2)
        errors = self.get_errors_amount(limited_2)
        self.assertEqual(
            handshakes,
            4,
        )
        self.assertEqual(
            errors,
            0,
        )


class BaseJa5ConfigTestSuite(tester.TempestaTest):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()

        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())

        self.tempesta = {
            "config": self.tempesta_tmpl % (cert_path, key_path),
            "custom_cert": True,
        }
        super().setUp()

    def run_test(self):
        self.assertRaises(ProcessBadExitStatusException, self.start_tempesta)

    def cleanup_check_dmesg(self):
        self.assertRaises(Exception, super().cleanup_check_dmesg)


class TestJa5InvalidConfigHashValue(BaseJa5ConfigTestSuite):
    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;

        access_log dmesg;
        tls_certificate %s;
        tls_certificate_key %s;
        tls_match_any_server_name;

        ja5t {
           hash invalid_hash 5 5;
        }

        srv_group srv_grp1 {
            server ${server_ip}:8000;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> block;
        }
    """
    test_config = BaseJa5ConfigTestSuite.run_test


class TestJa5InvalidTableSize(BaseJa5ConfigTestSuite):
    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;

        access_log dmesg;
        tls_certificate %s;
        tls_certificate_key %s;
        tls_match_any_server_name;

        ja5t storage_size=500 {
           hash a7007c90000 5 5;
        }

        srv_group srv_grp1 {
            server ${server_ip}:8000;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> block;
        }
    """
    test_config = BaseJa5ConfigTestSuite.run_test


class TestJa5ApplicationConfigRestart(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "".join(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 10\r\n"
                "Connection: keep-alive\r\n\r\n"
                "0123456789",
            ),
        }
    ]
    tempesta_tmpl = """
           cache 0;
           listen 443 proto=https;

           access_log dmesg;
           tls_certificate %s;
           tls_certificate_key %s;
           tls_match_any_server_name;

           ja5t {
              hash b7007c90000 5 5;
           }

           srv_group srv_grp1 {
               server ${server_ip}:8000;
           }
           vhost tempesta-tech.com {
               proxy_pass srv_grp1;
           }
           http_chain {
               host == "tempesta-tech.com" -> tempesta-tech.com;
               -> block;
           }
       """

    def __copy_certificates(self) -> tuple[str, str]:
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())

        return cert_path, key_path

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()

        cert_path, key_path = self.__copy_certificates()

        self.tempesta = {
            "config": self.tempesta_tmpl % (cert_path, key_path),
            "custom_cert": True,
        }
        super().setUp()

    def test_restart_ok(self):
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().restart()

    def test_reload_fail(self):
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().reload()
