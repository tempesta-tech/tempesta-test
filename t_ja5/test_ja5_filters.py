"""
Tests for JA5 Hash Filtering and Configuration Parsing
"""

import os.path
import string
import typing

from helpers.access_log import AccessLogLine
from helpers.error import ProcessBadExitStatusException
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class CustomTemplate(string.Template):
    delimiter = "&"


def gen_curl_ja5t_cmd(
    alpn: typing.Optional[typing.Literal["http2", "http1.1"]] = "http1.1",
    tls: typing.Literal["tlsv1.2", "tlsv1.3"] = "tlsv1.2",
    ciphers: str = "ECDHE-ECDSA-AES128-GCM-SHA256",
    curves: str = "prime256v1",
    connect_to: str = "tempesta-tech.com:443:${tempesta_ip}:443",
    url: str = "https://tempesta-tech.com/",
):
    if alpn is None:
        alpn = "no-alpn"

    return (
        f"--{alpn} -k --{tls} --ciphers {ciphers} --curves {curves} --connect-to {connect_to} {url}"
    )


def gen_curl_ja5h_cmd(
    http_version: typing.Literal["http2", "http1.1"] = "http1.1",
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
    additional_conf_dir = "/tmp/tempesta-filters/"
    additional_conf_file = additional_conf_dir + "ja5_filters.conf"
    tempesta = {
        "type": "tempesta",
        "config": """
        listen 443 proto=https,h2;

        access_log dmesg;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        !include %(path)s
        
        srv_group default {
            server ${server_ip}:8000;
        }
        srv_group srv_grp1 {
            server ${server_ip}:8000;
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
        % {"path": additional_conf_dir},
    }

    limited_client: str = ""
    different_client: str = ""

    response_ok: bytes = b"0123456789"
    response_fail: bytes = b""

    just_valid_ja5t_hash_string: str = "b7007c90000"
    just_valid_ja5h_hash_string: str = "55cbf8cce0170011"

    hash_type: typing.Literal["ja5t", "ja5h"] = None

    def clean_up(self):
        if os.path.exists(self.additional_conf_file):
            os.remove(self.additional_conf_file)

    def setUp(self):
        super().setUp()
        self.addCleanup(self.clean_up)

    def get_hash(self, fingerprint: AccessLogLine) -> str:
        return getattr(fingerprint, self.hash_type)

    def get_fingerprints(self) -> list[str or None]:
        return self.loggers.dmesg.log_findall('.*"ja5t=(\w+)" "ja5h=(\w+)"')

    def get_client_fingerprint(self, name: str) -> AccessLogLine:
        client = self.get_client(name)
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.stdout, self.response_ok)

        self.loggers.dmesg.update()
        fingerprints = AccessLogLine.parse_all(self.loggers.dmesg.log.decode())

        if not fingerprints:
            raise ValueError("Can not receive client ja5 fingerprint")

        return fingerprints[0]

    def write_ja5_config(self, text: str):
        os.makedirs(self.additional_conf_dir, exist_ok=True)

        with open(self.additional_conf_file, "w") as f:
            f.write(text)

    def update_config_with_ja5_hash_limit(
        self, ja5t_hash: str = None, ja5h_hash: str = None, reload: bool = True
    ):
        line = "ja5t {{ {} }}\nja5h {{ {} }}\n".format(
            f"hash {ja5t_hash} 1 1;" if ja5t_hash else "",
            f"hash {ja5h_hash} 1 1;" if ja5h_hash else "",
        )
        self.write_ja5_config(line)

        if not reload:
            return

        tempesta = self.get_tempesta()
        tempesta.reload()

    def set_config_ja5_hash(self, hash_value: str):
        key = f"{self.hash_type}_hash"
        kwargs = {key: hash_value}
        self.update_config_with_ja5_hash_limit(**kwargs)


@marks.parameterize_class(
    [
        {
            "name": "Tls",
            "hash_type": "ja5t",
            "limited_client": gen_curl_ja5t_cmd(tls="tlsv1.2", ciphers="DHE-RSA-AES128-GCM-SHA256"),
            "different_client": gen_curl_ja5t_cmd(tls="tlsv1.3", ciphers="TLS_AES_128_GCM_SHA256"),
        },
        {
            "name": "Curves",
            "hash_type": "ja5t",
            "limited_client": gen_curl_ja5t_cmd(curves="prime256v1"),
            "different_client": gen_curl_ja5t_cmd(curves="x25519"),
        },
        {
            "name": "Ciphers",
            "hash_type": "ja5t",
            "limited_client": gen_curl_ja5t_cmd(ciphers="ECDHE-ECDSA-AES128-GCM-SHA256"),
            "different_client": gen_curl_ja5t_cmd(ciphers="ECDHE-ECDSA-AES256-GCM-SHA384"),
        },
        {
            "name": "Vhost",
            "hash_type": "ja5t",
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
            "name": "Alpn",
            "hash_type": "ja5t",
            "limited_client": gen_curl_ja5t_cmd(alpn="http1.1"),
            "different_client": gen_curl_ja5t_cmd(alpn="http2"),
        },
        {
            "name": "NoAlpn",
            "hash_type": "ja5t",
            "limited_client": gen_curl_ja5t_cmd(alpn="http1.1"),
            "different_client": gen_curl_ja5t_cmd(alpn=None),
        },
        {
            "name": "Http",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(http_version="http1.1"),
            "different_client": gen_curl_ja5h_cmd(http_version="http2"),
        },
        {
            "name": "Method",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(method="GET"),
            "different_client": gen_curl_ja5h_cmd(method="POST"),
        },
        {
            "name": "Headers",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(headers=["Authorization: Bearer HELLO"]),
            "different_client": gen_curl_ja5h_cmd(
                headers=[
                    "Authorization: Bearer HELLO",
                    "X-APP-ID: application-dev-1",
                ]
            ),
        },
        {
            "name": "Referer",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(headers=["Referer: tempesta-tech.com"]),
            "different_client": gen_curl_ja5h_cmd(),
        },
        {
            "name": "Cookies",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(headers=["Cookie: session=testing"]),
            "different_client": gen_curl_ja5h_cmd(
                headers=[
                    "Cookie: session=testing; session2=testing2",
                ]
            ),
        },
        {
            "name": "Cookies-2",
            "hash_type": "ja5h",
            "limited_client": gen_curl_ja5h_cmd(headers=["Cookie: aaa=b; cccc=d; qq=dd"]),
            "different_client": gen_curl_ja5h_cmd(
                headers=[
                    "Cookie: aaa=b; cccc=d; qq=dd; ww=1",
                ]
            ),
        },
    ]
)
class TestJa5FiltersTestSuite(BaseJa5TestSuite):
    @staticmethod
    def __gen_client(name: str, value: int, cmd: str):
        return {
            "id": f"{name}-{value}",
            "type": "external",
            "binary": "curl",
            "cmd_args": cmd,
        }

    def count_equal(self, clients: list, prefix: str, value: bytes) -> int:
        clients = list(map(self.get_client, [name for name in clients if name.startswith(prefix)]))
        return len(list(filter(lambda item: item.stdout == value, clients)))

    def setUp(self):
        self.clients = [
            self.__gen_client("limited", value, self.limited_client) for value in range(2)
        ]
        self.clients += [
            self.__gen_client("different", value, self.different_client) for value in range(2)
        ]
        super().setUp()

    def test_ja5_hash_difference(self):
        self.start_all_services(client=False)

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
        self.update_config_with_ja5_hash_limit(
            ja5t_hash=self.just_valid_ja5t_hash_string,
            ja5h_hash=self.just_valid_ja5h_hash_string,
            reload=False,
        )
        super().setUp()

    def test_default_values(self):
        """
        Verify the default ja5 filters
        does not affect the application
        """
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
            "name": "Ja5tInvalidValue",
            "ja5t_block": "ja5t {hash invalid_hash 5 5;}",
        },
        {
            "name": "Ja5tInvalidTableSize",
            "ja5t_block": "ja5t storage_size=500 {hash a7007c90000 5 5;}",
        },
        {
            "name": "Ja5hInvalidValue",
            "ja5t_block": "ja5h {hash invalid_hash 5 5;}",
        },
        {
            "name": "Ja5hInvalidTableSize",
            "ja5t_block": "ja5h storage_size=500 {hash 55cbf8cce0170011 5 5;}",
        },
        {
            "name": "Ja5hDuplicatedDirective",
            "ja5t_block": "ja5h {hash 55cbf8cce0170011 5 5;} ja5h {}",
        },
        {
            "name": "Ja5hDuplicatedDirectiveContent",
            "ja5t_block": "ja5h {hash 55cbf8cce0170011 5 5;} ja5h {hash 55cbf8cce0170011 5 5;}",
        },
    ]
)
class TestConfig(BaseJa5TestSuite):
    ja5t_block: str = ""

    def setUp(self):
        self.write_ja5_config(self.ja5t_block)
        super().setUp()

    def test_config(self):
        self.oops_ignore = ["ERROR"]
        self.assertRaises(ProcessBadExitStatusException, self.start_tempesta)


@marks.parameterize_class(
    [
        {
            "name": "Ja5t",
            "hash_type": "ja5t",
        },
        {
            "name": "Ja5h",
            "hash_type": "ja5h",
        },
    ]
)
class TestRestartAppWithUpdatedHash(BaseJa5TestSuite):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_ja5t_cmd(),
        },
    ]

    def setUp(self):
        self.update_config_with_ja5_hash_limit(
            ja5t_hash=self.just_valid_ja5t_hash_string,
            ja5h_hash=self.just_valid_ja5h_hash_string,
            reload=False,
        )
        super().setUp()

    def test_restart_ok(self):
        """
        Verify successful application restart with
        ja5 configuration
        """
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().restart()

    def test_reload_ok(self):
        """
        Verify successful application reload with
        ja5 configuration
        """
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().reload()


@marks.parameterize_class(
    [
        {
            "name": "Ja5t",
            "hash_type": "ja5t",
        },
        {
            "name": "Ja5h",
            "hash_type": "ja5h",
        },
    ]
)
class TestClearHashes(BaseJa5TestSuite):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_ja5t_cmd(),
        },
    ]

    def setUp(self):
        self.update_config_with_ja5_hash_limit(
            ja5t_hash=self.just_valid_ja5t_hash_string,
            ja5h_hash=self.just_valid_ja5h_hash_string,
            reload=False,
        )
        super().setUp()

    def test_clear_traffic_block(self):
        self.start_all_services(client=False)

        client = self.get_client("curl")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.stdout, self.response_ok)

        fingerprint = self.get_client_fingerprint("curl")

        self.set_config_ja5_hash(self.get_hash(fingerprint))
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.stdout, self.response_fail)

        self.update_config_with_ja5_hash_limit()
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.stdout, self.response_ok)
