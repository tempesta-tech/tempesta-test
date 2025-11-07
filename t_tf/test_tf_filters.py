"""
Tests for TF Hash Filtering and Configuration Parsing
"""
import typing

from helpers import remote, tf_cfg
from helpers.access_log import AccessLogLine
from helpers.error import ProcessBadExitStatusException
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def gen_curl_tft_cmd(
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


def gen_curl_tfh_cmd(
    http_version: typing.Literal["http2", "http1.1"] = "http1.1",
    method: str = "GET",
    headers: list[str] = (),
):
    headers = " ".join([f'-H "{header}"' for header in headers])
    return f"-k --{http_version} -X{method} {headers} --connect-to tempesta-tech.com:443:${{tempesta_ip}}:443 https://tempesta-tech.com/"


class BaseTFTestSuite(tester.TempestaTest):
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
    additional_conf_dir = tf_cfg.cfg.get("Tempesta", "workdir") + "/tempesta-filters/"
    additional_conf_file = additional_conf_dir + "tf_filters.conf"
    tempesta = {
        "type": "tempesta",
        "config": """
        listen 443 proto=https,h2;

        access_log dmesg;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        !include ${tempesta_workdir}/tempesta-filters/
        
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
    }

    limited_client: str = ""
    different_client: str = ""

    response_ok: bytes = b"0123456789"
    response_fail: bytes = b""

    just_valid_tft_hash_string: str = "b7007c90000"
    just_valid_tfh_hash_string: str = "55cbf8cce0170011"

    hash_type: typing.Literal["tft", "tfh"] = None

    def clean_up(self):
        remote.tempesta.remove_file(self.additional_conf_file)

    def setUp(self):
        super().setUp()
        self.addCleanup(self.clean_up)

    def get_hash(self, fingerprint: AccessLogLine) -> str:
        return getattr(fingerprint, self.hash_type)

    def get_fingerprints(self) -> list[str or None]:
        return self.loggers.dmesg.log_findall('.*"tft=(\w+)" "tfh=(\w+)"')

    def get_client_fingerprint(self, name: str) -> AccessLogLine:
        client = self.get_client(name)
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.stdout, self.response_ok)

        self.loggers.dmesg.update()
        fingerprints = AccessLogLine.parse_all(self.loggers.dmesg.log.decode())

        if not fingerprints:
            raise ValueError("Can not receive client tf fingerprint")

        return fingerprints[0]

    def write_tf_config(self, text: str):
        remote.tempesta.copy_file(self.additional_conf_file, text)

    def update_config_with_tf_hash_limit(
        self, tft_hash: str = None, tfh_hash: str = None, reload: bool = True
    ):
        line = "tft {{ {} }}\ntfh {{ {} }}\n".format(
            f"hash {tft_hash} 1 1;" if tft_hash else "",
            f"hash {tfh_hash} 1 1;" if tfh_hash else "",
        )
        self.write_tf_config(line)

        if not reload:
            return

        tempesta = self.get_tempesta()
        tempesta.reload()

    def set_config_tf_hash(self, hash_value: str):
        key = f"{self.hash_type}_hash"
        kwargs = {key: hash_value}
        self.update_config_with_tf_hash_limit(**kwargs)


@marks.parameterize_class(
    [
        {
            "name": "Tls",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(tls="tlsv1.2", ciphers="DHE-RSA-AES128-GCM-SHA256"),
            "different_client": gen_curl_tft_cmd(tls="tlsv1.3", ciphers="TLS_AES_128_GCM_SHA256"),
        },
        {
            "name": "Curves",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(curves="prime256v1"),
            "different_client": gen_curl_tft_cmd(curves="x25519"),
        },
        {
            "name": "Ciphers",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(ciphers="ECDHE-ECDSA-AES128-GCM-SHA256"),
            "different_client": gen_curl_tft_cmd(ciphers="ECDHE-ECDSA-AES256-GCM-SHA384"),
        },
        {
            "name": "Vhost",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(
                connect_to="tempesta-tech.com:443:${tempesta_ip}:443",
                url="https://tempesta-tech.com/",
            ),
            "different_client": gen_curl_tft_cmd(
                connect_to="tempesta-tech-2.com:443:${tempesta_ip}:443",
                url="https://tempesta-tech-2.com/",
            ),
        },
        {
            "name": "Alpn",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(alpn="http1.1"),
            "different_client": gen_curl_tft_cmd(alpn="http2"),
        },
        {
            "name": "NoAlpn",
            "hash_type": "tft",
            "limited_client": gen_curl_tft_cmd(alpn="http1.1"),
            "different_client": gen_curl_tft_cmd(alpn=None),
        },
        {
            "name": "Http",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(http_version="http1.1"),
            "different_client": gen_curl_tfh_cmd(http_version="http2"),
        },
        {
            "name": "Method",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(method="GET"),
            "different_client": gen_curl_tfh_cmd(method="POST"),
        },
        {
            "name": "Headers",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(headers=["Authorization: Bearer HELLO"]),
            "different_client": gen_curl_tfh_cmd(
                headers=[
                    "Authorization: Bearer HELLO",
                    "X-APP-ID: application-dev-1",
                ]
            ),
        },
        {
            "name": "Referer",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(headers=["Referer: tempesta-tech.com"]),
            "different_client": gen_curl_tfh_cmd(),
        },
        {
            "name": "Cookies",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(headers=["Cookie: session=testing"]),
            "different_client": gen_curl_tfh_cmd(
                headers=[
                    "Cookie: session=testing; session2=testing2",
                ]
            ),
        },
        {
            "name": "Cookies-2",
            "hash_type": "tfh",
            "limited_client": gen_curl_tfh_cmd(headers=["Cookie: aaa=b; cccc=d; qq=dd"]),
            "different_client": gen_curl_tfh_cmd(
                headers=[
                    "Cookie: aaa=b; cccc=d; qq=dd; ww=1",
                ]
            ),
        },
    ]
)
class TestTFFiltersTestSuite(BaseTFTestSuite):
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

    def test_tf_hash_difference(self):
        self.start_all_services(client=False)

        client_names = list(map(lambda __client: __client["id"], self.clients))
        clients = list(map(self.get_client, client_names))
        fingerprints = list(map(self.get_client_fingerprint, client_names))

        self.assertEqual(self.get_hash(fingerprints[0]), self.get_hash(fingerprints[1]))
        self.assertEqual(self.get_hash(fingerprints[-1]), self.get_hash(fingerprints[-2]))
        self.assertNotEqual(self.get_hash(fingerprints[0]), self.get_hash(fingerprints[-1]))

        self.set_config_tf_hash(self.get_hash(fingerprints[0]))

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


class TestTFHashDoesNotMatchedWithFiltered(BaseTFTestSuite):
    clients = [
        {
            "id": "limited-1",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_tft_cmd(),
        },
        {
            "id": "limited-2",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_tft_cmd(),
        },
    ]

    def setUp(self):
        self.update_config_with_tf_hash_limit(
            tft_hash=self.just_valid_tft_hash_string,
            tfh_hash=self.just_valid_tfh_hash_string,
            reload=False,
        )
        super().setUp()

    def test_default_values(self):
        """
        Verify the default tf filters
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
            "name": "TFtInvalidValue",
            "tft_block": "tft {hash invalid_hash 5 5;}",
        },
        {
            "name": "TFtInvalidTableSize",
            "tft_block": "tft storage_size=500 {hash a7007c90000 5 5;}",
        },
        {
            "name": "TFhInvalidValue",
            "tft_block": "tfh {hash invalid_hash 5 5;}",
        },
        {
            "name": "TFhInvalidTableSize",
            "tft_block": "tfh storage_size=500 {hash 55cbf8cce0170011 5 5;}",
        },
        {
            "name": "TFhDuplicatedDirective",
            "tft_block": "tfh {hash 55cbf8cce0170011 5 5;} tfh {}",
        },
        {
            "name": "TFhDuplicatedDirectiveContent",
            "tft_block": "tfh {hash 55cbf8cce0170011 5 5;} tfh {hash 55cbf8cce0170011 5 5;}",
        },
    ]
)
class TestConfig(BaseTFTestSuite):
    tft_block: str = ""

    def setUp(self):
        self.write_tf_config(self.tft_block)
        super().setUp()

    def test_config(self):
        self.oops_ignore = ["ERROR"]
        self.assertRaises(ProcessBadExitStatusException, self.start_tempesta)


@marks.parameterize_class(
    [
        {
            "name": "TFt",
            "hash_type": "tft",
        },
        {
            "name": "TFh",
            "hash_type": "tfh",
        },
    ]
)
class TestRestartAppWithUpdatedHash(BaseTFTestSuite):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_tft_cmd(),
        },
    ]

    def setUp(self):
        self.update_config_with_tf_hash_limit(
            tft_hash=self.just_valid_tft_hash_string,
            tfh_hash=self.just_valid_tfh_hash_string,
            reload=False,
        )
        super().setUp()

    def test_restart_ok(self):
        """
        Verify successful application restart with
        tf configuration
        """
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().restart()

    def test_reload_ok(self):
        """
        Verify successful application reload with
        tf configuration
        """
        self.start_all_servers()
        self.start_tempesta()
        self.get_tempesta().reload()


@marks.parameterize_class(
    [
        {
            "name": "TFt",
            "hash_type": "tft",
        },
        {
            "name": "TFh",
            "hash_type": "tfh",
        },
    ]
)
class TestClearHashes(BaseTFTestSuite):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_tft_cmd(),
        },
        {
            "id": "blocked",
            "type": "external",
            "binary": "curl",
            "cmd_args": gen_curl_tft_cmd(url="https://tempesta-tech.com/[1-2]"),
        },
    ]

    def setUp(self):
        self.update_config_with_tf_hash_limit(
            tft_hash=self.just_valid_tft_hash_string,
            tfh_hash=self.just_valid_tfh_hash_string,
            reload=False,
        )
        super().setUp()

    def test_clear_traffic_block(self):
        self.start_all_services(client=False)

        fingerprint = self.get_client_fingerprint("curl")

        self.set_config_tf_hash(self.get_hash(fingerprint))

        blocked_client = self.get_client("blocked")
        blocked_client.start()
        self.wait_while_busy(blocked_client)
        blocked_client.stop()
        self.assertIn(
            "Connection reset by peer",
            blocked_client.stderr.decode(),
            f"Tempesta FW must block the client with {self.hash_type}={fingerprint}."
        )

        self.update_config_with_tf_hash_limit()
        client = self.get_client("curl")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(
            client.stdout,
            self.response_ok,
            f"Tempesta FW must not block the client with {self.hash_type}={fingerprint} "
            f"and empty hash config for Tempesta FW."
        )
