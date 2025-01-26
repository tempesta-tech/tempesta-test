"""Functional tests of ja5 filtration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from helpers import dmesg, tf_cfg
from helpers.control import Tempesta
from test_suite import marks, tester

DEPROXY_CLIENT_SSL = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 13\r\nContent-Type: text/html\r\n\r\n<html></html>",
}

TEMPESTA_CONFIG = """
listen 443 proto=h2,https;

server ${server_ip}:8000;

frang_limits {
    http_strict_host_checking false;
}

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
"""

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))
# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT_SSL]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestJa5t(tester.TempestaTest):
    """This class contains checks for tempesta ja5 filtration."""

    tempesta = {"config": TEMPESTA_CONFIG}

    backends = [DEPROXY_SERVER]

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_hash", tempesta_ja5_config="", expected_block=False),
            marks.Param(
                name="hash_not_for_client",
                tempesta_ja5_config="""
					ja5t {
						hash deadbeef 10 1000;
					}
				""",
                expected_block=False,
            ),
            marks.Param(
                name="hash_for_client_not_block",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 1 100;
					}
				""",
                expected_block=False,
            ),
            marks.Param(
                name="hash_for_client_block_by_conn",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 0 10;
						hash 66cb8f00d4250002 0 10;
					}
				""",
                expected_block=True,
            ),
            marks.Param(
                name="hash_for_client_block_by_rate",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 1 0;
						hash 66cb8f00d4250002 1 0;
					}
				""",
                expected_block=True,
            ),
        ]
    )
    def test(self, name, tempesta_ja5_config: str, expected_block: bool):
        """Update tempesta config. Send many identical requests and checks cache operation."""
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_ja5_config

        self.start_all_services()
        client = self.get_client("deproxy")
        request = client.create_request(method="GET", uri="/", headers=[])

        client.make_request(request)
        if expected_block:
            self.assertTrue(client.wait_for_connection_close())
        else:
            self.assertTrue(client.wait_for_response())
            self.assertTrue(client.last_response.status, "200")


class TestJa5tStress(tester.TempestaTest):
    """This class contains checks for tempesta ja5 filtration."""

    tempesta = {"config": TEMPESTA_CONFIG}

    backends = [DEPROXY_SERVER]

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --connections {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --duration {DURATION}"
            ),
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]
    tempesta_ja5_config_1 = """
        ja5t {
            hash deadbeef 10 1000;
            hash 1f5a9a29ef170000 1 10;
            hash 66cbda9cafc40009 0 0;
            hash 1f5a9a29ef170020 3 20;
        }
    """
    tempesta_ja5_config_2 = """
        ja5t {
            hash deadbeef 10 1000;
            hash 1f5a9a29ef170000 1 100;
        }
    """
    tempesta_ja5_config_empty = ""

    def change_cfg(self):
        tempesta: Tempesta = self.get_tempesta()
        config = tempesta.config.defconfig
        ja5_configs = [
            self.tempesta_ja5_config_empty,
            self.tempesta_ja5_config_1,
            self.tempesta_ja5_config_2,
        ] * 4

        for ja5_config in ja5_configs:
            tempesta.config.defconfig = config + ja5_config
            self.get_tempesta().reload()

            # sleep sometime to receive 200 responses
            time.sleep(0.5)

    @marks.Parameterize.expand(
        [
            marks.Param(name="Http", client_id="wrk"),
            marks.Param(name="H2", client_id="h2load"),
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test(self, name, client_id: str):
        self.start_all_services()
        client = self.get_client(client_id)
        client.start()
        self.change_cfg()
        self.wait_while_busy(client)
        client.stop()

        if client_id == "wrk":
            self.assertGreater(client.statuses[200], 0)
        else:
            self.assertNotIn(" 0 2xx, ", client.response_msg)

        # TODO: Check client status codes.
