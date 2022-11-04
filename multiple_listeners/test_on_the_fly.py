"""TestCase for change Tempesta config on the fly."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.external_client import ExternalTester
from framework.wrk_client import Wrk
from helpers.control import Tempesta

WRK_SCRIPT = "conn_close"  # with header 'connection: close'
STATUS_OK = "200"

SOCKET_START = "127.0.0.4:8282"
SOCKET_AFTER_RELOAD = "127.0.1.5:7654"

TEMPESTA_CONFIG = """
listen 127.0.0.4:8282;

srv_group default {
    server ${server_ip}:8000;
}

vhost tempesta-cat {
    proxy_pass default;
}

cache 0;
block_action attack reply;

http_chain {
    -> tempesta-cat;
}
"""

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;
events {
    worker_connections   1024;
    use epoll;
}
http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;
    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    error_log /dev/null emerg;
    access_log off;
    server {
        listen        ${server_ip}:8000;
        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestOnTheFly(tester.TempestaTest):
    """This class tests Tempesta for change config on the fly."""

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    clients = [
        {
            "id": "wrk-127.0.0.4:8282",
            "type": "wrk",
            "addr": "127.0.0.4:8282",
        },
        {
            "id": "curl-127.0.0.4:8282",
            "type": "external",
            "binary": "curl",
            "cmd_args": "-Ikf http://127.0.0.4:8282/",
        },
        {
            "id": "curl-127.0.1.5:7654",
            "type": "external",
            "binary": "curl",
            "cmd_args": "-Ikf http://127.0.1.5:7654/",
        },
    ]

    tempesta = {"config": TEMPESTA_CONFIG}

    def start_all(self):
        """Start server and tempesta."""
        self.start_all_servers()
        self.start_tempesta()

    def check_non_working_socket(self, tempesta: Tempesta, socket: str) -> None:
        """
        Check that socket is not working.

        Args:
            tempesta: object of working Tempesta
            socket: socket for checking
        """
        self.assertRaises(
            Exception,
            self.make_curl_request,
            "curl-{0}".format(socket),
        )
        self.assertNotIn(
            "listen {0};".format(socket),
            tempesta.config.get_config(),
        )

    def test_change_config_on_the_fly(self) -> None:
        """
        Test Tempesta for change config on the fly.

        Start Tempesta with one config - start wrk -
            - reload Tempesta with new config -
            - start new wrk
        """
        self.start_all()
        tempesta: Tempesta = self.get_tempesta()

        self.assertIn(
            "listen {0};".format(SOCKET_START),
            tempesta.config.get_config(),
        )
        self.make_curl_request("curl-{0}".format(SOCKET_START))

        # check reload sockets not in config
        self.check_non_working_socket(tempesta, SOCKET_AFTER_RELOAD)

        wrk: Wrk = self.get_client("wrk-{0}".format(SOCKET_START))
        wrk.set_script(WRK_SCRIPT)
        wrk.start()

        # change config and reload Tempesta
        tempesta.config.defconfig = tempesta.config.defconfig.replace(
            SOCKET_START,
            SOCKET_AFTER_RELOAD,
        )
        tempesta.reload()

        # check old sockets  not in config
        self.check_non_working_socket(tempesta, SOCKET_START)

        self.make_curl_request("curl-{0}".format(SOCKET_AFTER_RELOAD))
        self.assertIn(
            "listen {0};".format(SOCKET_AFTER_RELOAD),
            tempesta.config.get_config(),
        )

        self.wait_while_busy(wrk)
        wrk.stop()

    def make_curl_request(self, curl_client_id: str):
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        """
        curl: ExternalTester = self.get_client(curl_client_id)
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn(
            STATUS_OK,
            curl.response_msg,
        )
