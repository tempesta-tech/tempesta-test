"""TestCase for mixed listening sockets."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import socket
import ssl

from framework import tester
from framework.external_client import ExternalTester
from helpers import tf_cfg

STATUS_OK = "200"

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

TEMPESTA_CONFIG = """
listen ${tempesta_ip}:443 proto=h2;
listen ${tempesta_ip}:4433 proto=https;

srv_group default {
    server ${server_ip}:8000;
}

vhost tempesta-cat {
    proxy_pass default;
}

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

cache 0;
block_action attack reply;

http_chain {
    -> tempesta-cat;
}
"""


def establish_client_server_connection(
    port: int,
    protocols: list,
    hostname="localhost",
):
    """
    Establish a client-server connection and check verify protocol compliance.

    Args:
        port (int): server port for connection
        protocols (list): list of strings, ordered by preference
        hostname (str): server hostname

    Raises:
        RuntimeError: wrong protocol has been used
    """
    context = ssl.create_default_context()

    context.set_alpn_protocols(protocols)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port)) as tcp_conn:
        with context.wrap_socket(tcp_conn, server_hostname=hostname) as tls_conn:
            if tls_conn.selected_alpn_protocol() not in protocols:
                raise RuntimeError(f"Wrong protocol has been used for port {port}")


class TestMixedListeners(tester.TempestaTest):
    """This class contains test situations of sending h2 and https requests to mixed listeners."""

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
            "id": "curl-h2-true",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http2 https://${tempesta_ip}:443/",
        },
        {
            "id": "curl-h2-false",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http2 https://${tempesta_ip}:4433/",
        },
        {
            "id": "curl-https-true",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http1.1 https://${tempesta_ip}:4433/",
        },
        {
            "id": "curl-https-false",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http1.1 https://${tempesta_ip}:443/",
        },
    ]

    tempesta = {"config": TEMPESTA_CONFIG}

    def start_all(self):
        """Start server and tempesta."""
        self.start_all_servers()
        self.start_tempesta()

    def make_curl_request(self, curl_client_id: str) -> str:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        Returns:
            str: server response to the request as string
        """
        client: ExternalTester = self.get_client(curl_client_id)
        client.start()
        self.wait_while_busy(client)
        client.stop()
        if client.response_msg:
            tf_cfg.dbg(4, f"\t{client.options[0]} request received response")
        else:
            tf_cfg.dbg(4, f"\t{client.options[0]} request did not receive response")
        client.stop()
        return client.response_msg

    def check_curl_response(self, response: str, fail=False):
        """
        Check response to `curl` request.

        Args:
            response (str): response for checking
            fail (bool): if response must be successful - false
        """
        if fail:
            self.assertNotIn(
                STATUS_OK,
                response,
                "Error for curl",
            )
        else:
            self.assertIn(
                STATUS_OK,
                response,
                "Error for curl",
            )

    def test_mixed_h2_success(self):
        """
        Test h2 success situation.

        One `true` client apply h2 client for h2 socket,
        second `false` client apply h2 client for https socket,
        """
        self.start_all()

        self.check_curl_response(self.make_curl_request("curl-h2-true"), fail=False)
        self.assertRaises(
            ssl.SSLError,
            establish_client_server_connection,
            port=4433,
            protocols=["h2"],
        )

    def test_mixed_https_success(self):
        """
        Test https success situation.

        One `true` client apply https client for https socket,
        second `false` client apply https client for h2 socket,
        """
        self.start_all()

        self.check_curl_response(self.make_curl_request("curl-https-true"), fail=False)
        self.check_curl_response(self.make_curl_request("curl-https-false"), fail=True)
