"""Tests for Frang directive `connection_rate` and 'connection_burst'."""
import time

from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR = "Warning: frang: new connections {0} exceeded for"
ERROR_TLS = "Warning: frang: new TLS connections {0} exceeded for"


class FrangTlsRateBurstTestCase(FrangTestCase):
    """Tests for 'tls_connection_burst' and 'tls_connection_rate'."""

    clients = [
        {
            "id": "curl-1",
            "type": "curl",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
            "cmd_args": "-v",
            "headers": {
                "Connection": "close",
                "Host": "localhost",
            },
        },
    ]

    tempesta_template = {
        "config": """
            frang_limits {
                %(frang_config)s
            }

            listen 443 proto=https;

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
            cache_fulfill * *;
            block_action attack reply;

            http_chain {
                -> tempesta-cat;
            }
        """,
    }

    burst_warning = ERROR_TLS.format("burst")
    rate_warning = ERROR_TLS.format("rate")
    burst_config = "tls_connection_burst 5;\n\ttls_connection_rate 20;"
    rate_config = "tls_connection_burst 2;\n\ttls_connection_rate 4;"

    def _base_burst_scenario(self, connections: int):
        """
        Create several client connections and send request.
        If number of connections is more than 3 they will be blocked.
        """
        curl = self.get_client("curl-1")
        curl.uri += f"[1-{connections}]"
        curl.parallel = connections

        self.set_frang_config(self.burst_config)

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        time.sleep(self.timeout)

        warning_count = connections - 5 if connections > 5 else 0  # limit burst 5

        self.assertFrangWarning(warning=self.burst_warning, expected=warning_count)

        if warning_count:
            self.assertIn("Failed sending HTTP request", curl.last_response.stderr)

        self.assertFrangWarning(warning=self.rate_warning, expected=0)

    def _base_rate_scenario(self, connections: int, disable_hshc: bool = False):
        """
        Create several client connections and send request.
        If number of connections is more than 3m they will be blocked.
        """
        curl = self.get_client("curl-1")
        self.set_frang_config(
            "\n".join(
                [self.rate_config]
                + ["http_strict_host_checking false;"] if disable_hshc else []
            )
        )

        for step in range(connections):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

            time.sleep(DELAY)

        time.sleep(self.timeout)

        # until rate limit is reached
        if connections <= 4:  # rate limit 4
            self.assertFrangWarning(warning=self.rate_warning, expected=0)
            self.assertEqual(curl.last_response.status, 200)
        else:
            # rate limit is reached
            self.assertFrangWarning(warning=self.rate_warning, expected=1)
            self.assertIn("Failed sending HTTP request", curl.last_response.stderr)

        self.assertFrangWarning(warning=self.burst_warning, expected=0)

    def test_connection_burst(self):
        self._base_burst_scenario(connections=10)

    def test_connection_burst_without_reaching_the_limit(self):
        self._base_burst_scenario(connections=2)

    def test_connection_burst_on_the_limit(self):
        self._base_burst_scenario(connections=5)

    def test_connection_rate(self):
        self._base_rate_scenario(connections=5)

    def test_connection_rate_without_reaching_the_limit(self):
        self._base_rate_scenario(connections=2, disable_hshc=True)

    def test_connection_rate_on_the_limit(self):
        self._base_rate_scenario(connections=4)


class FrangConnectionRateBurstTestCase(FrangTlsRateBurstTestCase):
    """Tests for 'connection_burst' and 'connection_rate'."""

    clients = [
        {
            "id": "curl-1",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
            "headers": {
                "Connection": "close",
                "Host": "localhost",
            },
        },
    ]

    tempesta_template = {
        "config": """
            frang_limits {
                %(frang_config)s
            }
            
            listen 80;
            
            server ${server_ip}:8000;
            
            cache 0;
            block_action attack reply;
        """,
    }

    burst_warning = ERROR.format("burst")
    rate_warning = ERROR.format("rate")
    burst_config = "connection_burst 5;\n\tconnection_rate 20;"
    rate_config = "connection_burst 2;\n\tconnection_rate 4;"


class FrangConnectionRateDifferentIp(FrangTestCase):
    clients = [
        {
            "id": "curl-1",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
            "uri": "/[1-3]",
            "parallel": 3,
            "headers": {
                "Connection": "close",
                "Host": "debian",
            },
        },
        {
            "id": "deproxy-interface-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
        },
    ]

    tempesta = {
        "config": """
            frang_limits {
                connection_rate 2;
                ip_block on;
            }
            listen 80;
            server ${server_ip}:8000;
            block_action attack reply;
        """,
    }

    request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

    error = ERROR.format("rate")

    def test_two_clients_two_ip(self):
        """
        Create 3 client connections for first ip and 1 for second ip.
        Only first ip will be blocked.
        """
        client_1 = self.get_client("deproxy-interface-1")
        client_2 = self.get_client("curl-1")

        self.start_all_services(client=False)

        client_1.start()
        client_2.start()

        self.wait_while_busy(client_2)
        client_2.stop()

        client_1.send_request(self.request, "200")

        server = self.get_server("deproxy")
        self.assertTrue(4 > len(server.requests))

        time.sleep(self.timeout)

        self.assertFrangWarning(warning=self.error, expected=1)


class FrangConnectionBurstDifferentIp(FrangConnectionRateDifferentIp):
    tempesta = {
        "config": """
            frang_limits {
                connection_burst 2;
                ip_block on;
            }
            listen 80;
            server ${server_ip}:8000;
            block_action attack reply;
        """,
    }

    error = ERROR.format("burst")


class FrangTlsRateDifferentIp(FrangConnectionRateDifferentIp):
    clients = [
        {
            "id": "curl-1",
            "type": "curl",
            "addr": "${tempesta_ip}:443",
            "uri": "/[1-3]",
            "parallel": 3,
            "ssl": True,
            "headers": {
                "Connection": "close",
                "Host": "debian",
            },
        },
        {
            "id": "deproxy-interface-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "interface": True,
        },
    ]

    tempesta = {
        "config": """
            frang_limits {
                tls_connection_rate 2;
                ip_block on;
            }

            listen 443 proto=https;

            server ${server_ip}:8000;

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;

    """,
    }

    error = ERROR_TLS.format("rate")


class FrangTlsBurstDifferentIp(FrangTlsRateDifferentIp):
    tempesta = {
        "config": """
            frang_limits {
                tls_connection_burst 2;
                ip_block on;
            }

            listen 443 proto=https;

            server ${server_ip}:8000;

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;

    """,
    }

    error = ERROR_TLS.format("burst")


class FrangTlsAndNonTlsRateBurst(FrangTestCase):
    """Tests for tls and non-tls connections 'tls_connection_burst' and 'tls_connection_rate'"""

    clients = [
        {
            "id": "curl-https",
            "type": "curl",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
            "cmd_args": "-v",
            "headers": {
                "Connection": "close",
                "Host": "localhost",
            },
        },
        {
            "id": "curl-http",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
            "cmd_args": "-v",
            "headers": {
                "Connection": "close",
                "Host": "localhost",
            },
        },
    ]

    tempesta_template = {
        "config": """
            frang_limits {
                %(frang_config)s
            }
            
            listen 80;
            listen 443 proto=https;

            server ${server_ip}:8000;

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;
        """,
    }

    base_client_id = "curl-https"
    optional_client_id = "curl-http"
    burst_warning = ERROR_TLS.format("burst")
    rate_warning = ERROR_TLS.format("rate")
    burst_config = "tls_connection_burst 3;"
    rate_config = "tls_connection_rate 3;"

    def test_burst(self):
        """
        Set `tls_connection_burst 3` and create 4 tls and 4 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.burst_config)

        base_client = self.get_client(self.base_client_id)
        optional_client = self.get_client(self.optional_client_id)

        # burst limit 3
        limit = 4

        base_client.uri += f"[1-{limit}]"
        optional_client.uri += f"[1-{limit}]"
        base_client.parallel = limit
        optional_client.parallel = limit

        base_client.start()
        optional_client.start()
        self.wait_while_busy(base_client, optional_client)
        base_client.stop()
        optional_client.stop()

        self.assertEqual(len(optional_client.stats), limit, "Client has been unexpectedly blocked.")
        for stat in optional_client.stats:
            self.assertEqual(stat["response_code"], 200)
        time.sleep(self.timeout)
        self.assertFrangWarning(warning=self.burst_warning, expected=1)

    def test_rate(self):
        """
        Set `tls_connection_rate 3` and create 4 tls and 4 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.rate_config)

        base_client = self.get_client(self.base_client_id)
        optional_client = self.get_client(self.optional_client_id)

        # limit rate 3
        limit = 4

        base_client.uri += f"[1-{limit}]"
        optional_client.uri += f"[1-{limit}]"
        base_client.parallel = limit
        optional_client.parallel = limit

        base_client.start()
        optional_client.start()
        self.wait_while_busy(base_client, optional_client)
        base_client.stop()
        optional_client.stop()

        self.assertEqual(len(optional_client.stats), limit, "Client has been unexpectedly blocked.")
        for stat in optional_client.stats:
            self.assertEqual(stat["response_code"], 200)
        time.sleep(self.timeout)
        self.assertFrangWarning(warning=self.rate_warning, expected=1)


class FrangConnectionTlsAndNonTlsRateBurst(FrangTlsAndNonTlsRateBurst):
    """Tests for tls and non-tls connections 'connection_burst' and 'connection_rate'"""

    tempesta_template = {
        "config": """
            frang_limits {
                %(frang_config)s
            }

            listen 80;
            listen 443 proto=https;

            server ${server_ip}:8000;


            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;
        """,
    }

    base_client_id = "curl-http"
    optional_client_id = "curl-https"
    burst_warning = ERROR.format("burst")
    rate_warning = ERROR.format("rate")
    burst_config = "connection_burst 3;"
    rate_config = "connection_rate 3;"
