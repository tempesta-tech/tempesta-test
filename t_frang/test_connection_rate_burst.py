"""
Tests for Frang directive `*_connection_rate` and '*_connection_burst'.

From wiki, read it to understand burst tests (why number of warnings
are ranged):
"Minor bursts also can actually exceed the specified limit,
but not more than 2 times."
"""

import time

from helpers import util
from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR = "Warning: frang: new connections {0} exceeded for"
ERROR_TLS = "Warning: frang: new TLS connections {0} exceeded for"


class FrangTls(FrangTestCase):
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

    tempesta = {
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

        # we need to set 11=10+1 to guarantee burst 5
        warns_expected = range(max(connections - 10, 0), max(connections - 5, 0))

        self.check_connections([curl], self.burst_warning, warns_expected)
        self.assertFrangWarning(self.rate_warning, expected=0)

    def _base_rate_scenario(self, connections: int, disable_hshc: bool = False):
        """
        Create several client connections and send request.
        If number of connections is more than 3m they will be blocked.
        """
        curl = self.get_client("curl-1")
        self.set_frang_config(
            "\n".join(
                [self.rate_config] + (["http_strict_host_checking false;"] if disable_hshc else [])
            )
        )

        # TODO #480: doesn't work properly,
        # very slow execution to fit in a second
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
            self.check_connections([curl], self.rate_warning, resets_expected=connections - 4)

        self.assertFrangWarning(self.burst_warning, expected=0)

    def test_connection_burst(self):
        self._base_burst_scenario(connections=11)

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


class FrangTcp(FrangTls):
    """Tests for 'tcp_connection_burst' and 'tcp_connection_rate'."""

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

    tempesta = {
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
    burst_config = "tcp_connection_burst 5;\n\ttcp_connection_rate 20;"
    rate_config = "tcp_connection_burst 2;\n\ttcp_connection_rate 4;"


class FrangTlsVsBoth(FrangTestCase):
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

    tempesta = {
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
    opt_client_id = "curl-http"
    burst_warning = ERROR_TLS.format("burst")
    rate_warning = ERROR_TLS.format("rate")
    burst_config = "tls_connection_burst 3;"
    rate_config = "tls_connection_rate 3;"
    no_shc_config = "http_strict_host_checking false;"

    def _arrange_clients(self, conns_n):
        base_client = self.get_client(self.base_client_id)
        opt_client = self.get_client(self.opt_client_id)

        base_client.uri += f"[1-{conns_n}]"
        opt_client.uri += f"[1-{conns_n}]"
        base_client.parallel = conns_n
        opt_client.parallel = conns_n

        return base_client, opt_client

    def _act(self, base_client, opt_client):
        base_client.start()
        opt_client.start()
        self.wait_while_busy(base_client, opt_client)
        self.wait_while_busy(opt_client)
        base_client.stop()
        opt_client.stop()

    def test_burst(self):
        """
        Set `tls_connection_burst 3` and create 7 tls and 7 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.burst_config)
        # we need to set 7=6+1 to guarantee burst 3
        conns_n = 7
        base_client, opt_client = self._arrange_clients(conns_n)

        self._act(base_client, opt_client)

        resets_expected = range(conns_n - 3 * 2, conns_n - 3)
        self.check_connections([base_client], self.burst_warning, resets_expected)
        self.assertEqual(
            opt_client.statuses_from_stats(), {200: conns_n}, "Client has been unexpectely reset"
        )

    def test_rate(self):
        """
        Set `tls_connection_rate 3` and create 4 tls and 4 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.rate_config + self.no_shc_config)
        # limit rate 3
        conns_n = 4
        base_client, opt_client = self._arrange_clients(conns_n)

        self._act(base_client, opt_client)

        self.check_connections([base_client], self.rate_warning, resets_expected=conns_n - 3)
        self.assertEqual(
            opt_client.statuses_from_stats(), {200: conns_n}, "Client has been unexpectely reset"
        )


class FrangTcpVsBoth(FrangTlsVsBoth):
    """Tests for tls and non-tls connections 'tcp_connection_burst' and 'tcp_connection_rate'"""

    tempesta = {
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
    opt_client_id = "curl-https"
    burst_warning = ERROR.format("burst")
    rate_warning = ERROR.format("rate")
    burst_config = "tcp_connection_burst 3;"
    rate_config = "tcp_connection_rate 3;"

    def test_burst(self):
        """
        Set `tcp_connection_burst 3` and create 4 tls and 4 non-tls connections.
        Connections of both types will be blocked (4+4 > 3*2).
        """
        self.set_frang_config(frang_config=self.burst_config)
        conn_n = 4
        base_client, opt_client = self._arrange_clients(conn_n)

        self._act(base_client, opt_client)

        resets_expected = range(conn_n * 2 - 3 * 2, conn_n * 2 - 3)
        self.check_connections([base_client, opt_client], self.burst_warning, resets_expected)

    def test_rate(self):
        """
        Set tcp_connection_rate 3` and create 2 tls and 2 non-tls connections.
        Connections of both types will be blocked (2+2 > 3).
        """
        self.set_frang_config(frang_config=self.rate_config + self.no_shc_config)
        conns_n = 2
        base_client, opt_client = self._arrange_clients(conns_n)

        self._act(base_client, opt_client)

        self.check_connections(
            [base_client, opt_client], self.rate_warning, resets_expected=conns_n * 2 - 3
        )
