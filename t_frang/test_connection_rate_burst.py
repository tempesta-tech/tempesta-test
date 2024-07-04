"""
Tests for Frang directive `*_connection_rate` and '*_connection_burst'.

From wiki, read it to understand burst tests (why number of warnings
are ranged):
"Minor bursts also can actually exceed the specified limit,
but not more than 2 times."
"""

import re

from framework.parameterize import param, parameterize, parameterize_class
from helpers import tf_cfg
from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR = "Warning: frang: new connections {0} exceeded for"
ERROR_TLS = "Warning: frang: new TLS connections {0} exceeded for"


def parse_out(client):
    rx = re.compile(r"Errors: ([0-9]+)")
    reset_conn_n = int(rx.findall(client.stdout.decode())[0])
    rx = re.compile(r"Finished: ([0-9]+)")
    total_conn_n = int(rx.findall(client.stdout.decode())[0])

    return reset_conn_n, total_conn_n


@parameterize_class(
    [
        {
            "name": "TLS",
            "tls_connection": True,
            "burst_warning": ERROR_TLS.format("burst"),
            "rate_warning": ERROR_TLS.format("rate"),
            "burst_config": "tls_connection_burst 5;\n\ttls_connection_rate 20;",
            "rate_config": "tls_connection_burst 20;\n\ttls_connection_rate 5;",
        },
        {
            "name": "TCP",
            "tls_connection": False,
            "burst_warning": ERROR.format("burst"),
            "rate_warning": ERROR.format("rate"),
            "burst_config": "tcp_connection_burst 5;\n\ttcp_connection_rate 20;",
            "rate_config": "tcp_connection_burst 20;\n\ttcp_connection_rate 5;",
        },
    ]
)
class TestFrang(FrangTestCase):
    """Tests for 'tls_connection_burst' and 'tls_connection_rate'."""

    tempesta = {
        "config": """
            frang_limits {
                %(frang_config)s
            }
            
            listen 80;
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

    tls_connection: bool
    burst_warning: str
    rate_warning: str
    burst_config: str
    rate_config: str
    calculate_reset_function: callable

    @parameterize.expand(
        [
            param(name="burst", conn_n=20, warns_expected=range(1, 15)),
            param(name="burst_without_reaching_the_limit", conn_n=2, warns_expected=0),
            param(name="burst_on_the_limit", conn_n=5, warns_expected=0),
        ]
    )
    def test_connection(self, name, conn_n: int, warns_expected):
        """
        Create several client connections, if number of
        connections is more than 5 some of them will be
        blocked. We don't know real count of blocked
        connections because connnection is blocked only if
        connection count per 0.125 sec is greater then 5.
        """
        self.set_frang_config(self.burst_config)

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, self.tls_connection)

        reset_conn_n, total_conn_n = parse_out(client)
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
        self.assertEqual(total_conn_n, conn_n)
        self.assertEqual(reset_conn_n, warns_occured)
        self.assertFrangWarning(self.rate_warning, expected=0)

    @parameterize.expand(
        [
            param(name="rate", conn_n=20, warns_expected=range(1, 15)),
            param(name="rate_without_reaching_the_limit", conn_n=2, warns_expected=0),
            param(name="rate_on_the_limit", conn_n=5, warns_expected=0),
        ]
    )
    def test_connection(self, name, conn_n: int, warns_expected):
        """
        Create several client connections, if number of
        connections is more than 5 some of them will be
        blocked. We don't know real count of blocked
        connections because connnection is blocked only if
        connection count per 1 sec is greater then 5.
        """
        self.set_frang_config(self.rate_config)

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, self.tls_connection)

        reset_conn_n, total_conn_n = parse_out(client)

        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
        self.assertEqual(total_conn_n, conn_n)
        self.assertEqual(reset_conn_n, warns_occured)
        self.assertFrangWarning(self.burst_warning, expected=0)


class FrangTlsVsBoth(FrangTestCase):
    """Tests for tls and non-tls connections 'tls_connection_burst' and 'tls_connection_rate'"""

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

    burst_warning = ERROR_TLS.format("burst")
    rate_warning = ERROR_TLS.format("rate")
    burst_config = "tls_connection_burst 3;"
    rate_config = "tls_connection_rate 3;"

    def test_burst(self):
        """
        Set `tls_connection_burst 3` and create 7 tls and 7 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.burst_config)
        conn_n = 7

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, True)
        tls_reset_conn_n, tls_total_conn_n = parse_out(client)

        self.run_rate_check(client, conn_n, False)
        tcp_reset_conn_n, tcp_total_conn_n = parse_out(client)

        warns_expected = range(1, conn_n - 3)
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
        self.assertEqual(tls_total_conn_n, conn_n)
        self.assertEqual(tcp_total_conn_n, conn_n)
        self.assertEqual(tls_reset_conn_n, warns_occured)
        self.assertEqual(tcp_reset_conn_n, 0)
        self.assertFrangWarning(self.rate_warning, expected=0)

    def test_rate(self):
        """
        Set `tls_connection_rate 3` and create 7 tls and 7 non-tls connections.
        Only tls connections will be blocked.
        """
        self.set_frang_config(frang_config=self.rate_config)
        conn_n = 7

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, True)
        tls_reset_conn_n, tls_total_conn_n = parse_out(client)

        self.run_rate_check(client, conn_n, False)
        tcp_reset_conn_n, tcp_total_conn_n = parse_out(client)

        warns_expected = range(1, conn_n - 3)
        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
        self.assertEqual(tls_total_conn_n, conn_n)
        self.assertEqual(tcp_total_conn_n, conn_n)
        self.assertEqual(tls_reset_conn_n, warns_occured)
        self.assertEqual(tcp_reset_conn_n, 0)
        self.assertFrangWarning(self.burst_warning, expected=0)


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

    burst_warning = ERROR.format("burst")
    rate_warning = ERROR.format("rate")
    burst_config = "tcp_connection_burst 3;"
    rate_config = "tcp_connection_rate 3;"

    def test_burst(self):
        """
        Set `tcp_connection_burst 3` and create 7 tls and 7 non-tls connections.
        Connections of both types will be blocked.
        """
        self.set_frang_config(frang_config=self.burst_config)
        conn_n = 7

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, True)
        tls_reset_conn_n, tls_total_conn_n = parse_out(client)

        self.run_rate_check(client, conn_n, False)
        tcp_reset_conn_n, tcp_total_conn_n = parse_out(client)

        warns_expected = range(1, 2 * conn_n - 3)
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
        self.assertEqual(tls_total_conn_n, conn_n)
        self.assertEqual(tcp_total_conn_n, conn_n)
        self.assertEqual(tls_reset_conn_n + tcp_reset_conn_n, warns_occured)
        self.assertFrangWarning(self.rate_warning, expected=0)

    def test_rate(self):
        """
        Set tcp_connection_rate 3` and create 7 tls and 7 non-tls connections.
        Connections of both types will be blocked.
        """
        self.set_frang_config(frang_config=self.rate_config)
        conn_n = 7

        client = self.get_client("ratechecker")
        self.run_rate_check(client, conn_n, True)
        tls_reset_conn_n, tls_total_conn_n = parse_out(client)

        self.run_rate_check(client, conn_n, False)
        tcp_reset_conn_n, tcp_total_conn_n = parse_out(client)

        warns_expected = range(1, 2 * conn_n - 3)
        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
        self.assertEqual(tls_total_conn_n, conn_n)
        self.assertEqual(tcp_total_conn_n, conn_n)
        self.assertEqual(tls_reset_conn_n + tcp_reset_conn_n, warns_occured)
        self.assertFrangWarning(self.burst_warning, expected=0)
