"""
Tests for Frang directive `*_connection_rate` and '*_connection_burst'.

From wiki, read it to understand burst tests (why number of warnings
are ranged):
"Minor bursts also can actually exceed the specified limit,
but not more than 2 times."
"""

import socket
import ssl
import threading
import time

from helpers import tf_cfg, util
from t_frang.frang_test_case import DELAY, FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR = "Warning: frang: new connections {0} exceeded for"
ERROR_TLS = "Warning: frang: new TLS connections {0} exceeded for"


def is_socket_closed(sock: socket.socket) -> bool:
    try:
        # this will try to read bytes without blocking and
        # also without removing them from buffer (peek only)
        data = sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
        if len(data) == 0:
            return True
    except BlockingIOError:
        # socket is open and reading from it would block
        return False
    except ConnectionResetError:
        # socket was closed for some other reason
        return True
    else:
        return False


def is_tls_socket_closed(sock: socket.socket) -> bool:
    sock.settimeout(0)
    try:
        # this will try to read bytes without blocking and
        # also without removing them from buffer (peek only)
        data = sock.recv(16)
        if len(data) == 0:
            return True
    except ssl.SSLWantReadError:
        return False
    except:
        return True
    else:
        return False


class Connection:
    def __init__(self, port, protocols=None):
        self.port = port
        self.protocols = protocols
        self.tcp_conn = None
        self.tls_conn = None

    def __del__(self):
        if self.tls_conn:
            self.tls_conn.close()
        elif self.tcp_conn:
            self.tcp_conn.close()

    def __tls_wrap_client_server_connection(self, protocols: list):
        context = ssl.create_default_context()

        context.set_alpn_protocols(protocols)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            self.tls_conn = context.wrap_socket(
                self.tcp_conn, server_hostname=tf_cfg.cfg.get("Client", "hostname")
            )
        except:
            self.tls_conn = None

    def establish_client_server_connection(self):
        try:
            self.tcp_conn = socket.create_connection((tf_cfg.cfg.get("Tempesta", "ip"), self.port))
        except:
            self.tcp_conn = None

    def establish_client_server_tls_connection(self):
        self.establish_client_server_connection()
        if self.tcp_conn and not is_socket_closed(self.tcp_conn):
            self.__tls_wrap_client_server_connection(self.protocols)

    def establish_client_server_connection_in_thead(self):
        thread = threading.Thread(target=self.establish_client_server_connection)
        return thread

    def establish_client_server_tls_connection_in_thead(self):
        thread = threading.Thread(target=self.establish_client_server_tls_connection)
        return thread


def calculate_tls_reset_conn_n(conns):
    reset_conn_n = 0
    for conn in conns:
        if not conn.tls_conn or is_tls_socket_closed(conn.tls_conn):
            reset_conn_n += 1
    return reset_conn_n


def calculate_tcp_reset_conn_n(conns):
    reset_conn_n = 0
    for conn in conns:
        if not conn.tcp_conn or is_socket_closed(conn.tcp_conn):
            reset_conn_n += 1
    return reset_conn_n


def start_and_wait_threads(threads):
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()


def create_connections(count, tls_enabled, sleep_time=None):
    connections = []
    port = 443 if tls_enabled else 80

    for _ in range(count):
        conn = Connection(port, ["http/1.1"])
        connections.append(conn)
        if tls_enabled:
            conn.establish_client_server_tls_connection()
        else:
            conn.establish_client_server_connection()
        if sleep_time:
            time.sleep(sleep_time)

    return connections


def create_connections_and_threads(count, tls_enabled):
    connections = []
    threads = []
    port = 443 if tls_enabled else 80

    for _ in range(count):
        conn = Connection(port, ["http/1.1"])
        connections.append(conn)
        if tls_enabled:
            threads.append(conn.establish_client_server_tls_connection_in_thead())
        else:
            threads.append(conn.establish_client_server_connection_in_thead())

    return connections, threads


class FrangTls(FrangTestCase):
    tls_connection = True

    """Tests for 'tls_connection_burst' and 'tls_connection_rate'."""

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
    rate_config = "tls_connection_burst 20;\n\ttls_connection_rate 5;"

    def _base_burst_scenario(self, conn_n: int):
        """
        Create several client connections, if number of
        connections is more than 5 some of them will be
        blocked. We don't know real count of blocked
        connections because connnection is blocked only if
        connection count per 0.125 sec is greater then 5.
        """
        self.set_frang_config(self.burst_config)

        connections, threads = create_connections_and_threads(conn_n, self.tls_connection)
        start_and_wait_threads(threads)
        reset_conn_n = (
            calculate_tls_reset_conn_n(connections)
            if self.tls_connection
            else calculate_tcp_reset_conn_n(connections)
        )

        warns_expected = range(1, conn_n - 5) if conn_n - 5 > 0 else 0
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
        self.assertEqual(reset_conn_n, warns_occured)
        self.assertFrangWarning(self.rate_warning, expected=0)

    def _base_rate_scenario(self, conn_n: int):
        """
        Create several client connections, if number of
        connections is more than 5 some of them will be
        blocked. We don't know real count of blocked
        connections because connnection is blocked only if
        connection count per 1 sec is greater then 5.
        """
        self.set_frang_config(self.rate_config)
        connections = create_connections(conn_n, self.tls_connection, 0.01)
        reset_conn_n = (
            calculate_tls_reset_conn_n(connections)
            if self.tls_connection
            else calculate_tcp_reset_conn_n(connections)
        )

        warns_expected = range(1, conn_n - 5) if conn_n - 5 > 0 else 0
        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
        self.assertFrangWarning(self.burst_warning, expected=0)

    def test_connection_burst(self):
        self._base_burst_scenario(conn_n=20)

    def test_connection_burst_without_reaching_the_limit(self):
        self._base_burst_scenario(conn_n=2)

    def test_connection_burst_on_the_limit(self):
        self._base_burst_scenario(conn_n=5)

    def test_connection_rate(self):
        self._base_rate_scenario(conn_n=20)

    def test_connection_rate_without_reaching_the_limit(self):
        self._base_rate_scenario(conn_n=2)

    def test_connection_rate_on_the_limit(self):
        self._base_rate_scenario(conn_n=5)


class FrangTcp(FrangTls):
    tls_connection = False

    """Tests for 'tcp_connection_burst' and 'tcp_connection_rate'."""

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
    rate_config = "tcp_connection_burst 20;\n\ttcp_connection_rate 5;"


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

        tls_connections, tls_threads = create_connections_and_threads(conn_n, True)
        tcp_connections, tcp_threads = create_connections_and_threads(conn_n, False)
        threads = tls_threads + tcp_threads

        start_and_wait_threads(threads)
        tls_reset_conn_n = calculate_tls_reset_conn_n(tls_connections)
        tcp_reset_conn_n = calculate_tcp_reset_conn_n(tcp_connections)

        warns_expected = range(1, conn_n - 3)
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
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

        tls_connections = create_connections(conn_n, True, 0.01)
        tcp_connections = create_connections(conn_n, False, 0.01)

        tls_reset_conn_n = calculate_tls_reset_conn_n(tls_connections)
        tcp_reset_conn_n = calculate_tcp_reset_conn_n(tcp_connections)

        warns_expected = range(1, conn_n - 3)
        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
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

    base_client_id = "curl-http"
    opt_client_id = "curl-https"
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

        tls_connections, tls_threads = create_connections_and_threads(conn_n, True)
        tcp_connections, tcp_threads = create_connections_and_threads(conn_n, False)
        threads = tls_threads + tcp_threads

        start_and_wait_threads(threads)
        tls_reset_conn_n = calculate_tls_reset_conn_n(tls_connections)
        tcp_reset_conn_n = calculate_tcp_reset_conn_n(tcp_connections)

        warns_expected = range(1, 2 * conn_n - 3)
        warns_occured = self.assertFrangWarning(self.burst_warning, warns_expected)
        self.assertEqual(tls_reset_conn_n + tcp_reset_conn_n, warns_occured)
        self.assertFrangWarning(self.rate_warning, expected=0)

    def test_rate(self):
        """
        Set tcp_connection_rate 3` and create 7 tls and 7 non-tls connections.
        Connections of both types will be blocked.
        """
        self.set_frang_config(frang_config=self.rate_config)
        conn_n = 7

        tls_connections = create_connections(conn_n, True, 0.01)
        tcp_connections = create_connections(conn_n, False, 0.01)

        tls_reset_conn_n = calculate_tls_reset_conn_n(tls_connections)
        tcp_reset_conn_n = calculate_tcp_reset_conn_n(tcp_connections)

        warns_expected = range(1, 2 * conn_n - 3)
        warns_occured = self.assertFrangWarning(self.rate_warning, warns_expected)
        self.assertEqual(tls_reset_conn_n + tcp_reset_conn_n, warns_occured)
        self.assertFrangWarning(self.burst_warning, expected=0)
