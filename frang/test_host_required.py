"""
Tests for Frang directive `http_host_required'.
"""

from framework import tester
from helpers import dmesg


class HostHeader(tester.TempestaTest):
    """
    Tests for non-TLS related checks in 'http_host_required' directive. See
    TLSMatchHostSni test for other cases.
    """

    clients = [{"id": "client", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 80;

            frang_limits {
                http_host_required;
            }

            server ${server_ip}:8000;

        """
    }

    WARN_OLD_PROTO = "Warning: frang: Host header field in protocol prior to HTTP/1.1"
    WARN_UNKNOWN = "Warning: frang: Request authority is unknown"
    WARN_DIFFER = "Warning: frang: Request authority in URI differs from host header"
    WARN_IP_ADDR = "Warning: frang: Host header field contains IP address"

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server("0")
        self.assertTrue(srv.wait_for_connections(timeout=1))

    def test_host_good(self):
        """Host header is provided, and has the same value as URI in absolute
        form.
        """
        self.start_all()

        requests = (
            "GET / HTTP/1.1\r\n"
            "Host: tempesta-tech.com\r\n"
            "\r\n"
            "GET / HTTP/1.1\r\n"
            "Host:    tempesta-tech.com     \r\n"
            "\r\n"
            "GET http://tempesta-tech.com/ HTTP/1.1\r\n"
            "Host: tempesta-tech.com\r\n"
            "\r\n"
            "GET http://user@tempesta-tech.com/ HTTP/1.1\r\n"
            "Host: tempesta-tech.com\r\n"
            "\r\n"
        )
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(4, len(deproxy_cl.responses))
        self.assertFalse(deproxy_cl.connection_is_closed())

    def test_host_empty(self):
        """Host header has empty value. Restricted by Tempesta security rules."""
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" "Host: \r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_UNKNOWN), 1, "Frang limits warning is not shown")

    def test_host_missing(self):
        """Host header is missing, but required."""
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_UNKNOWN), 1, "Frang limits warning is not shown")

    def test_host_old_proto(self):
        """Host header in http request below http/1.1. Restricted by
        Tempesta security rules.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.0\r\n" "Host: tempesta-tech.com\r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(
            klog.warn_count(self.WARN_OLD_PROTO), 1, "Frang limits warning is not shown"
        )

    def test_host_mismatch(self):
        """Host header and authority in uri has different values."""
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET http://user@tempesta-tech.com/ HTTP/1.1\r\n" "Host: example.com\r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_DIFFER), 1, "Frang limits warning is not shown")

    def test_host_mismatch_empty(self):
        """Host header is empty, only authority in uri points to specific
        virtual host. Not allowed by RFC.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET http://user@tempesta-tech.com/ HTTP/1.1\r\n" "Host: \r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_UNKNOWN), 1, "Frang limits warning is not shown")

    def test_host_ip(self):
        """Host header in IP address form. Restricted by Tempesta security
        rules.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" "Host: 127.0.0.1\r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_IP_ADDR), 1, "Frang limits warning is not shown")

    def test_host_ip6(self):
        """Host header in IP address form. Restricted by Tempesta security
        rules.
        """
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)

        requests = "GET / HTTP/1.1\r\n" "Host: [::1]:80\r\n" "\r\n"
        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(requests)
        deproxy_cl.wait_for_response()

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertEqual(klog.warn_count(self.WARN_IP_ADDR), 1, "Frang limits warning is not shown")


class AuthorityHeader(tester.TempestaTest):
    """Test for 'http_host_required' directive, h2 protocol version,
    Curl is not flexible as Deproxy, so we cant set headers as we want to,
    so only basic tests are done here. Key `=H "host:..."` sets authority
    header for h2, not Host header.
    """

    clients = [
        {
            "id": "curl-ip",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-kf " "https://${tempesta_ip}/ "  # Set non-null return code on 4xx-5xx responses.
            ),
        },
        {
            "id": "curl-dns",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-kf "  # Set non-null return code on 4xx-5xx responses.
                "https://${tempesta_ip}/ "
                '-H "host: tempesta-test.com"'
            ),
        },
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            frang_limits {
                http_host_required;
            }

            server ${server_ip}:8000;

        """
    }

    WARN_IP_ADDR = "Warning: frang: Host header field contains IP address"

    def test_pass(self):
        """Authority header contains host in DNS form, request is allowed."""
        curl = self.get_client("curl-dns")

        self.start_all_servers()
        self.start_tempesta()
        srv = self.get_server("0")
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        klog = dmesg.DmesgFinder(ratelimited=False)

        curl.start()
        self.wait_while_busy(curl)
        self.assertEqual(
            0, curl.returncode, msg=("Curl return code is not 0 (%d)." % (curl.returncode))
        )
        self.assertEqual(
            klog.warn_count(self.WARN_IP_ADDR), 0, "Frang limits warning is incorrectly shown"
        )
        curl.stop()

    def test_block(self):
        """Authority header  contains name in IP address form, request is
        rejected.
        """
        curl = self.get_client("curl-ip")

        self.start_all_servers()
        self.start_tempesta()
        srv = self.get_server("0")
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(timeout=1))
        klog = dmesg.DmesgFinder(ratelimited=False)

        curl.start()
        self.wait_while_busy(curl)
        self.assertEqual(
            1, curl.returncode, msg=("Curl return code is not 1 (%d)." % (curl.returncode))
        )
        self.assertEqual(klog.warn_count(self.WARN_IP_ADDR), 1, "Frang limits warning is not shown")
        curl.stop()
