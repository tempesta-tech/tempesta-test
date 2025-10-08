"""
Tests for valid and invalid TLS handhshakes, various violations in
handshake messages.
"""

from helpers import analyzer, dmesg, error, remote
from helpers.cert_generator_x509 import CertGenerator
from test_suite import marks, tester

from .fuzzer import tls_record_fuzzer
from .handshake import *

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TlsHandshakeTest(tester.TempestaTest):
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
            listen 443 proto=https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
            }
        """
    }

    def start_all(self):
        deproxy_srv = self.get_server("0")
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1), "Cannot start Tempesta")

    def test_tls12_synthetic(self):
        self.start_all()
        res = TlsHandshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_1byte_transfer(self):
        self.start_all()
        self.oops_ignore = ["WARNING"]
        hs = TlsHandshake(chunk=1)
        hs.timeout = 30
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_9byte_transfer(self):
        self.start_all()
        self.oops_ignore = ["WARNING"]
        res = TlsHandshake(chunk=9).do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_10byte_transfer(self):
        self.start_all()
        self.oops_ignore = ["WARNING"]
        res = TlsHandshake(chunk=10).do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    @dmesg.unlimited_rate_on_tempesta_node
    def test_many_ciphers(self):
        self.start_all()
        hs12 = TlsHandshake()
        # Tempesta handles about 758 bytes worth of cipher list, and throws
        # away the remainder. As clients usually tend to send preferred ciphers
        # first, and there are no such number of distinct ciphers to fill those
        # 758 bytes, it's safe to ignore the remainder. Just making sure
        # Tempesta doesn't crash and doesn't generate an error message.

        # Put valid cipher in first 122 values
        hs12.ciphers = list(range(64, 50000))
        # Add some compressions as well. `0` is NULL-compression, so we are
        # good.
        hs12.compressions = list(range(15))
        res = hs12.do_12()
        self.assertTrue(res)

    @dmesg.unlimited_rate_on_tempesta_node
    def test_long_sni(self):
        """Also tests receiving of TLS alert."""
        self.start_all()
        hs12 = TlsHandshake()
        hs12.sni = "a" * 1000
        hs12.do_12()
        self.oops_ignore = ["WARNING"]
        self.assertTrue(hs12.hs.alert_received, "Alert not recieved")
        warn = "ClientHello: bad extension size"
        self.assertTrue(self.loggers.dmesg.find(warn), "No warning about bad ClientHello")

    def test_empty_sni_default(self):
        self.start_all()
        hs12 = TlsHandshake()
        hs12.sni = ""
        self.assertFalse(hs12.do_12(), "Empty SNI accepted by default")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_sni(self):
        """
        Try to open a connection with SNI that doesn't match any vhost name
        in configuration, but send a request which targets correct vhost.
        The connection will be rejected, due to SNI mismatch. Don't confuse it
        for Vhost Confusion prevention, where the connection will be established,
        but request - filtered.
        """
        self.start_all()
        hs12 = TlsHandshake()
        hs12.sni = "badservername"
        hs12.do_12()
        self.oops_ignore = ["WARNING"]
        self.assertTrue(hs12.hs.alert_received, "Alert not recieved")
        self.assertTrue(
            self.loggers.dmesg.find("requested unknown server name 'badservername'"),
            "Bad SNI isn't logged",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_sign_algs(self):
        self.start_all()
        hs12 = TlsHandshake()
        # Generate bad extension mismatching length and actual data.
        hs12.ext_sa = TLS_Ext_SignatureAlgorithms(
            sig_algs=[0x0201, 0x0401, 0x0501, 0x0601, 0x0403], len=11
        )
        hs12.do_12()
        self.oops_ignore = ["WARNING"]
        self.assertTrue(hs12.hs.alert_received, "Alert not recieved")
        warn = "ClientHello: bad signature algorithm extension"
        self.assertTrue(self.loggers.dmesg.find(warn), "No warning about bad ClientHello")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_elliptic_curves(self):
        self.start_all()
        hs12 = TlsHandshake()
        hs12.ext_ec = TLS_Ext_SupportedEllipticCurves(groups=["sect163k1"])
        hs12.do_12()
        self.oops_ignore = ["WARNING"]
        self.assertTrue(hs12.hs.alert_received, "Alert not recieved")
        warn = "None of the common ciphersuites is usable"
        self.assertTrue(self.loggers.dmesg.find(warn), "No warning about bad ClientHello")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_renegotiation_info(self):
        self.start_all()
        hs12 = TlsHandshake()

        hs12.renegotiation_info = TLS_Ext_RenegotiationInfo(
            renegotiated_connection="foo", type=65281
        )
        hs12.do_12()
        self.oops_ignore = ["WARNING"]
        self.assertTrue(hs12.hs.alert_received, "Alert not recieved")
        warn = "ClientHello: bad renegotiation_info"
        self.assertTrue(
            self.loggers.dmesg.find(warn), "No warning about non-empty RenegotiationInfo"
        )

    def test_alert(self):
        self.start_all()
        tls_conn = TlsHandshake()
        tls_conn.send_data = [
            TLSAlert(level=1, descr=10),
            TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
        ]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(
            len(tls_conn.hs.server_data) == 1,
            "Wrong request 1 result: %s" % tls_conn.hs.server_data,
        )

        # Unknown alerts are just ignored.
        tls_conn = TlsHandshake()
        tls_conn.send_data = [
            TLSAlert(level=22, descr=77),
            TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
        ]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(
            len(tls_conn.hs.server_data) == 1,
            "Wrong request 2 result: %s" % tls_conn.hs.server_data,
        )

        tls_conn = TlsHandshake()
        tls_conn.send_data = [
            TLSAlert(level=2, descr=10),
            TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
        ]
        tls_conn.do_12()
        self.assertTrue(len(tls_conn.hs.server_data) == 0, "Request processed on closed socket")

    def test_close_notify(self):
        self.start_all()
        tls_conn = TlsHandshake()
        tls_conn.send_data = [
            TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
            TLSAlert(level=1, descr=0),
            TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
        ]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(
            len(tls_conn.hs.server_data) == 2, "Wrong request result: %s" % tls_conn.hs.server_data
        )
        alert = tls_conn.hs.server_data[1]
        self.assertTrue(
            isinstance(alert, TLSAlert), "Wrong request result: %s" % tls_conn.hs.server_data
        )
        self.assertEqual(len(alert), 2)
        self.assertEqual(alert, TLSAlert(level=1, descr=0))

    @marks.profiled
    def test_fuzzing(self):
        """
        Inject bad (fuzzed) TLS records at different places on TLS handshake.
        Also try different message variants for each place.
        """
        self.start_all()
        fuzzer = tls_record_fuzzer()
        for _ in range(10):
            # Only 4 places to inject a packet in simple handshake and
            # request test.
            for inject_rec in range(4):
                tls_conn = TlsHandshake()
                tls_conn.inject = inject_rec
                try:
                    res = tls_conn.do_12(fuzzer)
                    self.assertFalse(res, "Got request on fuzzed connection")
                except:
                    # Broken pipe socket error and TLS fatal alerts are
                    # expected in the test.
                    pass

    def test_regression_1(self):
        """Application data records before ClientFinished."""
        self.start_all()

        class _ModifiedTLSClientAutomaton(ModifiedTLSClientAutomaton):
            self.host = "tempesta-tech.com"

            @ATMT.state()
            def ADDED_CHANGECIPHERSPEC(self):
                pass

            @ATMT.condition(ADDED_CHANGECIPHERSPEC)
            def should_add_ClientFinished(self):
                self.add_record()
                self.add_msg(
                    TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")
                )
                self.add_record()
                self.add_msg(TLSFinished())
                raise self.ADDED_CLIENTFINISHED()

        conn = TlsHandshake()
        res = conn.do_12(automaton=_ModifiedTLSClientAutomaton)
        self.assertFalse(res, "Bad handshake successfully processed")

    def test_old_handshakes(self):
        self.start_all()
        res = TlsHandshakeStandard().do_old()
        self.assertTrue(res, "Wrong old handshake result: %s" % res)


class TlsMissingDefaultKey(tester.TempestaTest):
    backends = TlsHandshakeTest.backends

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group be1 { server ${server_ip}:8000; }

            vhost example.com {
                proxy_pass be1;
            }

            vhost tempesta-tech.com {
                tls_certificate ${tempesta_workdir}/tempesta.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.key;
                proxy_pass be1;
            }
        """,
    }

    @dmesg.unlimited_rate_on_tempesta_node
    def test(self):
        deproxy_srv = self.get_server("0")
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1), "Cannot start Tempesta")

        # tempesta-tech.com => ok
        hs = TlsHandshake()
        hs.sni = "tempesta-tech.com"
        res = hs.do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

        # example.com => internal error
        hs = TlsHandshake()
        hs.sni = "example.com"
        hs.do_12()
        self.assertTrue(hs.hs.alert_received, "Alert not recieved")

        # empty sni => internal error
        hs = TlsHandshake()
        hs.sni = ""
        hs.do_12()
        self.assertTrue(hs.hs.alert_received, "Alert not recieved")
        self.assertTrue(
            self.loggers.dmesg.find(" requested unknown server name"), "Bad SNI isn't logged"
        )
        self.assertTrue(
            self.loggers.dmesg.find("requested missing server name"), "Bad SNI isn't logged"
        )


class TlsVhostHandshakeTest(tester.TempestaTest):
    backends = [
        {
            "id": "be1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "be1",
        },
        {
            "id": "be2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "be2",
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group be1 { server ${server_ip}:8000; }
            srv_group be2 { server ${server_ip}:8001; }

            # Ensure that vhost1 only is using the global certificate.
            tls_certificate ${tempesta_workdir}/vhost1.crt;
            tls_certificate_key ${tempesta_workdir}/vhost1.key;

            vhost vhost1.net {
                proxy_pass be1;
            }

            vhost vhost2.net {
                proxy_pass be2;
                tls_certificate ${tempesta_workdir}/vhost2.crt;
                tls_certificate_key ${tempesta_workdir}/vhost2.key;
            }

            http_chain {
                host == "vhost1.net" -> vhost1.net;
                host == "vhost2.net" -> vhost2.net;
                -> block;
            }
        """,
        "custom_cert": True,
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.gen_cert("vhost1")
        cls.gen_cert("vhost2")

    @staticmethod
    def gen_cert(host_name):
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        cgen.CN = host_name + ".net"
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    def test_vhost_sni(self):
        self.start_all_services(client=False)
        vhs = TlsHandshake()
        vhs.sni = "vhost1.net"
        vhs.send_data = [TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {vhs.sni}\r\n\r\n")]
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake with vhost1: %s" % res)
        self.assertTrue(
            vhs.hs.server_data[0].data.decode().endswith("be1"),
            "Bad response from vhost1: [%s]" % vhs.hs.server_data[0].data.decode(),
        )
        self.assertTrue(
            x509_check_cn(vhs.hs.server_cert[0], "vhost1.net"),
            "Wrong certificate received for vhost1",
        )

        vhs = TlsHandshake()
        vhs.sni = "vhost2.net"
        vhs.send_data = [TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {vhs.sni}\r\n\r\n")]
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake with vhost2: %s" % res)
        self.assertTrue(
            vhs.hs.server_data[0].data.decode().endswith("be2"),
            "Bad response from vhost2: [%s]" % vhs.hs.server_data[0].data.decode(),
        )
        self.assertTrue(
            x509_check_cn(vhs.hs.server_cert[0], "vhost2.net"),
            "Wrong certificate received for vhost2",
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def test_empty_sni_default(self):
        """
        When a client doesn't send an ampty SNI identifier, handshake will not be established
        And ensure the sni==vhost2.net provided will route to vhost2.net
        """
        self.start_all_services(client=False)
        vhs = TlsHandshake()
        vhs.sni = ""
        vhs.host = "vhost1.net"
        vhs.send_data = []
        res = vhs.do_12()
        self.assertFalse(res, "Handshake successfull with empty sni: %s" % res)

        vhs = TlsHandshake()
        vhs.sni = "vhost2.net"
        vhs.host = "vhost2.net"
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake: %s" % res)
        resp = vhs.hs.server_data[0].data.decode("utf-8")
        self.assertTrue(resp.endswith("be2"), "Bad response from vhost2: [%s]" % resp)
        self.assertTrue(
            x509_check_cn(vhs.hs.server_cert[0], "vhost2.net"),
            "Wrong certificate received for vhost1",
        )

    def test_bad_host(self):
        """
        Tempesta FW must block the client via http tables because it uses the invalid host in TLS handshake.
        We should except R or RA TCP flags because Tempesta can send one of the two.
        """
        sniffer = analyzer.Sniffer(node=remote.tempesta, host="Tempesta", timeout=3, ports=(443, ))
        sniffer.start()
        self.start_all_services(client=False)
        hs12 = TlsHandshake()
        hs12.sni = ["vhost1.net", "vhost2.net"]
        hs12.host = "bad.host.com"
        self.assertTrue(hs12.do_12(), "Bad Host successfully processed")
        self.assertEqual(len(hs12.hs.server_data), 0, "Got unexpected response after Errno 104")
        sniffer.stop()

        tempesta_to_client_packets = [p.sprintf("%TCP.flags%") for p in sniffer.packets if p[TCP].sport == 443]
        is_rst_present = "R" in tempesta_to_client_packets
        is_rst_and_ack_present = "RA" in tempesta_to_client_packets

        self.assertTrue(
            is_rst_present or is_rst_and_ack_present,
            f"No connection reset received. {is_rst_present = } and {is_rst_and_ack_present = }"
        )


class TlsCertReconfig(tester.TempestaTest):
    """
    Strictly speaking this is not a TLS handshake test, it's a certificates
    test. However, we need a low level access to the exchanged certificate, so
    ScaPy interface is required and the test went here.
    """

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
            }
        """,
    }

    @staticmethod
    def gen_cert():
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        cert_path = "%s/tempesta.crt" % workdir
        key_path = "%s/tempesta.key" % workdir
        cgen = CertGenerator(cert_path, key_path)
        cgen.O = "New Issuer"
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    def test(self):
        deproxy_srv = self.get_server("0")
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1), "Cannot start Tempesta")

        vhs = TlsHandshake()
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake: %s" % res)
        res = x509_check_issuer(vhs.hs.server_cert[0], "Tempesta Technologies Inc.")
        self.assertTrue(res, "Wrong certificate configured")

        # Reload Tempesta with new certificate.
        self.gen_cert()
        self.get_tempesta().reload()

        vhs = TlsHandshake()
        res = vhs.do_12()
        self.assertTrue(res, "Bad second handshake: %s" % res)
        res = x509_check_issuer(vhs.hs.server_cert[0], "New Issuer")
        self.assertTrue(res, "Wrong certificate reloaded")
