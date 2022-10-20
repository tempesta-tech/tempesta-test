"""
Tests for valid and invalid TLS handhshakes, various violations in
handshake messages.
"""
from time import sleep
from framework import tester
from framework.x509 import CertGenerator
from helpers import remote, tf_cfg, util, dmesg
from .handshake import *
from .fuzzer import tls_record_fuzzer

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TlsHandshakeTest(tester.TempestaTest):

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;

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
        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")

    def test_tls12_synthetic(self):
        self.start_all()
        res = TlsHandshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_1byte_transfer(self):
        self.start_all()
        res = TlsHandshake(chunk=1).do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_9byte_transfer(self):
        self.start_all()
        res = TlsHandshake(chunk=9).do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_10byte_transfer(self):
        self.start_all()
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
        hs12.ciphers = list(range(64,50000)) # Working
        # hs12.ciphers = list(range(50000)) # Not working
        # Add some compressions as well. `0` is NULL-compression, so we are
        # good.
        hs12.compressions = list(range(15))
        res = hs12.do_12()
        self.assertTrue(res)

    @dmesg.unlimited_rate_on_tempesta_node
    def test_long_sni(self):
        """ Also tests receiving of TLS alert. """
        self.start_all()
        hs12 = TlsHandshake()
        hs12.sni = "a" * 1000
        # Tempesta must send a TLS alerts raising TLSProtocolError exception.
        hs12.do_12()
        self.oops_ignore = ['WARNING']
        self.assertEqual(hs12.hs.state.state, 'TLSALERT_RECIEVED')
        warn = "ClientHello: bad extension size"
        self.assertEqual(self.oops.warn_count(warn), 1,
                         "No warning about bad ClientHello")

    def test_empty_sni_default(self):
        self.start_all()
        hs12 = TlsHandshake()
        hs12.sni = ''
        self.assertTrue(hs12.do_12(), "Empty SNI isn't accepted by default")

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
        hs12.sni = "bad.server.name"
        hs12.do_12()
        self.oops_ignore = ['WARNING']
        self.assertEqual(hs12.hs.state.state, 'TLSALERT_RECIEVED')
        self.assertEqual(self.oops.warn_count("requested unknown server name '.server.name'"), 1,
                         "Bad SNI isn't logged")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_sign_algs(self):
        self.start_all()
        hs12 = TlsHandshake()
        # Generate bad extension mismatching length and actual data.
        hs12.ext_sa = TLS_Ext_SignatureAlgorithms(sig_algs=[0x0201, 0x0401, 0x0501, 0x0601, 0x0403],len=11)
        # Tempesta must send a TLS alerts raising TLSProtocolError exception.
        hs12.do_12()
        self.oops_ignore = ['WARNING']
        self.assertEqual(hs12.hs.state.state, 'TLSALERT_RECIEVED')
        warn = "ClientHello: bad signature algorithm extension"
        self.assertEqual(self.oops.warn_count(warn), 1,
                         "No warning about bad ClientHello")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_elliptic_curves(self):
        self.start_all()
        hs12 = TlsHandshake()
        # Tempesta must send a TLS alerts raising TLSProtocolError exception.
        hs12.ext_ec = TLS_Ext_SupportedEllipticCurves(groups=['sect163k1'])
        hs12.do_12()
        self.oops_ignore = ['WARNING']
        self.assertEqual(hs12.hs.state.state, 'TLSALERT_RECIEVED')
        warn = "None of the common ciphersuites is usable"
        self.assertEqual(self.oops.warn_count(warn), 1,
                         "No warning about bad ClientHello")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_bad_renegotiation_info(self):
        self.start_all()
        hs12 = TlsHandshake()
        hs12.renegotiation_info = TLS_Ext_RenegotiationInfo(renegotiated_connection="foo", type=65281)
        # Tempesta must send a TLS alerts raising TLSProtocolError exception.
        hs12.do_12()
        self.oops_ignore = ['WARNING']
        self.assertEqual(hs12.hs.state.state, 'TLSALERT_RECIEVED')
        warn = "ClientHello: bad renegotiation_info"
        self.assertEqual(self.oops.warn_count(warn), 1,
                         "No warning about non-empty RenegotiationInfo")

    def test_alert(self):
        self.start_all()
        tls_conn = TlsHandshake()
        tls_conn.send_data = [TLSAlert(level=1, descr=10), TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(len(tls_conn.hs.server_data)==1, "Wrong request 1 result: %s" % tls_conn.hs.server_data)
        
        # Unknown alerts are just ignored.
        tls_conn = TlsHandshake()
        tls_conn.send_data = [TLSAlert(level=22, descr=77), TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(len(tls_conn.hs.server_data)==1, "Wrong request 2 result: %s" % tls_conn.hs.server_data)
        
        tls_conn = TlsHandshake()
        tls_conn.send_data = [TLSAlert(level=2, descr=10), TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")]
        tls_conn.do_12()
        self.assertTrue(len(tls_conn.hs.server_data)==0, "Request processed on closed socket")

    def test_close_notify(self):
        self.start_all()
        tls_conn = TlsHandshake()
        tls_conn.send_data = [TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"), TLSAlert(level=1, descr=0), TLSApplicationData(data="GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")]
        self.assertTrue(tls_conn.do_12(), "Can not connect to Tempesta")
        self.assertTrue(len(tls_conn.hs.server_data)==2, "Wrong request result: %s" % tls_conn.hs.server_data)
        alert = tls_conn.hs.server_data[1]
        self.assertTrue(isinstance(alert, TLSAlert), "Wrong request result: %s" % tls_conn.hs.server_data)
        self.assertEqual(len(alert), 2)
        self.assertEqual(alert, TLSAlert(level=1, descr=0))

    @util.profiled
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
        conn = TlsHandshake()
        conn.conn_estab()
        c_h = tls.TLSClientHello(
            gmt_unix_time=0x22222222,
            random_bytes='\x11' * 28,
            cipher_suites=[
                tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
            compression_methods=[tls.TLSCompressionMethod.NULL],
            extensions=[
                tls.TLSExtension() / tls.TLSExtECPointsFormat()]
            + conn.extra_extensions()
        )
        msg1 = tls.TLSRecord(version='TLS_1_2') / \
               tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / c_h])
        resp = conn.send_recv(msg1)
        self.assertTrue(resp.haslayer(tls.TLSCertificate))

        cke_h = tls.TLSHandshakes(
            handshakes=[tls.TLSHandshake() /
                        conn.sock.tls_ctx.get_client_kex_data(val=0xdeadbabe)])
        msg2 = tls.TLSRecord(version='TLS_1_2') / cke_h
        msg3 = tls.TLSRecord(version='TLS_1_2') / tls.TLSChangeCipherSpec()

        conn.sock.sendall(tls.TLS.from_records([msg2, msg3]))
        # An application data record before Client Finished message.
        conn.send_recv(tls.TLSPlaintext(data='x'*1000))

    def test_old_handshakes(self):
        self.start_all()
        res = TlsHandshakeStandard().do_old()
        self.assertTrue(res, "Wrong old handshake result: %s" % res)


class TlsMissingDefaultKey(tester.TempestaTest):
    backends = TlsHandshakeTest.backends

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group be1 { server ${server_ip}:8000; }

            vhost example.com {
                proxy_pass be1;
            }

            vhost tempesta-tech.com {
                proxy_pass be1;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }

            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "example.com" -> example.com;
                -> block;
            }
        """,
    }

    @dmesg.unlimited_rate_on_tempesta_node
    def test(self):
        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")

        # tempesta.com => ok
        res = TlsHandshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)

        # example.com => internal error
        hs = TlsHandshake()
        hs.sni = ['example.com']
        with self.assertRaises(tls.TLSProtocolError):
            hs.do_12()
        # empty sni => internal error
        hs = TlsHandshake()
        hs.sni = []
        with self.assertRaises(tls.TLSProtocolError):
            hs.do_12()
        self.assertEqual(self.oops.warn_count("requested misconfigured vhost"), 2,
                         "Bad SNI isn't logged")


class TlsVhostHandshakeTest(tester.TempestaTest):
    backends = [
        {
            'id' : 'be1',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 3\r\n'
                'Connection: keep-alive\r\n'
                '\r\n'
                'be1'
        },
        {
            'id' : 'be2',
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 3\r\n'
                'Connection: keep-alive\r\n'
                '\r\n'
                'be2'
        }
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            srv_group be1 { server ${server_ip}:8000; }
            srv_group be2 { server ${server_ip}:8001; }

            # Ensure that vhost1 only is using the global certificate.
            tls_certificate ${general_workdir}/vhost1.crt;
            tls_certificate_key ${general_workdir}/vhost1.key;

            vhost vhost1.net {
                proxy_pass be1;
            }

            vhost vhost2.net {
                proxy_pass be2;
                tls_certificate ${general_workdir}/vhost2.crt;
                tls_certificate_key ${general_workdir}/vhost2.key;
            }

            http_chain {
                host == "vhost1.net" -> vhost1.net;
                host == "vhost2.net" -> vhost2.net;
                -> block;
            }
        """,
        'custom_cert': True
    }

    @staticmethod
    def gen_cert(host_name):
        workdir = tf_cfg.cfg.get('General', 'workdir')
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        cgen.CN = host_name + u'.net'
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    def init(self):
        self.gen_cert("vhost1")
        self.gen_cert("vhost2")
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()

    def test_vhost_sni(self):
        self.init()
        vhs = TlsHandshake()
        vhs.sni = "vhost1.net"
        vhs.send_data = [TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {vhs.sni}\r\n\r\n")]
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake with vhost1: %s" % res)
        self.assertTrue(vhs.hs.server_data[0].data.decode().endswith("be1"),
                        "Bad response from vhost1: [%s]" % vhs.hs.server_data[0].data.decode())
        self.assertTrue(x509_check_cn(vhs.hs.server_cert[0], "vhost1.net"),
                        "Wrong certificate received for vhost1")

        vhs = TlsHandshake()
        vhs.sni = "vhost2.net"
        vhs.send_data = [TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: {vhs.sni}\r\n\r\n")]
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake with vhost2: %s" % res)
        self.assertTrue(vhs.hs.server_data[0].data.decode().endswith("be2"),
                        "Bad response from vhost2: [%s]" % vhs.hs.server_data[0].data.decode())
        self.assertTrue(x509_check_cn(vhs.hs.server_cert[0], "vhost2.net"),
                        "Wrong certificate received for vhost2")

    @dmesg.unlimited_rate_on_tempesta_node
    def test_empty_sni_default(self):
        """When a client doesn't send a SNI identifier, the global certificates
        will be used. The request is processed well, if it follows the
        http_chain rules by the host header.
        """
        self.init()
        vhs = TlsHandshake()
        vhs.sni = ''
        vhs.host = 'vhost1.net'
        # vhs.send_data = [TLSApplicationData(data=f"GET / HTTP/1.1\r\nHost: vhost1.net\r\n\r\n")]
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake: %s" % res)
        resp = vhs.hs.server_data[0].data.decode("utf-8")
        self.assertTrue(resp.endswith("be1"),
                        "Bad response from vhost1: [%s]" % resp)
        self.assertTrue(x509_check_cn(vhs.hs.server_cert[0], "vhost1.net"),
                        "Wrong certificate received for vhost1")

        vhs = TlsHandshake()
        vhs.sni = ''
        vhs.host = "vhost2.net"
        res = vhs.do_12()
        self.assertTrue(res, "Bad handshake: %s" % res)
        resp = vhs.hs.server_data[0].data.decode("utf-8")
        self.assertTrue(resp.endswith("be2"),
                        "Bad response from vhost2: [%s]" % resp)
        self.assertTrue(x509_check_cn(vhs.hs.server_cert[0], "vhost1.net"),
                        "Wrong certificate received for vhost1")

    def test_bad_host(self):
        self.init()
        hs12 = TlsHandshake()
        hs12.sni = ["vhost1.net", "vhost2.net"]
        hs12.host = "bad.host.com"
        self.assertFalse(hs12.do_12(), "Bad Host successfully processed")


class TlsCertReconfig(tester.TempestaTest):
    """
    Strictly speaking this is not a TLS handshake test, it's a certificates
    test. However, we need a low level access to the exchanged certificate, so
    ScaPy interface is required and the test went here.
    """
    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Connection: keep-alive\r\n\r\n'
        },
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;

            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;

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
        workdir = tf_cfg.cfg.get('General', 'workdir')
        cert_path = "%s/tempesta.crt" % workdir
        key_path = "%s/tempesta.key" % workdir
        cgen = CertGenerator(cert_path, key_path)
        cgen.O = u'New Issuer'
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())
    def test(self):
        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")

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
