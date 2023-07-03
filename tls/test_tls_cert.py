"""
Tests for basic x509 handling: certificate loading and getting a valid request
and response, stale certificates and certificates with unsupported algorithms.
"""
from abc import abstractmethod
from datetime import datetime, timedelta
from itertools import cycle, islice

from cryptography.hazmat.primitives.asymmetric import ec

from framework import tester
from framework.templates import fill_template, populate_properties
from framework.x509 import CertGenerator
from helpers import dmesg, remote, tempesta, tf_cfg
from helpers.error import Error

from .handshake import TlsHandshake, x509_check_cn

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


def generate_certificate(cn="tempesta-tech.com", san=None, cert_name="tempesta"):
    """Generate and upload certificate with given
    common name and  list of Subject Alternative Names.
    Name generated files as `cert_name`.crt and `cert_name`.key.
    """
    workdir = tf_cfg.cfg.get("General", "workdir")

    cgen = CertGenerator(
        cert_path=f"{workdir}/{cert_name}.crt", key_path=f"{workdir}/{cert_name}.key"
    )
    cgen.CN = cn
    cgen.san = san
    cgen.generate()

    cert_path, key_path = cgen.get_file_paths()
    remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
    remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    return cgen


class X509(tester.TempestaTest):
    TIMEOUT = 1  # Use bigger timeout for debug builds.

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 10\r\n"
            "Connection: keep-alive\r\n\r\n"
            "0123456789",
        }
    ]

    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;
        tls_certificate %s;
        tls_certificate_key %s;
        server ${server_ip}:8000;
    """

    def __init__(self, *args, **kwargs):
        self.cgen = None
        super(X509, self).__init__(*args, **kwargs)

    def check_good_cert(self):
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()

        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())
        self.start_tempesta()

        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=self.TIMEOUT), "Cannot start Tempesta"
        )
        client = self.get_client("deproxy")
        client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, "200", "Bad response status: %s" % status)

    @dmesg.unlimited_rate_on_tempesta_node
    def check_bad_alg(self, msg):
        """
        Tempesta normally loads a certificate, but fails on TLS handshake.
        """
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()

        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())
        self.start_tempesta()

        # Collect warnings before start w/ a bad certificate.
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(
            deproxy_srv.wait_for_connections(timeout=X509.TIMEOUT), "Cannot start Tempesta"
        )
        client = self.get_client("deproxy")
        client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertFalse(res, "Erroneously established connection")
        self.assertEqual(
            self.oops.warn_count(msg), 1, "Tempesta doesn't throw a warning on bad certificate"
        )

    @dmesg.unlimited_rate_on_tempesta_node
    def check_cannot_start(self, msg):
        # Don't fail the test if errors and warnings are detected, It's an
        # expected behaviour.
        self.oops_ignore = ["WARNING", "ERROR"]
        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())
        try:
            self.start_tempesta()
        except:
            pass
        self.assertGreater(self.oops.warn_count(msg), 0, "Tempesta doesn't report error")


class RSA4096_SHA512(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha512"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA2048_SHA512(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 2048}
        self.cgen.sign_alg = "sha512"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA1024_SHA384(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 1024}
        self.cgen.sign_alg = "sha384"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA512_SHA256(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            "alg": "rsa",
            "len": 512,  # We do not support RSA key length less than 1024
        }
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start(
            "Warning: Trying to load an RSA key smaller"
            + " than 1024 bits. Please use stronger keys."
        )


class ECDSA_SHA256_SECP192(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            "alg": "ecdsa",
            "curve": ec.SECP192R1(),  # Deprecated curve, RFC 8422 5.1.1
        }
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("with OID 1.2.840.10045.3.1.1 is unsupported")


class ECDSA_SHA256_SECP256(X509):
    """ECDSA-SHA256-SECP256R1 is the default certificate."""

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "ecdsa", "curve": ec.SECP256R1()}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class ECDSA_SHA384_SECP521(X509):
    """The curve secp521r1 isn't recommended by IANA, so it isn't supported
    by Tempesta FW.
    https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
    """

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "ecdsa", "curve": ec.SECP521R1()}
        self.cgen.sign_alg = "sha384"
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("with OID 1.3.132.0.35 is unsupported")


class InvalidHash(X509):
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.sign_alg = "sha1"  # Unsupported
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("with OID 1.2.840.10045.4.1 is unsupported")


class StaleCert(X509):
    """
    We do allow to load stale certificates and just use them - that's not our
    business to limit a user which certificates to use. In general this is a job
    for tools like certbot. Probably, we should print a warning about stale
    certificates.
    """

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.not_valid_before = datetime.now() - timedelta(days=365)
        # Very small overdue as of 30 seconds.
        self.cgen.not_valid_after = datetime.now() - timedelta(seconds=30)
        self.cgen.generate()
        self.tempesta = {
            "config": X509.tempesta_tmpl % self.cgen.get_file_paths(),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class TlsCertSelect(tester.TempestaTest):
    clients = [
        {
            "id": "0",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "example.com",
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
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group be1 { server ${server_ip}:8000; }

            tls_certificate ${general_workdir}/tempesta_global.crt;
            tls_certificate_key ${general_workdir}/tempesta_global.key;

            vhost example.com {
                proxy_pass be1;
            }

            vhost tempesta-tech.com {
                proxy_pass be1;
                tls_certificate ${general_workdir}/tempesta_rsa.crt;
                tls_certificate_key ${general_workdir}/tempesta_rsa.key;
                tls_certificate ${general_workdir}/tempesta_ec.crt;
                tls_certificate_key ${general_workdir}/tempesta_ec.key;
            }

            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                host == "example.com" -> example.com;
                -> block;
            }
        """,
        "custom_cert": True,
    }

    # This function can be redefined in subclasses to provide
    # an instance TlsHandshake() with different parameters
    def get_tls_handshake(self):
        return TlsHandshake()

    @staticmethod
    def gen_cert(host_name, alg=None):
        workdir = tf_cfg.cfg.get("General", "workdir")
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        if alg == "rsa":
            cgen.key = {"alg": "rsa", "len": 2048}
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    def test_vhost_cert_selection(self):
        self.gen_cert("tempesta_ec")
        self.gen_cert("tempesta_rsa", "rsa")
        self.gen_cert("tempesta_global", "rsa")
        deproxy_srv = self.get_server("0")
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1), "Cannot start Tempesta")
        # TlsHandshake proposes EC only cipher suite and it must successfully
        # request Tempesta.
        res = self.get_tls_handshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        # Similarly it must fail on RSA-only vhost.
        hs = TlsHandshake()
        hs.sni = "example.com"
        hs.ciphers = list(range(49196, 49198))  # EC Ciphers
        res = hs.do_12()
        self.assertFalse(res, "Wrong handshake result: %s" % res)


class TlsCertSelectBySan(tester.TempestaTest):
    """Subject Alternative Name certificate match to SNI."""

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n"),
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:8000; }

            vhost example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }
        """,
        "custom_cert": True,
    }

    @property
    def verbose(self):
        return tf_cfg.v_level() >= 3

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def check_handshake_success(self, sni):
        """Run TLS handshake with the given SNI and check it is completes successfully."""
        hs = TlsHandshake()
        hs.sni = sni
        # TLS 1.2 handshake completed with no exception => SNI is accepted
        hs.do_12()
        self.assertTrue(x509_check_cn(hs.hs.server_cert[0], "tempesta-tech.com"))

    def check_handshake_unrecognized_name(self, sni):
        """
        Run TLS handshake with the given SNI
        and check server name is not recognised by the server.
        """
        hs = TlsHandshake()
        hs.sni = sni
        hs.do_12()
        self.assertEqual(hs.hs.state.state, "TLSALERT_RECIEVED", "Alert not recieved")

    def test_sni_matched(self):
        """SAN certificate matches the passed SNI."""
        san = ["example.com", "*.example.com"]
        generate_certificate(san=san)
        self.start_all()

        for sni in (
            "example.com",
            "a.example.com",
            "www.example.com",
            ".example.com",
            "-.example.com",
            "EXAMPLE.COM",
            "www.EXAMPLE.com",
            "A.EXAMPLE.COM",
            "A.eXaMpLe.CoM",
            # max length, length 240 'a' will give DECODE_ERROR
            f"{'-' * 239}.example.com",
        ):
            with self.subTest(msg="Trying TLS handshake", sni=sni):
                self.check_handshake_success(sni=sni)

    def test_sni_not_matched(self):
        """SAN certificate does not match the passed SNI."""
        san = ["example.com", "*.example.com"]
        generate_certificate(san=san)
        self.start_all()

        for sni in (
            "b.a.example.com",
            "..example.com",
            ".a.example.com",
            "www.www.example.com",
            "example.com.www",
            "example.com.",
            "a-example.com",
            "a.example.comm",
            "a.example.com-",
            "a.example.com.",
            "a.example.com.example.com",
            tf_cfg.cfg.get("Server", "ip"),
            "a" * 251,  # max length, 252 will give DECODE_ERROR
        ):
            with self.subTest(msg="Trying TLS handshake with expected unknown SNI", sni=sni):
                self.check_handshake_unrecognized_name(sni=sni)

    def test_various_san_and_sni_matched(self):
        """Various SAN certificates match the passed SNI."""
        # ignore "Vhost %s com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        generate_certificate()
        self.start_all()

        for san, sni in (
            (["*.b.c.example.com"], "a.b.c.example.com"),
            (["example.com"], "example.com"),
            ([".example.com"], "www.example.com"),
            (["www.localhost", "example.com"], "example.com"),
            (["*.xn--e1aybc.xn--90a3ac"], "xn--e1aybc.xn--e1aybc.xn--90a3ac"),
            (["localhost"], "localhost"),
            (["*.local"], "example.local"),
        ):
            generate_certificate(san=san)
            self.get_tempesta().reload()
            with self.subTest(msg="Trying TLS handshake", san=san, sni=sni):
                self.check_handshake_success(sni=sni)

    def test_various_san_and_sni_not_matched(self):
        """Various SAN certificates do not match the passed SNI."""
        # ignore "Vhost %s com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        generate_certificate()
        self.start_all()

        for san, sni in (
            (["a.*.example.com"], "a.b.example.com"),
            # Component fragment wildcards does not accepted.
            # Related discussion: https://codereview.chromium.org/762013002
            (["w*.example.com"], "www.example.com"),
            (["a.example.com"], "b.example.com"),
        ):
            generate_certificate(san=san)
            self.get_tempesta().reload()
            with self.subTest(
                msg="Trying TLS handshake with expected unknown SNI", san=san, sni=sni
            ):
                self.check_handshake_unrecognized_name(sni=sni)

    @dmesg.unlimited_rate_on_tempesta_node
    def test_unknown_server_name_warning(self):
        """Test that expected 'unknown server name' warning appears in DMESG logs."""
        generate_certificate(san=["example.com", "*.example.com"])
        self.start_all()

        for sni, printable_name in (
            ("localhost", "'localhost'"),
            ("a.localhost", "'a.localhost'"),
            ("a.b.localhost", "'a.b.localhost'"),  # subdomain should be displayed
            ("a.b.c.localhost", "'a.b.c.localhost'"),
            ("a.b.c.localhost.com", "'a.b.c.localhost.com'"),
            ("a.b.c.example.com", "'a.b.c.example.com'"),
            ("\0hidden part :)", "''"),  # non-printable characters allowed
            ("\n\n\n", "'"),  # empty lines appears in the log
        ):
            with self.subTest(msg="Check 'unknown server name' warning", sni=sni):
                with dmesg.wait_for_msg(
                    f"requested unknown server name {printable_name}", timeout=1, permissive=False
                ):
                    self.check_handshake_unrecognized_name(sni=sni)

    def test_sni_match_after_reload(self):
        """
        Test that SAN certificate match changes after (multiple) configuration reload.
        """
        RELOAD_COUNT = 5

        def handshake(sni):
            hs = TlsHandshake()
            hs.sni = sni
            return hs.do_12()

        san_iter = cycle(
            [
                ["*.example.com"],
                ["*.tempesta-tech.com"],
            ]
        )
        sni_iter = cycle(["a.example.com", "b.tempesta-tech.com"])

        generate_certificate(san=[])
        # ignore "Vhost %s com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        self.start_all()

        for i in range(RELOAD_COUNT):
            generate_certificate(san=next(san_iter))
            self.get_tempesta().reload()

            self.assertTrue(handshake(next(sni_iter)), "First handshake should pass")
            self.assertFalse(handshake(next(sni_iter)), "Second handshake should fail")
            next(sni_iter)  # additional shift to alternate the order


class TlsCertSelectBySanwitMultipleSections(tester.TempestaTest):
    """Test that no confusion occurs between wildcard certificate
    and certificate for specific subdomain. After Tempesta reload,
    certificate selection is changed according to the current config.
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n" "\r\n"),
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:8000; }

            vhost example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/wildcard.crt;
                tls_certificate_key ${general_workdir}/wildcard.key;
            }

            vhost private.example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/private.crt;
                tls_certificate_key ${general_workdir}/private.key;
            }
        """,
        "custom_cert": True,
    }

    config_no_private_section = """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:8000; }

            vhost example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/wildcard.crt;
                tls_certificate_key ${general_workdir}/wildcard.key;
            }
    """

    config_only_private_section = """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:8000; }

            vhost private.example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/private.crt;
                tls_certificate_key ${general_workdir}/private.key;
            }
    """

    @property
    def verbose(self):
        return tf_cfg.v_level() >= 3

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def reload_with_config(self, template: str):
        """Reconfigure Tempesta with the provided config `template`."""
        desc = {"config": template, "custom_cert": True}
        populate_properties(desc)
        config_text = fill_template(desc["config"], desc)

        config = tempesta.Config()
        config.set_defconfig(config_text, custom_cert=True)
        self.get_tempesta().config = config
        self.get_tempesta().reload()

    def test(self):
        generate_certificate(
            cert_name="wildcard", cn="wildcard", san=["example.com", "*.example.com"]
        )
        generate_certificate(
            cert_name="private", cn="private", san=["example.com", "private.example.com"]
        )
        self.start_all()
        # save the current config text
        original_config = self.get_tempesta().config.defconfig

        # Both 'wildcard' and 'private' certificates are provided
        for sni, expected_cert in (
            ("example.com", "private"),
            ("private.example.com", "private"),
            ("public.example.com", "wildcard"),
        ):
            with self.subTest(msg="Trying TLS handshake", sni=sni):
                hs = TlsHandshake()
                hs.sni = sni
                hs.do_12()
                self.assertTrue(x509_check_cn(hs.hs.server_cert[0], expected_cert))

        self.reload_with_config(self.config_no_private_section)
        # After Tempesta reload, 'wildcard' certificate are provided for all subdomains
        for sni, expected_cert in (
            ("example.com", "wildcard"),
            ("public.example.com", "wildcard"),
            ("private.example.com", "wildcard"),
        ):
            with self.subTest(msg="Trying TLS handshake after config reload", sni=sni):
                hs = TlsHandshake()
                hs.sni = sni
                hs.do_12()
                self.assertTrue(x509_check_cn(hs.hs.server_cert[0], expected_cert))

        self.reload_with_config(self.config_only_private_section)
        for sni in "example.com", "private.example.com":
            # After Tempesta reload,
            # 'private' certificate is provided for 'private' section,
            hs = TlsHandshake()
            hs.sni = sni
            hs.do_12()
            self.assertTrue(x509_check_cn(hs.hs.server_cert[0], "private"))

        # and no certificate provided for removed 'wildcard' section subdomains
        for sni in ["public.example.com"]:
            with self.subTest(msg="Check 'unknown server name' warning after reload", sni=sni):
                hs = TlsHandshake()
                hs.sni = sni
                hs.do_12()
                self.assertEqual(hs.hs.state.state, "TLSALERT_RECIEVED")

        # After Tempesta reload, certificates are provided as at the beginning of the test
        self.reload_with_config(original_config)
        for sni, expected_cert in (
            ("example.com", "private"),
            ("private.example.com", "private"),
            ("public.example.com", "wildcard"),
        ):
            with self.subTest(msg="Trying TLS handshake after second config reload", sni=sni):
                hs = TlsHandshake()
                hs.sni = sni
                hs.do_12()
                self.assertTrue(x509_check_cn(hs.hs.server_cert[0], expected_cert))


class WrkTestsMultipleVhosts(tester.TempestaTest):
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

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
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

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "ssl": True,
            "addr": f'{tf_cfg.cfg.get("Tempesta", "ip")}:443',
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    def config_changer(self):
        self.set_second_config()
        self.set_first_config()
        self.set_second_config()
        self.set_first_config()
        self.set_second_config()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()

    def test_wrk(self):
        generate_certificate(
            cert_name="localhost", cn="localhost", san=[tf_cfg.cfg.get("Tempesta", "ip")]
        )
        generate_certificate(
            cert_name="private", cn="private", san=["example.com", "private.example.com"]
        )
        self.start_all()
        self.set_first_config()
        wrk = self.get_client("wrk")
        wrk.duration = 10
        wrk.start()
        self.config_changer()
        wrk.stop()
        self.wait_while_busy(wrk)
        print(dir(wrk.statuses))
        print(wrk.statuses)
        self.assertNotEqual(
            0,
            wrk.requests,
            msg='"wrk" client has not sent requests or received results.',
        )
        
    def set_first_config(self):
        config = tempesta.Config()
        config.set_defconfig(
            """
                cache 0;
                listen 443 proto=https;

                srv_group sg { server %s:8000; }

                vhost localhost {
                    proxy_pass sg;
                    tls_certificate /tmp/host/localhost.crt;
                    tls_certificate_key /tmp/host/localhost.key;
                }

                vhost private.example.com {
                    proxy_pass sg;
                    tls_certificate /tmp/host/private.crt;
                    tls_certificate_key /tmp/host/private.key;
                }
                
                http_chain {
                    -> localhost;
                }
            """ % (tf_cfg.cfg.get("General", "ip")),
        custom_cert=True
        )
        self.get_tempesta().config = config
        self.get_tempesta().reload()
        
    def set_second_config(self):
        config = tempesta.Config()
        config.set_defconfig(
            """
                cache 0;
                listen 443 proto=https;

                srv_group sg { server %s:8000; }

                vhost private.example.com {
                    proxy_pass sg;
                    tls_certificate /tmp/host/private.crt;
                    tls_certificate_key /tmp/host/private.key;
                }

                vhost localhost {
                    proxy_pass sg;
                    tls_certificate /tmp/host/localhost.crt;
                    tls_certificate_key /tmp/host/localhost.key;
                }
                
                http_chain {
                    -> localhost;
                }
                
            """% (tf_cfg.cfg.get("General", "ip")),
        custom_cert=True)
        self.get_tempesta().config = config
        self.get_tempesta().reload()


class BaseTlsSniWithHttpTable(tester.TempestaTest, base=True):
    """
    Base class for vhost sections access tests.
    """

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "example.com",
        },
    ]

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 8\r\n\r\n" "server-1"),
        },
        {
            "id": "server-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 8\r\n\r\n" "server-2"),
        },
        {
            "id": "server-3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 8\r\n\r\n" "server-3"),
        },
        {
            "id": "server-4",
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 8\r\n\r\n" "server-4"),
        },
    ]

    tempesta_tmpl = """
            cache 0;
            listen 443 proto=https;
            frang_limits {
                http_strict_host_checking;
            }

            # Optional Frang section
            %s

            srv_group sg1 { server ${server_ip}:8000; }
            srv_group sg2 { server ${server_ip}:8001; }
            srv_group sg3 { server ${server_ip}:8002; }
            srv_group sg4 { server ${server_ip}:8003; }

            vhost example.com {
                proxy_pass sg1;
                tls_certificate ${general_workdir}/example.crt;
                tls_certificate_key ${general_workdir}/example.key;
            }

            vhost tempesta-tech.com {
                proxy_pass sg2;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }

            vhost localhost-vhost {
                proxy_pass sg3;
            }

            vhost default-vhost {
                proxy_pass sg4;
            }

            http_chain {
              host == "example.com" -> example.com;
              host == "localhost" -> localhost-vhost;
              host == "tempesta-tech.com" -> tempesta-tech.com;
              -> default-vhost;
            }
    """

    @property
    @abstractmethod
    def frang_limits(self):
        pass

    def setUp(self):
        self.tempesta = {"config": self.tempesta_tmpl % (self.frang_limits), "custom_cert": True}
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def make_request(self, host):
        """Make request with the specified `host` header and
        return the body of response."""
        client = self.get_client("deproxy")
        client.make_request(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
        return client.wait_for_response(timeout=X509.TIMEOUT)

    def expect_request_processed(self, host, expected_server):
        self.assertTrue(self.make_request(host))
        client = self.get_client("deproxy")
        status = client.last_response.status
        self.assertEqual(status, "200", f"Bad response status: {status}")
        self.assertEqual(client.last_response.body, expected_server)

    def expect_request_fail(self, host):
        self.assertFalse(self.make_request(host))

    def test_valid(self):
        """
        CN: example.com
        SAN: [example.com]
        SNI: example.com
        HOST: example.com
        """
        generate_certificate(cn="example.com", san=["example.com"])
        self.start_all()
        self.expect_request_processed("example.com", expected_server="server-1")

    def test_with_san(self):
        """
        CN: random()
        SAN: [example.com]
        SNI: example.com
        HOST: localhost
        """
        generate_certificate(cn="random-name", san=["example.com"], cert_name="example")
        self.start_all()
        self.expect_request_fail("localhost")

    def test_with_common_name(self):
        """
        CN: example.com
        SAN: []
        SNI: example.com
        HOST: localhost
        """
        generate_certificate(cn="example.com", san=None)
        self.start_all()
        self.expect_request_fail("localhost")

    def test_with_any_host(self):
        """
        CN: random()
        SAN: []
        SNI: example.com
        HOST: random()
        """
        # ignore "Vhost example.com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        generate_certificate(cn="random-name", san=None)
        self.start_all()
        self.expect_request_fail("another-random-name")


class TlsSniWithHttpTable(BaseTlsSniWithHttpTable):
    """
    Test that vhost could not be accessed with certificate from another section.
    """

    frang_limits = ""


class BaseTlsMultiTest(tester.TempestaTest, base=True):
    """Base class to test multiplexed (pipelided) requests."""

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: server-1\r\n"
                "Date: test\r\n"
                "Content-Length: 8\r\n\r\n"
                "server-1"
            ),
        },
        {
            "id": "server-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: server-2\r\n"
                "Date: test\r\n"
                "Content-Length: 8\r\n\r\n"
                "server-2"
            ),
        },
    ]

    tempesta_tmpl = """
            cache 0;
            listen 443 proto=%s;
            frang_limits {
                http_strict_host_checking;
            }

            # Optional Frang section
            %s

            srv_group sg1 { server ${server_ip}:8000; }
            srv_group sg2 { server ${server_ip}:8001; }

            vhost example.com {
                proxy_pass sg1;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }

            vhost localhost-vhost {
                proxy_pass sg2;
            }

            http_chain {
              host == "localhost" -> localhost-vhost;
              host == "a.example.com" -> example.com;
            }
    """

    @property
    @abstractmethod
    def proto(self):
        pass

    @property
    @abstractmethod
    def clients(self):
        pass

    @property
    @abstractmethod
    def frang_limits(self):
        pass

    @abstractmethod
    def build_requests(self, hosts):
        pass

    def setUp(self):
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto, self.frang_limits),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def start_all(self):
        generate_certificate(san=["example.com", "*.example.com"])
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def run_alterative_access(self):
        """Try to access multiple hosts in alterating order."""
        REQ_NUM = 4
        self.assertFalse(REQ_NUM % 2, "REQ_NUM should be even")
        host_iter = cycle(["a.example.com", "localhost"])

        self.start_all()
        client = self.get_client("deproxy")
        server1 = self.get_server("server-1")
        server2 = self.get_server("server-2")

        client.make_requests(self.build_requests(hosts=islice(host_iter, REQ_NUM)))
        client.wait_for_response(timeout=2)

        self.assertLess(len(client.responses), 2)
        # server1 received requests
        self.assertGreater(len(server1.requests), 0)
        # server2 did not receive requests
        self.assertEqual(len(server2.requests), 0)


class TlsSniWithHttpTableMulti(BaseTlsMultiTest):
    proto = "https"
    frang_limits = ""

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "a.example.com",
        },
    ]

    def build_requests(self, hosts):
        def build_request(host):
            return "GET / HTTP/1.1\r\n" f"Host: {host}\r\n" "\r\n"

        return "".join([build_request(host) for host in hosts])

    def test_alternating_access(self):
        """
        Test for HTTP/1.1 pipelined request: 'localhost'
        vhost should not receive requests.
        """
        self.run_alterative_access()


class TlsSniWithHttpTableMultiH2(BaseTlsMultiTest):
    proto = "h2"
    frang_limits = ""

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "example.com",
        },
    ]

    def build_requests(self, hosts):
        def build_request(host):
            return [(":authority", host), (":path", "/"), (":scheme", "https"), (":method", "GET")]

        return [build_request(host) for host in hosts]

    def test_alternating_access(self):
        """
        Test for HTTP/2 multiplexed requests: 'localhost'
        vhost should not receive requests.
        """
        self.run_alterative_access()
