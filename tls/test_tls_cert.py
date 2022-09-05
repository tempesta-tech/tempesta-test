"""
Tests for basic x509 handling: certificate loading and getting a valid request
and response, stale certificates and certificates with unsupported algorithms.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from itertools import cycle, islice

from helpers import dmesg, remote, tempesta, tf_cfg
from helpers.error import Error
from framework import tester
from framework.templates import fill_template, populate_properties
from framework.x509 import CertGenerator
from .handshake import TlsHandshake, x509_check_cn
from .scapy_ssl_tls import ssl_tls as tls

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


def generate_certificate(
        cn: str = 'tempesta-tech.com',
        san: list[str] = None,
        cert_name: str = "tempesta"
) -> CertGenerator:
    """Generate and upload certificate with given
    common name and  list of Subject Alternative Names.
    Name generated files as `cert_name`.crt and `cert_name`.key.
    """
    workdir = tf_cfg.cfg.get('General', 'workdir')

    cgen = CertGenerator(
        cert_path=f"{workdir}/{cert_name}.crt",
        key_path=f"{workdir}/{cert_name}.key"
    )
    cgen.CN = cn
    cgen.san = san
    cgen.generate()

    cert_path, key_path = cgen.get_file_paths()
    remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
    remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    return cgen


class X509(tester.TempestaTest):

    TIMEOUT = 1 # Use bigger timeout for debug builds.

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
    ]

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n' \
                'Content-Length: 10\r\n' \
                'Connection: keep-alive\r\n\r\n'
                '0123456789'
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
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()

        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())
        self.start_tempesta()

        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=self.TIMEOUT),
                        "Cannot start Tempesta")
        client = self.get_client('deproxy')
        client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, '200', "Bad response status: %s" % status)

    @dmesg.unlimited_rate_on_tempesta_node
    def check_bad_alg(self, msg):
        """
        Tempesta normally loads a certificate, but fails on TLS handshake.
        """
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()

        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())
        self.start_tempesta()

        # Collect warnings before start w/ a bad certificate.
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=X509.TIMEOUT),
                        "Cannot start Tempesta")
        client = self.get_client('deproxy')
        client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertFalse(res, "Erroneously established connection")
        self.assertEqual(self.oops.warn_count(msg), 1,
                         "Tempesta doesn't throw a warning on bad certificate")

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
        self.assertGreater(self.oops.warn_count(msg), 0,
                           "Tempesta doesn't report error")


class RSA4096_SHA512(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'rsa',
            'len': 4096
        }
        self.cgen.sign_alg = 'sha512'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA2048_SHA512(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'rsa',
            'len': 2048
        }
        self.cgen.sign_alg = 'sha512'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA1024_SHA384(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'rsa',
            'len': 1024
        }
        self.cgen.sign_alg = 'sha384'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class RSA512_SHA256(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'rsa',
            'len': 512 # We do not support RSA key length less than 1024
        }
        self.cgen.sign_alg = 'sha256'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("Warning: Trying to load an RSA key smaller"
                                + " than 1024 bits. Please use stronger keys.")


class ECDSA_SHA256_SECP192(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP192R1() # Deprecated curve, RFC 8422 5.1.1
        }
        self.cgen.sign_alg = 'sha256'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("with OID 1.2.840.10045.3.1.1 is unsupported")


class ECDSA_SHA256_SECP256(X509):
    """ ECDSA-SHA256-SECP256R1 is the default certificate. """

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP256R1()
        }
        self.cgen.sign_alg = 'sha256'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class ECDSA_SHA384_SECP521(X509):
    """ The curve secp521r1 isn't recommended by IANA, so it isn't supported
    by Tempesta FW.
    https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
    """

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP521R1()
        }
        self.cgen.sign_alg = 'sha384'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_cannot_start("with OID 1.3.132.0.35 is unsupported")


class InvalidHash(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.sign_alg = 'sha1' # Unsupported
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
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
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class TlsCertSelect(tester.TempestaTest):
    clients = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
            'ssl_hostname' : 'example.com'
        },
    ]

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
        'custom_cert': True
    }
    
    # This function can be redefined in subclasses to provide
    # an instance TlsHandshake() with different parameters
    def get_tls_handshake(self):
        return TlsHandshake()

    @staticmethod
    def gen_cert(host_name, alg=None):
        workdir = tf_cfg.cfg.get('General', 'workdir')
        cert_path = "%s/%s.crt" % (workdir, host_name)
        key_path = "%s/%s.key" % (workdir, host_name)
        cgen = CertGenerator(cert_path, key_path)
        if alg == 'rsa':
             cgen.key = {
                'alg': 'rsa',
                'len': 2048
            }
        cgen.generate()
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    def test_vhost_cert_selection(self):
        self.gen_cert("tempesta_ec")
        self.gen_cert("tempesta_rsa", 'rsa')
        self.gen_cert("tempesta_global", 'rsa')
        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")
        # TlsHandshake proposes EC only cipher suite and it must successfully
        # request Tempesta.
        res = self.get_tls_handshake().do_12()
        self.assertTrue(res, "Wrong handshake result: %s" % res)
        # Similarly it must fail on RSA-only vhost.
        hs = TlsHandshake()
        hs.sni = ['example.com']
        with self.assertRaises(tls.TLSProtocolError):
            hs.do_12()


class TlsCertSelectBySAN(tester.TempestaTest):
    """Subject Alternative Name certificate match to SNI."""

    tempesta = {
        'config': """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:443; }

            vhost example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }
        """,
        'custom_cert': True
    }

    @property
    def verbose(self):
        return tf_cfg.v_level() >= 3

    def test_sni_matched(self):
        """SAN certificate matches passed SNI."""
        generate_certificate(san=['example.com', '*.example.com'])
        self.start_tempesta()

        for sni in (
                'example.com',
                'a.example.com',
                'www.example.com',
                '.example.com',
                'EXAMPLE.COM',
                'A.EXAMPLE.COM',
                'A.eXaMpLe.CoM',
                '-.example.com',
                # max length, length 240 'a' will give DECODE_ERROR
                f"{'-' * 239}.example.com",
        ):
            with self.subTest(msg="Trying TLS handshake", sni=sni):
                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                # TLS 1.2 handshake completed with no exception => SNI is accepted
                hs._do_12_hs()
                self.assertTrue(x509_check_cn(hs.cert, "tempesta-tech.com"))

    def test_sni_not_matched(self):
        """SAN certificate does not match passed SNI."""
        generate_certificate(san=['example.com', '*.example.com'])
        self.start_tempesta()

        for sni in (
                'b.a.example.com',
                '..example.com',
                '@.example.com',
                '*.example.com',
                '!!!.example.com',
                '.a.example.com',
                'www.www.example.com',
                'example.com.www',
                'example.com.',
                'a-example.com',
                'a.example.comm',
                'a.example.com-',
                'a.example.com.',
                'a.example.com.example.com',
                tf_cfg.cfg.get("Server", "ip"),
                'a' * 251,  # max length, 252 will give DECODE_ERROR
        ):
            with self.subTest(msg="Trying TLS handshake with bad SNI", sni=sni):
                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                with self.assertRaisesRegex(tls.TLSProtocolError, 'UNRECOGNIZED_NAME'):
                    hs._do_12_hs()

    def test_unknown_server_name_warning(self):
        """Test that expected 'unknown server name' warning appears in DMESG logs."""
        generate_certificate(san=['example.com', '*.example.com'])
        self.start_tempesta()
        for sni in (
                "localhost",
                "a.localhost",
                "a.b.localhost",
                "a.b.c.localhost",
                "a.b.c.localhost.com",
                "a.b.c.example.com",
        ):
            with self.subTest(msg="Check 'unknown server name' warning", sni=sni):
                # restart DMESG finder, to update messages from the current time
                self.oops = self.oops.__class__()

                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                with self.assertRaisesRegex(tls.TLSProtocolError, 'UNRECOGNIZED_NAME'):
                    hs._do_12_hs()

                self.assertEqual(
                    1,
                    self.oops.warn_count(f"requested unknown server name '{sni}'"),
                    # Report all founded 'unknown server name' warnings
                    f"Warnings: {self.oops.warn_match('requested unknown server name .*')}"
                )

    def test_sni_match_after_reload(self):
        """
        Test that SAN certificate match changes after (multiple) configuration reload.
        """
        RELOAD_COUNT = 5

        def handshake(sni):
            hs = TlsHandshake(verbose=self.verbose)
            hs.sni = [sni]
            hs._do_12_hs()

        san_iter = cycle([
            ['*.example.com'],
            ['*.tempesta-tech.com'],
        ])
        sni_iter = cycle(['a.example.com', 'b.tempesta-tech.com'])

        generate_certificate(san=[])
        # ignore "Vhost %s com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        self.start_tempesta()

        for i in range(RELOAD_COUNT):
            generate_certificate(san=next(san_iter))
            self.get_tempesta().reload()

            try:
                handshake(next(sni_iter))
            except tls.TLSProtocolError:
                raise Exception(f"SNI should match to the current certificate [i={i}]")

            with self.assertRaisesRegex(
                    tls.TLSProtocolError, 'UNRECOGNIZED_NAME',
                    msg=f"SNI should not match to the current certificate [i={i}]"
            ):
                handshake(next(sni_iter))

            next(sni_iter)


class TlsCertSelectBySANwitMultipleSections(tester.TempestaTest):
    """Test that no confusion occurs between wildcard certificate
    and certificate for specific subdomain. After Tempesta reload,
    certificate selection is changed according to the current config.
    """

    tempesta = {
        'config': """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:443; }

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
        'custom_cert': True
    }

    config_no_private_section = """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:443; }

            vhost example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/wildcard.crt;
                tls_certificate_key ${general_workdir}/wildcard.key;
            }
    """

    config_only_private_section = """
            cache 0;
            listen 443 proto=https;

            srv_group sg { server ${server_ip}:443; }

            vhost private.example.com {
                proxy_pass sg;
                tls_certificate ${general_workdir}/private.crt;
                tls_certificate_key ${general_workdir}/private.key;
            }
    """

    @property
    def verbose(self):
        return tf_cfg.v_level() >= 3

    def reload_with_config(self, template: str):
        """Reconfigure Tempesta with the provided config `template`.
        """
        desc = {
            'config': template,
            'custom_cert': True
        }
        populate_properties(desc)
        config_text = fill_template(desc['config'], desc)

        config = tempesta.Config()
        config.set_defconfig(config_text, custom_cert=True)
        self.get_tempesta().config = config
        self.get_tempesta().reload()

    def test(self):
        generate_certificate(
            cert_name='wildcard',
            cn='wildcard',
            san=['example.com', '*.example.com']
        )
        generate_certificate(
            cert_name='private',
            cn='private',
            san=['example.com', 'private.example.com']
        )
        self.start_tempesta()
        # save the current config text
        original_config = self.get_tempesta().config.defconfig

        # Both 'wildcard' and 'private' certificates are provided
        for sni, expected_cert in (
                ('example.com', 'wildcard'),
                ('public.example.com', 'wildcard'),
                ('private.example.com', 'private'),
        ):
            with self.subTest(msg="Trying TLS handshake", sni=sni):
                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                hs._do_12_hs()
                self.assertTrue(x509_check_cn(hs.cert, expected_cert))

        self.reload_with_config(self.config_no_private_section)
        # After Tempesta reload, 'wildcard' certificate are provided for all subdomains
        for sni, expected_cert in (
                ('example.com', 'wildcard'),
                ('public.example.com', 'wildcard'),
                ('private.example.com', 'wildcard'),
        ):
            with self.subTest(msg="Trying TLS handshake after config reload", sni=sni):
                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                hs._do_12_hs()
                self.assertTrue(x509_check_cn(hs.cert, expected_cert))

        self.reload_with_config(self.config_only_private_section)
        # After Tempesta reload,
        # 'wildcard' certificate is provided for 'private' section,
        hs = TlsHandshake(verbose=self.verbose)
        hs.sni = ['private.example.com']
        hs._do_12_hs()
        self.assertTrue(x509_check_cn(hs.cert, 'private'))

        # and no certificate provided for removed 'wildcard' section subdomains
        for sni in 'example.com', 'public.example.com':
            with self.subTest(msg="Check 'unknown server name' warning after reload", sni=sni):
                with self.assertRaisesRegex(tls.TLSProtocolError, 'UNRECOGNIZED_NAME'):
                    hs = TlsHandshake(verbose=self.verbose)
                    hs.sni = [sni]
                    hs._do_12_hs()

        # After Tempsta reload, certificates are provided as at the beginning of the test
        self.reload_with_config(original_config)
        for sni, expected_cert in (
                ('example.com', 'wildcard'),
                ('public.example.com', 'wildcard'),
                ('private.example.com', 'private'),
        ):
            with self.subTest(
                    msg="Trying TLS handshake after second config reload",
                    sni=sni
            ):
                hs = TlsHandshake(verbose=self.verbose)
                hs.sni = [sni]
                hs._do_12_hs()
                self.assertTrue(x509_check_cn(hs.cert, expected_cert))


class TlsSNIwithHttpTable(tester.TempestaTest):
    """
    Test that show that non-TLS vhost could be accessed with certificate from
    another section.
    Test should fail after the fix.
    """

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '443',
            'ssl': True,
            'ssl_hostname': 'example.com',
        },
    ]

    backends = [
        {
            'id': 'server-1',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 8\r\n\r\n'
                'server-1'
            )
        },
        {
            'id': 'server-2',
            'type': 'deproxy',
            'port': '8001',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 8\r\n\r\n'
                'server-2'
            )
        },
        {
            'id': 'server-3',
            'type': 'deproxy',
            'port': '8002',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 8\r\n\r\n'
                'server-3'
            )
        },
    ]

    tempesta = {
        'config': """
            cache 0;
            listen 443 proto=https;

            srv_group sg1 { server ${server_ip}:8000; }
            srv_group sg2 { server ${server_ip}:8001; }
            srv_group sg3 { server ${server_ip}:8002; }

            vhost example.com {
                proxy_pass sg1;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
            }

            vhost localhost-vhost {
                proxy_pass sg2;
            }

            vhost default-vhost {
                proxy_pass sg3;
            }

            http_chain {
              host == "localhost" -> localhost-vhost;
              -> default-vhost;
            }
        """,
        'custom_cert': True
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def make_request(self, host: str) -> str:
        """Make request with the specified `host` header and
        return the body of response."""
        client = self.get_client('deproxy')
        client.make_request(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertTrue(res, 'Cannot process request')
        status = client.last_response.status
        self.assertEqual(status, '200', f'Bad response status: {status}')
        return client.last_response.body

    def test_with_san(self):
        """
        CN: random()
        SAN: [example.com]
        SNI: example.com
        HOST: localhost
        """
        generate_certificate(cn='random-name', san=['example.com'])
        self.start_all()
        self.assertEqual(self.make_request('localhost'), 'server-2')

    def test_with_common_name(self):
        """
        CN: example.com
        SAN: []
        SNI: example.com
        HOST: localhost
        """
        generate_certificate(cn='example.com', san=None)
        self.start_all()
        self.assertEqual(self.make_request('localhost'), 'server-2')

    def test_with_any_host(self):
        """
        CN: random()
        SAN: []
        SNI: example.com
        HOST: random()
        """
        # ignore "Vhost example.com doesn't have certificate with matching SAN/CN"
        self.oops_ignore = ["WARNING"]
        generate_certificate(cn='random-name', san=None)
        self.start_all()
        self.assertEqual(self.make_request('another-random-name'), 'server-3')


class BaseTlsMulti(ABC):
    """Base class to test multiplexed (pipelided) requests."""

    backends = [
        {
            'id': 'server-1',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Server: server-1\r\n'
                'Date: test\r\n'
                'Content-Length: 8\r\n\r\n'
                'server-1'
            ),
        },
        {
            'id': 'server-2',
            'type': 'deproxy',
            'port': '8001',
            'response': 'static',
            'response_content': (
                'HTTP/1.1 200 OK\r\n'
                'Server: server-2\r\n'
                'Date: test\r\n'
                'Content-Length: 8\r\n\r\n'
                'server-2'
            ),
        },
    ]

    tempesta_tmpl = """
            cache 0;
            listen 443 proto=%s;

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

    @abstractmethod
    def build_requests(self, hosts: list[str]):
        pass

    def setUp(self):
        self.tempesta = {
            'config': self.tempesta_tmpl % (self.proto),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def start_all(self):
        generate_certificate(san=['example.com', '*.example.com'])
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def run_alterative_access(self):
        """Try to access multiple hosts in alterating order."""
        REQ_NUM = 4
        self.assertFalse(REQ_NUM % 2, "REQ_NUM should be even")
        host_iter = cycle(['a.example.com', 'localhost'])

        self.start_all()

        client = self.get_client('deproxy')
        server1 = self.get_server("server-1")
        server2 = self.get_server("server-2")

        client.make_requests(
            self.build_requests(
                hosts=islice(host_iter, REQ_NUM)
            )
        )
        client.wait_for_response(timeout=60)

        self.assertEqual(REQ_NUM, len(client.responses))
        # Half of responses are from server1,
        self.assertEqual(REQ_NUM / 2, len(server1.requests))
        # and half from server2
        self.assertEqual(REQ_NUM / 2, len(server2.requests))


class TlsSNIwithHttpTableMulti(BaseTlsMulti, tester.TempestaTest):

    proto = "https"

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '443',
            'ssl': True,
            'ssl_hostname': 'a.example.com',
        },
    ]

    def build_requests(self, hosts):

        def build_request(host):
            return (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "\r\n"
            )

        return "\r\n".join(
            [build_request(host) for host in hosts]
        )

    def test_alternating_access(self):
        """
        Test for HTTP1 pipelined request: both 'example.com' and 'localhost'
        vhosts are accessed in alternating order.
        """
        self.run_alterative_access()


class TlsSNIwithHttpTableMultiH2(BaseTlsMulti, tester.TempestaTest):

    proto = "h2"

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy_h2',
            'addr': "${tempesta_ip}",
            'port': '443',
            'ssl': True,
            'ssl_hostname': 'example.com'
        },
    ]

    def build_requests(self, hosts):

        def build_request(host):
            return [
                (':authority', host),
                (':path', '/'),
                (':scheme', 'https'),
                (':method', 'GET')
            ]

        return [build_request(host) for host in hosts]

    def test_alternating_access(self):
        """
        Test for HTTP1 pipelined request: both 'example.com' and 'localhost'
        vhosts are accessed in alternating order.
        """
        # Ignore 'BUG tfw_stream_cache Tainted'
        self.oops_ignore = ["WARNING"]
        self.run_alterative_access()
