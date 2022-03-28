"""
Tests for basic x509 handling: certificate loading and getting a valid request
and response, stale certificates and certificates with unsupported algorithms.
"""
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec

from helpers import dmesg, remote, tf_cfg
from helpers.error import Error
from framework import tester
from framework.x509 import CertGenerator
from .handshake import TlsHandshake
from .scapy_ssl_tls import ssl_tls as tls

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


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
