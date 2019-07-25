"""
Tests for basic x509 handling: certificate loading and getting a valid request
and response, stale certificates and certificates with unsupported algorithms.
ECDSA-SHA256-SECP256R1 is the default certificate, so do not test it.
"""
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec

from helpers import dmesg, remote, tf_cfg
from helpers.error import Error
from framework import tester
from framework.x509 import CertGenerator

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
        tls_fallback_default allow_any;
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
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key())
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=self.TIMEOUT),
                        "Cannot start Tempesta")

        self.start_all_clients()
        client = self.get_client('deproxy')
        client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, '200', "Bad response status: %s" % status)

    def check_bad_alg(self, msg):
        """
        Tempesta normally loads a certificate, but fails on TLS handshake.
        """
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()

        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key())
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=X509.TIMEOUT),
                        "Cannot start Tempesta")

        # Collect warnings before start w/ a bad certificate.
        warns = dmesg.count_warnings(msg)
        self.start_all_clients()
        client = self.get_client('deproxy')
        client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        res = client.wait_for_response(timeout=X509.TIMEOUT)
        self.assertFalse(res, "Erroneously established connection")
        self.assertEqual(dmesg.count_warnings(msg), warns + 1,
                         "Tempesta doesn't throw warning on bad certificate")

    def check_cannot_start(self, msg):
        """
        The test must implement tearDown() to avoid the framework complains
        about error messages.
        """
        # We have to copy the certificate and key on our own.
        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key())
        self.start_tempesta()
        self.assertGreater(dmesg.count_warnings(msg), 0,
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
        self.check_bad_alg("Warning: Unrecognized TLS receive return code")


class ECDSA_SHA256_SECP192(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP192R1() # Unsupported curve
        }
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_bad_alg("Warning: None of the common ciphersuites is usable")


class ECDSA_SHA512_SECP384(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP384R1() # Unsupported curve
        }
        self.cgen.sign_alg = 'sha512'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_bad_alg("Warning: None of the common ciphersuites is usable")


class ECDSA_SHA384_SECP521(X509):

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP521R1() # Unsupported curve
        }
        self.cgen.sign_alg = 'sha384'
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_bad_alg("Warning: None of the common ciphersuites is usable")


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
        # TODO #1294: Tempesta throws misleading ERROR report on invalid
        # tls_certificate configuration, just the same as if there is no
        # certificate file at all, instead of correctly report about
        # not supported SHA1.
        self.check_cannot_start("ERROR: configuration parsing error")

    def tearDown(self):
        self.deproxy_manager.stop()
        # We do care only about Oopses, not about warnings or errors.
        self.oops.update()
        if self.oops.warn_count("Oops") > 0:
            raise Error("Oopses happened during test on Tempesta")


class StaleCert(X509):
    """
    We do allow to load stale certificates and just use them - that's not our
    business to limit a user which certificates to use. In general this is a job
    for tools like certbot. Probably, we should print a warning about stale
    certificates.
    """
    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.not_valid_before = datetime.now() - timedelta(365)
        # Very small overdue as of 30 seconds.
        self.cgen.not_valid_after = datetime.now() - timedelta(0, 30)
        self.cgen.generate()
        self.tempesta = {
            'config' : X509.tempesta_tmpl % self.cgen.get_file_paths(),
            'custom_cert': True
        }
        tester.TempestaTest.setUp(self)

    def test(self):
        self.check_good_cert()


class TlsDuplicateCerts(tester.TempestaTest):
    clients = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
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

            vhost tempesta-tech.com {
                proxy_pass be1;
                tls_certificate ${general_workdir}/tempesta.crt;
                tls_certificate_key ${general_workdir}/tempesta.key;
                tls_certificate ${general_workdir}/tempesta_dup.crt;
                tls_certificate_key ${general_workdir}/tempesta_dup.key;
            }

            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
            }
        """,
        'custom_cert': True
    }

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
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key())

    def test_duplicate(self):
        self.gen_cert("tempesta")
        self.gen_cert("tempesta2")

        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")
        msg = "Warning: Unrecognized TLS receive return code"
        warns = dmesg.count_warnings(msg)
        self.start_all_clients()
        client = self.get_client('0')
        client.make_request('GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n')
        res = client.wait_for_response(timeout=1)
        self.assertFalse(res, "Erroneously established connection")
        self.assertEqual(dmesg.count_warnings(msg), warns + 1,
                         "No warning about duplicate certificates")

    def test_2_diff_certs(self):
        self.gen_cert("tempesta")
        self.gen_cert("tempesta2", 'rsa')

        deproxy_srv = self.get_server('0')
        deproxy_srv.start()
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "Cannot start Tempesta")

        self.start_all_clients()
        client = self.get_client('0')
        client.make_request('GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n')
        res = client.wait_for_response(timeout=1)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, '200', "Bad response status: %s" % status)
