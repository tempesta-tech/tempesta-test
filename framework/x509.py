"""
X509 certificates generation required to test handling of different cipher
suites anomalies on Tempesta TLS side. We didn't modify mbedTLS x509 related
code, so now we're not interested with x509 parsing at all, so we do not play
with different x509 formats, extensions and so on.

Without loss of generality we use self-signed certificates to make things simple
in tests.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from helpers import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class CertGenerator:

    def __init__(self, cert_path=None, key_path=None, default=False):
        workdir = tf_cfg.cfg.get('General', 'workdir')
        self.f_cert = cert_path if cert_path else workdir + "/tempesta.crt"
        self.f_key = key_path if key_path else workdir + "/tempesta.key"
        # Define the certificate fields data supposed for mutation by a caller.
        self.C = u'US'
        self.ST = u'Washington'
        self.L = u'Seattle'
        self.O = u'Tempesta Technologies Inc.'
        self.OU = u'Testing'
        self.CN = u'tempesta-tech.com'
        self.emailAddress = u'info@tempesta-tech.com'
        self.not_valid_before = datetime.now() - timedelta(1)
        self.not_valid_after = datetime.now() + timedelta(365)
        # Use EC by defauls as the fastest and more widespread.
        self.key = {
            'alg': 'ecdsa',
            'curve': ec.SECP256R1()
        }
        self.sign_alg = 'sha256'
        self.format = 'pem'
        self.cert = None
        self.pkey = None
        if default:
            self.generate()

    @staticmethod
    def __write(path, data):
        fdesc = open(path, "wt")
        fdesc.write(data)
        fdesc.close()

    def __encoding(self):
        if self.format == 'pem':
            return serialization.Encoding.PEM
        else:
            raise NotImplementedError("Not implemented encoding: %s"
                                      % self.format)

    def __build_name(self):
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.C),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.ST),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.L),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.O),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.OU),
            x509.NameAttribute(NameOID.COMMON_NAME, self.CN),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.emailAddress),
        ])

    def __gen_key_pair(self):
        if self.key['alg'] == 'rsa':
            assert self.key['len'], "No RSA key length specified"
            self.pkey = rsa.generate_private_key(65537, self.key['len'],
                                                 default_backend())
        elif self.key['alg'] == 'ecdsa':
            assert self.key['curve'], "No EC curve specified"
            self.pkey = ec.generate_private_key(self.key['curve'],
                                                default_backend())
        else:
            raise NotImplementedError("Not implemented key algorithm: %s"
                                      % self.key_alg)

    def __hash(self):
        if self.sign_alg == 'sha1':
            return hashes.SHA1()
        elif self.sign_alg == 'sha256':
            return hashes.SHA256()
        elif self.sign_alg == 'sha384':
            return hashes.SHA384()
        elif self.sign_alg == 'sha512':
            return hashes.SHA512()
        else:
            raise NotImplementedError("Not implemented hash algorithm: %s"
                                      % self.sign_alg)

    def serialize_cert(self):
        return self.cert.public_bytes(self.__encoding())

    def serialize_priv_key(self):
        return self.pkey.private_bytes(self.__encoding(),
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())

    def generate(self):
        self.__gen_key_pair()
        x509name = self.__build_name()
        builder = x509.CertificateBuilder().serial_number(
            x509.random_serial_number()
        ).subject_name(
            x509name
        ).issuer_name(
            x509name
        ).not_valid_before(
            self.not_valid_before
        ).not_valid_after(
            self.not_valid_after
        ).public_key(
            self.pkey.public_key()
        )
        self.cert = builder.sign(self.pkey, self.__hash(), default_backend())
        # Write the certificate & private key.
        self.__write(self.f_cert, self.serialize_cert())
        self.__write(self.f_key, self.serialize_priv_key())

    def __str__(self):
        assert self.cert, "Stringify null x509 certificate object"
        return str(self.cert)

    def get_file_paths(self):
        return (self.f_cert, self.f_key)
