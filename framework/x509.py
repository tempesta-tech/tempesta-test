"""
X509 certificates generator.

X509 certificates generation required to test handling of different cipher
suites anomalies on Tempesta TLS side. We didn't modify mbedTLS x509 related
code, so now we're not interested with x509 parsing at all, so we do not play
with different x509 formats, extensions and so on.

Without loss of generality we use self-signed certificates
to make things simple in tests.
"""
from datetime import datetime, timedelta
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from helpers import remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


class CertGenerator(object):
    def __init__(
        self,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        default: bool = False,
    ):
        workdir = tf_cfg.cfg.get("General", "workdir")
        self.f_cert = cert_path if cert_path else workdir + "/tempesta.crt"
        self.f_key = key_path if key_path else workdir + "/tempesta.key"
        # Create directories if don't exist
        dirs = [
            workdir,
            # Get only directory from full path
            "/".join(self.f_cert.split("/")[:-1]),
            "/".join(self.f_key.split("/")[:-1]),
        ]
        for dir_ in dirs:
            # We must create dir on host node because we cannot run this class on another node
            remote.host.mkdir(dir_)
        # Define the certificate fields data supposed for mutation by a caller.
        self.C = "US"
        self.ST = "Washington"
        self.L = "Seattle"
        self.O = "Tempesta Technologies Inc."
        self.OU = "Testing"
        self.CN = "tempesta-tech.com"
        self.emailAddress = "info@tempesta-tech.com"
        self.not_valid_before = datetime.now() - timedelta(1)
        self.not_valid_after = datetime.now() + timedelta(365)
        # Use EC by defaults as the fastest and more widespread.
        self.key = {
            "alg": "ecdsa",
            "curve": ec.SECP256R1(),
        }
        self.sign_alg = "sha256"
        self.format = "pem"
        self.cert = None
        self.pkey = None
        # Subject Alternative Name field: list of additional host names
        self.san = []
        if default:
            self.generate()

    @staticmethod
    def __write(path, data):
        with open(path, "wt") as fdesc:
            fdesc.write(data.decode())

    def __encoding(self):
        if self.format == "pem":
            return serialization.Encoding.PEM
        raise NotImplementedError(
            "Not implemented encoding: {0}".format(self.format),
        )

    def __build_name(self):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.C),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.ST),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.L),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.O),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.OU),
                x509.NameAttribute(NameOID.COMMON_NAME, self.CN),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.emailAddress),
            ]
        )

    def __gen_key_pair(self):
        if self.key["alg"] == "rsa":
            assert self.key["len"], "No RSA key length specified"
            self.pkey = rsa.generate_private_key(
                65537,
                self.key["len"],
                default_backend(),
            )

        elif self.key["alg"] == "ecdsa":
            assert self.key["curve"], "No EC curve specified"
            self.pkey = ec.generate_private_key(
                self.key["curve"],
                default_backend(),
            )

        else:
            raise NotImplementedError(
                "Not implemented key algorithm: {0}".format(self.key_alg),
            )

    def __hash(self):
        if self.sign_alg == "sha1":
            return hashes.SHA1()
        elif self.sign_alg == "sha256":
            return hashes.SHA256()
        elif self.sign_alg == "sha384":
            return hashes.SHA384()
        elif self.sign_alg == "sha512":
            return hashes.SHA512()
        raise NotImplementedError(
            "Not implemented hash algorithm: {0}".format(self.sign_alg),
        )

    def serialize_cert(self):
        return self.cert.public_bytes(
            self.__encoding(),
        )

    def serialize_priv_key(self):
        return self.pkey.private_bytes(
            self.__encoding(),
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def generate(self):
        self.__gen_key_pair()
        x509name = self.__build_name()
        builder = (
            x509.CertificateBuilder()
            .serial_number(
                x509.random_serial_number(),
            )
            .subject_name(
                x509name,
            )
            .issuer_name(
                x509name,
            )
            .not_valid_before(
                self.not_valid_before,
            )
            .not_valid_after(
                self.not_valid_after,
            )
            .public_key(
                self.pkey.public_key(),
            )
        )
        if self.san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(name) for name in self.san],
                ),
                critical=False,
            )
        self.cert = builder.sign(
            self.pkey,
            self.__hash(),
            default_backend(),
        )
        # Write the certificate & private key.
        self.__write(
            self.f_cert,
            self.serialize_cert(),
        )
        self.__write(
            self.f_key,
            self.serialize_priv_key(),
        )

    def __str__(self):
        assert self.cert, "Stringify null x509 certificate object"
        return str(self.cert)

    def get_file_paths(self):
        return self.f_cert, self.f_key
