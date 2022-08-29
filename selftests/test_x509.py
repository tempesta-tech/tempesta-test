import subprocess
import unittest
from pathlib import Path

from framework.x509 import CertGenerator

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TestX509CertGenerator(unittest.TestCase):

    @property
    def cert_text(self) -> str:
        """openssl text dump of the certificate."""
        return subprocess.check_output([
            'openssl', 'x509', '-text', '-noout', '-in',
            self.cgen.get_file_paths()[0]
        ], text=True)

    def setUp(self):
        self.cgen = CertGenerator()
        self.remove_certs()

    def tearDown(self):
        self.remove_certs()

    def remove_certs(self):
        for path in self.cgen.get_file_paths():
            Path(path).unlink(missing_ok=True)

    def test_no_san_extentsion_in_cert_by_default(self):
        self.cgen.generate()
        self.assertNotIn('Subject Alternative Name', self.cert_text)

    def test_san_extension_in_cert(self):
        self.cgen.san = ['node1.tempesta-tech.com', 'node2.tempesta-tech.com']

        self.cgen.generate()

        cert_text = self.cert_text
        self.assertIn('Subject Alternative Name', cert_text)
        self.assertIn('DNS:node1.tempesta-tech.com, DNS:node2.tempesta-tech.com', cert_text)
