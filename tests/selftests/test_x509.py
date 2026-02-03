import unittest

from framework.helpers.cert_generator_x509 import CertGenerator

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestX509CertGenerator(unittest.TestCase):
    @property
    def cert_text(self) -> str:
        """openssl text dump of the certificate."""
        return self.cgen._node.run_cmd(
            f"openssl x509 -text -noout -in {self.cgen.get_file_paths()[0]}"
        )[0].decode()

    def setUp(self):
        self.cgen = CertGenerator()
        self.remove_certs()  # initial certs cleanup before testing
        self.addCleanup(self.remove_certs)

    def remove_certs(self):
        for path in self.cgen.get_file_paths():
            self.cgen._node.remove_file(path)

    def test_no_san_extentsion_in_cert_by_default(self):
        self.cgen.generate()
        self.assertNotIn("Subject Alternative Name", self.cert_text)

    def test_san_extension_in_cert(self):
        self.cgen.san = ["node1.tempesta-tech.com", "node2.tempesta-tech.com"]

        self.cgen.generate()

        cert_text = self.cert_text
        self.assertIn("Subject Alternative Name", cert_text)
        self.assertIn("DNS:node1.tempesta-tech.com, DNS:node2.tempesta-tech.com", cert_text)
