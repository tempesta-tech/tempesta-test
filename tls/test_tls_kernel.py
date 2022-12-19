"""
Tests for the Tempesta Linux kernel TLS-related routines.
"""
import re

from framework import tester
from helpers import remote

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TCrypt(tester.TempestaTest):
    """
    Use tcrypt kernel module to test the Linux crypto algorithms.
    Update/reopen https://github.com/tempesta-tech/tempesta/issues/1340 if
    the test fails.
    At the moment Tempesta TLS uses gcm(aes), ccm(aes), hmac(sha256),
    hmac(sha384), and hmac(sha512) - modes 35, 37, 102, 103, and 104
    correspondingly (see linux/crypto/tcrypt.c), so test only these algorithms.
    """

    def test_tcrypt(self):
        try:
            remote.tempesta.run_cmd(
                "for m in 35 37 102 103 104;" " do modprobe tcrypt mode=$m;" "done"
            )
        except Exception as e:
            # modprobe tcrypt always returns non-zero status code.
            # -EAGAIN return code is the successful return code of the module.
            m = re.findall("Resource temporarily unavailable", e.stderr.decode())
            self.assertEqual(len(m), 5)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
