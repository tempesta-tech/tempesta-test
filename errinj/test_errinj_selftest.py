"""Error injectiom self test"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from subprocess import PIPE, Popen


class ErrinjSelf(tester.TempestaTest):
    def test_errinj_self_test(self):
        self.start_tempesta()

        # Error injetion wasn't set, result = NONE
        command = "sysctl net.tempesta.errinj"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"net.tempesta.errinj = NONE\n")
        self.assertEqual(stderr, b"")

        # Unknown error injetion cause error
        command = "sysctl -w net.tempesta.errinj=UNKNOWN_ERROR_INJECTION"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"")
        self.assertIn(b'sysctl: setting key "net.tempesta.errinj"', stderr)

        # Error injection should be passed as "name=val"
        command = "sysctl -w net.tempesta.errinj=ERRINJ_SELF_TEST"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"")
        self.assertIn(b'sysctl: setting key "net.tempesta.errinj"', stderr)

        # Pass invalid value for boolean error injection
        command = "sysctl -w net.tempesta.errinj=ERRINJ_SELF_TEST=xxx"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"")
        self.assertIn(b'sysctl: setting key "net.tempesta.errinj"', stderr)

        # Check correct selftest for boolean error injection
        command = "sysctl -w net.tempesta.errinj=ERRINJ_SELF_TEST=1"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"net.tempesta.errinj = ERRINJ_SELF_TEST=1\n")
        self.assertEqual(stderr, b"")

        # Check read of previously set error injection
        command = "sysctl net.tempesta.errinj"
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(stdout, b"net.tempesta.errinj = ERRINJ_SELF_TEST=true\n")
        self.assertEqual(stderr, b"")
