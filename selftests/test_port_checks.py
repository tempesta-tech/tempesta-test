import unittest

from framework.port_checks import FreePortsChecker

ESTABLISHED_9005 = b"""
192.168.1.1:22
192.168.1.1:22
192.168.1.1:9005
192.168.1.1:22
"""

ESTABLISHED_9005_9006 = b"""
192.168.1.1:22
[::ffff:192.168.1.1]:9006
192.168.1.1:22
[::ffff:192.168.1.1]:9006
192.168.1.1:22
192.168.1.1:9005
"""


class TestFreePortsChecker(unittest.TestCase):
    @unittest.mock.patch("framework.port_checks.remote.tempesta")
    def test_check_ports_established(self, tempesta):
        for ss, ports, expected in (
            [b"", ["9005"], False],
            [b"", [], True],
            [ESTABLISHED_9005, [], True],
            [ESTABLISHED_9005, ["9005"], True],
            [ESTABLISHED_9005, ["9006"], False],
            [ESTABLISHED_9005, ["9005", "9006"], False],
            [ESTABLISHED_9005_9006, ["9005"], True],
            [ESTABLISHED_9005_9006, ["9006"], True],
            [ESTABLISHED_9005_9006, ["9005", "9006"], True],
        ):
            with self.subTest(msg="Check established", ss=ss, ports=ports, expected=expected):
                checker = FreePortsChecker()
                checker.port_checks = ports
                tempesta.run_cmd.return_value = ss, None
                self.assertEqual(
                    checker.check_ports_established(ip="192.168.1.1", ports=ports), expected
                )
