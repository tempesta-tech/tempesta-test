"""Composable, reusable additional functionality for `framework.tester.TempestaTest` subclasses."""

from helpers import remote
from helpers.tf_cfg import test_logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NetfilterMarkMixin:
    """Mixin to set Netfilter mark."""

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self._nf_mark = None
        super().setUp()
        self.addCleanup(self.cleanup_del_nf_mark)

    def cleanup_del_nf_mark(self):
        if self._nf_mark:
            self.del_nf_mark(self._nf_mark)

    def set_nf_mark(self, mark):
        cmd = "iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark %s" % mark
        test_logger.info(f"Set Netfilter mark: {mark}")
        remote.tempesta.run_cmd(cmd, timeout=30)
        self._nf_mark = mark

    def del_nf_mark(self, mark):
        cmd = "iptables -t mangle -D PREROUTING -p tcp -j MARK --set-mark %s" % mark
        test_logger.info(f"Delete Netfilter mark: {mark}")
        remote.tempesta.run_cmd(cmd, timeout=30)
        self._nf_mark = None
