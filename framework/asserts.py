"""
The purpose of this layer is providing set of asserts, that can be reused.
It's expected that all repeated asserting code will move here eventually.
"""

from helpers.analyzer import RST, TCP

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Sniffer:
    def _get_dport_from_sock(self, s):
        if hasattr(s, "socket"):
            s = s.socket
        if isinstance(s, int):
            return s
        try:
            return s.getsockname()[1]
        except:
            # Just skip the port if the socket isn't ready.
            # It's stupid, but prevents us from falls.
            return None

    def save_must_reset_socks(self, *socks):
        self.must_rst_dports = set(filter(None, map(self._get_dport_from_sock, socks)))

    def save_must_not_reset_socks(self, *socks):
        self.must_not_rst_dports = set(filter(None, map(self._get_dport_from_sock, socks)))

    def assert_reset_socks(self, packets):
        rst_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        self.assertTrue(
            self.must_rst_dports.issubset(rst_packet_dports),
            f"Ports must be reset: {self.must_rst_dports}, but the actual state is: {rst_packet_dports}",
        )

    def assert_unreset_socks(self, packets):
        rst_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        self.assertFalse(
            rst_packet_dports.intersection(self.must_not_rst_dports),
            f"Ports mustn't be reset: {self.must_not_rst_dports}, but the actual state is: {rst_packet_dports}",
        )
