"""
The purpose of this layer is providing set of asserts, that can be reused.
It's expected that all repeated asserting code will move here eventually.
"""

from helpers.analyzer import FIN, RST, TCP

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Sniffer:
    def _get_dport_from_sock(self, s):
        if hasattr(s, "socket"):
            s = s.socket
        if isinstance(s, int):
            return s
        return s.getsockname()[1]

    def _get_dports(self, socks: list) -> set:
        """Call after client started to save sockets for 'assert_unreset_socks'"""
        return set(filter(None, map(self._get_dport_from_sock, socks)))

    def save_must_reset_socks(self, socks: list):
        self.must_rst_dports = self._get_dports(socks)

    def save_must_not_reset_socks(self, socks: list):
        self.must_not_rst_dports = self._get_dports(socks)

    def save_must_fin_socks(self, socks: list):
        self.must_fin_dports = self._get_dports(socks)

    def save_must_not_fin_socks(self, socks: list):
        self.must_not_fin_dports = self._get_dports(socks)

    def assert_reset_socks(self, packets):
        assert hasattr(self, "must_rst_dports"), "save_must_rst_dports must be called before"
        rst_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        self.assertTrue(
            self.must_rst_dports.issubset(rst_packet_dports),
            f"Ports must be reset: {self.must_rst_dports}, "
            f"but the actual state is: {rst_packet_dports}",
        )

    def assert_unreset_socks(self, packets):
        assert hasattr(
            self, "must_not_rst_dports"
        ), "save_must_not_rst_dports must be called before"
        rst_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        self.assertFalse(
            rst_packet_dports.intersection(self.must_not_rst_dports),
            f"Ports mustn't be reset: {self.must_not_rst_dports}, "
            f"but the actual state is: {rst_packet_dports}",
        )

    def assert_fin_socks(self, packets):
        assert hasattr(self, "must_fin_dports"), "save_must_fin_dports must be called before"
        fin_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & FIN}
        self.assertTrue(
            self.must_fin_dports.issubset(fin_packet_dports),
            f"Ports must be closed via FIN: {self.must_fin_dports}, "
            f"but the actual state is: {fin_packet_dports}",
        )

    def assert_not_fin_socks(self, packets):
        assert hasattr(
            self, "must_not_fin_dports"
        ), "save_must_not_fin_dports must be called before"
        fin_packet_dports = {p[TCP].dport for p in packets if p[TCP].flags & FIN}
        self.assertFalse(
            fin_packet_dports.intersection(self.must_not_fin_dports),
            f"Ports mustn't be closed via FIN: {self.must_not_fin_dports}, "
            f"but the actual state is: {fin_packet_dports}",
        )
