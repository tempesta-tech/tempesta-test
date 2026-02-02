"""
The purpose of this layer is providing set of asserts, that can be reused.
It's expected that all repeated asserting code will move here eventually.
"""

from scapy.packet import Packet

from framework.deproxy_client import BaseDeproxyClient
from helpers.analyzer import FIN, RST, TCP

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Sniffer:
    @staticmethod
    def _get_src_ports_from_deproxy_clients(clients: list[BaseDeproxyClient]) -> set[int]:
        """Call after client started to save sockets for 'assert_unreset_socks'"""
        return {client.src_port for client in clients}

    def assert_reset_socks(self, packets: list[Packet], clients: list[BaseDeproxyClient]) -> None:
        rst_src_ports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        must_rst_src_ports = self._get_src_ports_from_deproxy_clients(clients)
        assert must_rst_src_ports.issubset(rst_src_ports), (
            f"Ports must be reset: {must_rst_src_ports}, "
            f"but the actual state is: {rst_src_ports}",
        )

    def assert_unreset_socks(self, packets: list[Packet], clients: list[BaseDeproxyClient]) -> None:
        rst_packet_src_ports = {p[TCP].dport for p in packets if p[TCP].flags & RST}
        must_not_rst_src_ports = self._get_src_ports_from_deproxy_clients(clients)
        assert not must_not_rst_src_ports.issubset(rst_packet_src_ports), (
            f"Ports mustn't be reset: {must_not_rst_src_ports}, "
            f"but the actual state is: {rst_packet_src_ports}",
        )

    def assert_fin_socks(self, packets: list[Packet], clients: list[BaseDeproxyClient]) -> None:
        fin_packet_src_ports = {p[TCP].dport for p in packets if p[TCP].flags & FIN}
        must_fin_src_ports = self._get_src_ports_from_deproxy_clients(clients)
        assert must_fin_src_ports.issubset(fin_packet_src_ports), (
            f"Ports must be closed via FIN: {must_fin_src_ports}, "
            f"but the actual state is: {fin_packet_src_ports}",
        )

    def assert_not_fin_socks(self, packets: list[Packet], clients: list[BaseDeproxyClient]) -> None:
        fin_packet_src_ports = {p[TCP].dport for p in packets if p[TCP].flags & FIN}
        must_not_fin_src_ports = self._get_src_ports_from_deproxy_clients(clients)
        assert not must_not_fin_src_ports.issubset(fin_packet_src_ports), (
            f"Ports mustn't be closed via FIN: {must_not_fin_src_ports}, "
            f"but the actual state is: {fin_packet_src_ports}",
        )
