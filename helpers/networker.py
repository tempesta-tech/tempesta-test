""" Helpers to control different network adapter settings. """
import re
import socket
import struct

from contextlib import contextmanager
from typing import Generator, Any

from helpers import remote, tf_cfg
from helpers.tf_cfg import test_logger


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NetWorker:

    def __init__(self, node: remote.ANode):
        self._state_dict = {True: "on", False: "off", "on": True, "off": False}
        self._tcp_options = dict()

        self._node: remote.ANode = node
        self._dst_node = self._get_dst_node()

        self._gateway_ip = tf_cfg.cfg.get(self._node.type, "ip")
        self._interface_name = tf_cfg.cfg.get("Server", "aliases_interface")
        self._base_interface_ip = tf_cfg.cfg.get("Server", "aliases_base_ip")
        self._interface: str = self._route_dst_ip(ip=self._get_dst_ipv4())
        self._prev_ipv6_addresses: list[str] = self._get_ipv6_addresses()
        self._prev_mtu: int = self._get_mtu()
        self._prev_mtu_expires: int = self._get_mtu_expires()
        self._prev_ip_no_pmtu_disc: int = self._get_ip_no_pmtu_disc()
        self._prev_tso: bool = self._get_state(what="tcp-segmentation-offload")
        self._prev_gro: bool = self._get_state(what="generic-receive-offload")
        self._prev_gso: bool = self._get_state(what="generic-segmentation-offload")

    @staticmethod
    def _check_ssh_ip_addr(ip: str) -> bool:
        """
        We must not remove Tempesta and server IPs because it's break the ssh connection
        """
        return ip not in [tf_cfg.cfg.get("Tempesta", "ip"), tf_cfg.cfg.get("Server", "ip")]

    @staticmethod
    def ip_str_to_number(ip_addr) -> int:
        """Convert ip to number"""
        return struct.unpack("!L", socket.inet_aton(ip_addr))[0]

    @staticmethod
    def ip_number_to_str(ip_addr) -> str:
        """Convert ip in numeric form to string"""
        return socket.inet_ntoa(struct.pack("!L", ip_addr))

    def _get_dst_node(self) -> remote.ANode:
        node_dict = {remote.LocalNode: remote.tempesta, remote.RemoteNode: remote.server}
        return node_dict.get(type(self._node))

    def _route_dst_ip(self, ip: str) -> str:
        """Determine outgoing interface for the IP."""
        return self._node.run_cmd(f"LANG=C ip route get to {ip} | grep -o 'dev [a-zA-Z0-9_-]*'")[0].split()[1].decode()

    def _get_mtu(self) -> int:
        return int(self._node.run_cmd(f"LANG=C ip addr show {self._interface} |grep -o 'mtu [0-9]*'")[0].split()[1])

    def _change_mtu(self, mtu: int) -> int:
        """Change the device MTU and return previous MTU."""
        prev_mtu = self._get_mtu()
        self._node.run_cmd(f"LANG=C ip link set {self._interface} mtu {mtu}")
        return int(prev_mtu)

    def _get_ip_no_pmtu_disc(self) -> int:
        return int(self._node.run_cmd("sysctl --values net.ipv4.ip_no_pmtu_disc")[0])

    def _set_ip_no_pmtu_disc(self, ip_no_pmtu_disc: int) -> None:
        self._node.run_cmd(f"sysctl -w net.ipv4.ip_no_pmtu_disc={ip_no_pmtu_disc}")

    def _get_mtu_expires(self) -> int:
        return int(self._node.run_cmd("sysctl --values net.ipv4.route.mtu_expires")[0])

    def _set_mtu_expires(self, expires: int) -> None:
        self._node.run_cmd(f"sysctl -w net.ipv4.route.mtu_expires={expires}")

    def _get_ipv6_addresses(self) -> list[str]:
        pattern = re.compile(r'inet6\s+([a-fA-F0-9:]+/\d+)')
        stdout, _ = self._node.run_cmd(f"ip -6 addr show dev {self._interface}")

        ipv6_addresses = []

        for line in stdout.decode().splitlines():
            match = pattern.search(line)
            if match:
                ipv6_addresses.append(match.group(1))
        return ipv6_addresses

    def _restore_ipv6_addresses(self) -> None:
        cur_ipv6_addresses = self._get_ipv6_addresses()
        for addr in self._prev_ipv6_addresses:
            if addr not in cur_ipv6_addresses:
                self._node.run_cmd(f"ip -6 addr add {addr} dev {self._interface}")

    def _get_state(self, what: str) -> bool:
        out = self._node.run_cmd(f"ethtool --show-features {self._interface} | grep {what}")
        return self._state_dict.get(out[0].decode("utf-8").split(" ")[-1].strip("\n"))

    def _set_state(self, what: str, on: bool) -> None:
        self._node.run_cmd(f"ethtool -K {self._interface} {what} {self._state_dict.get(on)}")

    def _get_dst_ipv4(self) -> str:
        """
        We only have two dst IPs:
            - Client/Server IP is dst IP for Tempesta FW;
            - Tempesta FW IP is dst IP for Client, Server;
        """
        if isinstance(self._node, remote.LocalNode):
            return tf_cfg.cfg.get("Tempesta", "ip")
        else:
            return tf_cfg.cfg.get("Client", "ip")

    def change_mtu(self, mtu: int, disable_pmtu: bool) -> None:
        self._change_mtu(mtu=mtu)
        self._set_mtu_expires(0)
        if disable_pmtu:
            self._set_ip_no_pmtu_disc(1)

    def restore_interface_settings(self) -> None:
        self._change_mtu(mtu=self._prev_mtu)
        self._set_mtu_expires(self._prev_mtu_expires)
        self._set_ip_no_pmtu_disc(self._prev_ip_no_pmtu_disc)
        self._restore_ipv6_addresses()

    def change_tso_gro_gso(self, on: bool) -> None:
        self._set_state("tso", on)
        self._set_state("gro", on)
        self._set_state("gso", on)

    def restore_tso_gro_gso(self) -> None:
        self._set_state("tso", self._prev_tso)
        self._set_state("gro", self._prev_gro)
        self._set_state("gso", self._prev_gso)

    def save_tcp_option(self, option_name: str) -> None:
        out = self._node.run_cmd(f"sysctl {option_name}")
        self._tcp_options[option_name] = out[0].decode("utf-8").split(" = ")[-1].strip("\n")

    def set_tcp_option(self, option_name: str, option_val: str) -> None:
        self._node.run_cmd(f"sysctl -w {option_name}={option_val}")

    def restore_tcp_options(self) -> None:
        for option_name, option_value in self._tcp_options.items():
            self.set_tcp_option(option_name, option_value)

    def create_interface(self, iface_id: int) -> tuple[str, str]:
        """Create interface alias for listeners on nginx machine"""
        base_ip_addr = self.ip_str_to_number(self._base_interface_ip)
        iface_ip_addr = base_ip_addr + iface_id
        iface_ip = self.ip_number_to_str(iface_ip_addr)

        iface = f"{self._interface_name}:{iface_id}"

        try:
            test_logger.info(f"Adding ip {iface_ip}")
            self._node.run_cmd(f"LANG=C ip address add {iface_ip}/24 dev {self._interface_name} label {iface}")
        except:
            test_logger.warning("Interface alias already added")

        return iface, iface_ip

    def remove_interface(self, ip_: str) -> None:
        """Remove interface"""
        if self._check_ssh_ip_addr(ip_):
            try:
                test_logger.info(f"Removing ip {ip_}")
                self._node.run_cmd(f"LANG=C ip address del {ip_}/24 dev {self._interface_name}")
                test_logger.info("Interface alias already removed")
            except:
                test_logger.warning("Interface alias not removed")

    def create_interfaces(self, number_of_ip: int) -> list[str]:
        """Create specified amount of interface aliases"""
        ips = []
        for i in range(number_of_ip):
            (_, ip) = self.create_interface(i)
            ips.append(ip)
        return ips

    def remove_interfaces(self, ips: list[str]) -> None:
        """Remove previously created interfaces"""
        for ip in ips:
            self.remove_interface(ip)

    def create_route(self, ip_: str) -> None:
        """Create route"""
        try:
            test_logger.info(f"Adding route for {ip_}")
            self._dst_node.run_cmd(f"LANG=C ip route add {ip_} via {self._gateway_ip} dev {self._interface_name}")
            test_logger.info("Route already added")
        except:
            test_logger.warning("Route not added")

    def create_routes(self, ips: list[str]) -> None:
        for ip_ in ips:
            self.create_route(ip_)

    def remove_route(self, ip_: str):
        """Remove route"""
        # we must not remove Tempesta and server IPs because it's break the ssh connection
        if self._check_ssh_ip_addr(ip_):
            try:
                test_logger.info(f"Removing route for {ip_}")
                self._dst_node.run_cmd(f"LANG=C ip route del {ip_} dev {self._interface_name}")
                test_logger.info("Route already removed")
            except:
                test_logger.warning("Route not removed")

    def remove_routes(self, ips: list[str]) -> None:
        """Remove previously created routes"""
        for ip_ in ips:
            self.remove_route(ip_)


@contextmanager
def change_mtu_and_restore_interfaces(*, mtu: int, disable_pmtu: bool) -> Generator[list[NetWorker], Any, None]:
    if type(remote.tempesta) == type(remote.client):
        networkers: list[NetWorker] = [NetWorker(remote.tempesta)]
    else:
        networkers: list[NetWorker] = [NetWorker(remote.tempesta), NetWorker(remote.client)]

    try:
        for networker in networkers:
            networker.change_mtu(mtu=mtu, disable_pmtu=disable_pmtu)
        yield networkers
    finally:
        for networker in networkers:
            networker.restore_interface_settings()


@contextmanager
def change_and_restore_tso_gro_gso(*, tso_gro_gso: bool, mtu: int) -> Generator[list[NetWorker], Any, None]:
    with change_mtu_and_restore_interfaces(mtu=mtu, disable_pmtu=False) as networkers:
        try:
            for networker in networkers:
                networker.change_tso_gro_gso(tso_gro_gso)
            yield networkers
        finally:
            for networker in networkers:
                networker.restore_tso_gro_gso()


@contextmanager
def change_and_restore_tcp_options(*, mtu: int, tcp_options: dict[str, str]) -> Generator[list[NetWorker], Any, None]:
    with change_mtu_and_restore_interfaces(mtu=mtu, disable_pmtu=False) as networkers:
        try:
            for networker in networkers:
                for option_name, option_val in tcp_options.items():
                    networker.save_tcp_option(option_name)
                    networker.set_tcp_option(option_name, option_val)
            yield networkers
        finally:
            for networker in networkers:
                networker.restore_tcp_options()


@contextmanager
def create_and_cleanup_interfaces(
    *, node: remote.ANode, number_of_ip: int
) -> Generator[list[str], Any, None]:
    networker = NetWorker(node)
    ips = []
    try:
        ips = networker.create_interfaces(number_of_ip)
        networker.create_routes(ips)
        yield ips
    finally:
        networker.remove_routes(ips)
        networker.remove_interfaces(ips)
