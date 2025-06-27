"""
System utils for network administration.
"""

import socket
import struct

from helpers import remote, tf_cfg
from helpers.error import Error
from helpers.tf_cfg import test_logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def ip_str_to_number(ip_addr):
    """Convert ip to number"""
    packed = socket.inet_aton(ip_addr)
    return struct.unpack("!L", packed)[0]


def ip_number_to_str(ip_addr):
    """Convert ip in numeric form to string"""
    packed = struct.pack("!L", ip_addr)
    return socket.inet_ntoa(packed)


def create_interface(iface_id, base_iface_name, base_ip):
    """Create interface alias for listeners on nginx machine"""
    base_ip_addr = ip_str_to_number(base_ip)
    iface_ip_addr = base_ip_addr + iface_id
    iface_ip = ip_number_to_str(iface_ip_addr)

    iface = "%s:%i" % (base_iface_name, iface_id)

    command = "LANG=C ip address add %s/24 dev %s label %s" % (iface_ip, base_iface_name, iface)
    try:
        test_logger.info(f"Adding ip {iface_ip}")
        remote.server.run_cmd(command)
    except:
        test_logger.warning("Interface alias already added")

    return iface, iface_ip


def remove_interface(interface_name, iface_ip):
    """Remove interface"""
    template = "LANG=C ip address del %s/24 dev %s"
    if iface_ip != tf_cfg.cfg.get("Server", "aliases_base_ip"):
        try:
            test_logger.info(f"Removing ip {iface_ip}")
            remote.server.run_cmd(template % (iface_ip, interface_name))
        except:
            test_logger.warning("Interface alias already removed")


def create_interfaces(base_interface_name, base_interface_ip, number_of_ip):
    """Create specified amount of interface aliases"""
    ips = []
    for i in range(number_of_ip):
        (_, ip) = create_interface(i, base_interface_name, base_interface_ip)
        ips.append(ip)
    return ips


def remove_interfaces(base_interface_name, ips):
    """Remove previously created interfaces"""
    for ip in ips:
        remove_interface(base_interface_name, ip)


def route_dst_ip(node, ip):
    """Determine outgoing interface for the IP."""
    command = "LANG=C ip route get to %s | grep -o 'dev [a-zA-Z0-9_-]*'" % ip
    try:
        res, _ = node.run_cmd(command)
        return res.split()[1].decode()
    except Error as err:
        raise Error("Can not determine outgoing device for %s: %s" % (ip, err))


def get_mtu(node, dev):
    command = "LANG=C ip addr show %s|grep -o 'mtu [0-9]*'" % dev
    try:
        res, _ = node.run_cmd(command)
        return int(res.split()[1])
    except Error as err:
        raise Error("Can not determine MTU for device %s: %s" % (dev, err))


def get_ip_no_pmtu_disc(node):
    command = "sysctl --values net.ipv4.ip_no_pmtu_disc"
    try:
        res, _ = node.run_cmd(command)
        return int(res)
    except Error as err:
        raise Error("Can not determine ip no pmtu discovery %s" % err)


def set_ip_no_pmtu_disc(node, ip_no_pmtu_disc):
    command = "sysctl -w net.ipv4.ip_no_pmtu_disc=%d" % ip_no_pmtu_disc
    try:
        node.run_cmd(command)
    except Error as err:
        raise Error("Can not set no pmtu discovery %s" % err)


def get_mtu_expires(node):
    command = "sysctl --values net.ipv4.route.mtu_expires"
    try:
        res, _ = node.run_cmd(command)
        return int(res)
    except Error as err:
        raise Error("Can not determine MTU expires timeout %s" % err)


def set_mtu_expires(node, expires):
    command = "sysctl -w net.ipv4.route.mtu_expires=%d" % expires
    try:
        node.run_cmd(command)
    except Error as err:
        raise Error("Can not set MTU expires timeout %s" % err)


def change_mtu(node, dev, mtu):
    """Change the device MTU and return previous MTU."""
    prev_mtu = get_mtu(node, dev)
    command = "LANG=C ip link set %s mtu %d" % (dev, mtu)
    try:
        node.run_cmd(command)
    except Error as err:
        raise Error("Can't set MTU %d for device %s" % (mtu, dev))
    if mtu != get_mtu(node, dev):
        raise Error("Cannot set MTU %d for device %s" % (mtu, dev))
    return prev_mtu


def create_route(base_iface_name, ip, gateway_ip):
    """Create route"""
    command = "LANG=C ip route add %s via %s dev %s" % (ip, gateway_ip, base_iface_name)
    try:
        test_logger.info(f"Adding route for {ip}")
        remote.tempesta.run_cmd(command)
    except:
        test_logger.warning("Route already added")

    return


def remove_route(interface_name, ip):
    """Remove route"""
    template = "LANG=C ip route del %s dev %s"
    try:
        test_logger.info(f"Removing route for {ip}")
        remote.tempesta.run_cmd(template % (ip, interface_name))
    except:
        test_logger.warning("Route already removed")


def remove_routes(base_interface_name, ips):
    """Remove previously created routes"""
    for ip in ips:
        remove_route(base_interface_name, ip)
