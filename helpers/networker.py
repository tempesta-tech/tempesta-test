""" Helpers to control different network adapter settings. """

import re
import socket

import pyroute2

from helpers import remote, tf_cfg
from test_suite import sysnet

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NetWorker:
    @staticmethod
    def __get_ipv6_addr(dev):
        ip = pyroute2.IPRoute()
        index = ip.link_lookup(ifname=dev)[0]

        return ip.get_addr(family=socket.AF_INET6, index=index)

    @staticmethod
    def __set_ipv6_addr(dev, old_ipv6_addresses):
        curr_ipv6_addresses = NetWorker().__get_ipv6_addr(dev)
        ip = pyroute2.IPRoute()
        index = ip.link_lookup(ifname=dev)[0]

        for ipv6_addr in old_ipv6_addresses:
            if ipv6_addr not in curr_ipv6_addresses:
                addr = ipv6_addr.get_attr("IFA_ADDRESS")
                mask = ipv6_addr["prefixlen"]
                ip.addr("add", index=index, address=addr, mask=mask)

    @staticmethod
    def __get_dev():
        dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
        return dev

    @staticmethod
    def __get_state(dev, what):
        cmd = f"ethtool --show-features {dev} | grep {what}"
        out = remote.client.run_cmd(cmd)
        return out[0].decode("utf-8").split(" ")[-1].strip("\n")

    @staticmethod
    def __set_state(dev, what, on=True):
        if on:
            cmd = f"ethtool -K {dev} {what} on"
        else:
            cmd = f"ethtool -K {dev} {what} off"
        out = remote.client.run_cmd(cmd)

    def mtu_ctx(self, node, dev, mtu):
        try:
            yield
        finally:
            sysnet.change_mtu(node, dev, mtu)

    @staticmethod
    def _set_mtu(saved_prev_mtu, node, destination_ip, mtu, disable_pmtu):
        dev = sysnet.route_dst_ip(node=node, ip=destination_ip)
        dest_ip = (
            destination_ip
            if not re.match(r"^(127)\.(0)\.(0)\.(\d{1,3})$", destination_ip)
            else "local"
        )
        if not (dev, dest_ip) in saved_prev_mtu:
            ipv6_addresses = NetWorker().__get_ipv6_addr(dev)
            prev_mtu = sysnet.change_mtu(node=node, dev=dev, mtu=mtu)
            prev_mtu_expires = sysnet.get_mtu_expires(node)
            prev_ip_no_pmtu_disc = None
            if disable_pmtu:
                prev_ip_no_pmtu_disc = sysnet.get_ip_no_pmtu_disc(node)
                sysnet.set_ip_no_pmtu_disc(node, 1)
            sysnet.set_mtu_expires(node, 0)
            saved_prev_mtu[(dev, dest_ip)] = [
                node,
                dev,
                prev_mtu,
                prev_mtu_expires,
                prev_ip_no_pmtu_disc,
                ipv6_addresses,
            ]

    @staticmethod
    def _node_from_str(node):
        if node == "remote.tempesta":
            return remote.tempesta
        elif node == "remote.server":
            return remote.server
        elif node == "remote.client":
            return remote.client
        else:
            return None

    @staticmethod
    def set_mtu(
        nodes: [
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ],
        disable_pmtu=False
    ):
        def decorator(test):
            def wrapper(self, *args, **kwargs):
                try:
                    saved_prev_mtu = {}
                    for node in nodes:
                        NetWorker()._set_mtu(
                            saved_prev_mtu=saved_prev_mtu,
                            node=NetWorker._node_from_str(node["node"]),
                            destination_ip=node["destination_ip"],
                            mtu=node["mtu"],
                            disable_pmtu=disable_pmtu
                        )

                    test(self, *args, **kwargs)
                finally:
                    for (
                        node,
                        dev,
                        prev_mtu,
                        prev_mtu_expires,
                        prev_ip_no_pmtu_disc,
                        ipv6_addresses,
                    ) in saved_prev_mtu.values():
                        sysnet.change_mtu(node=node, dev=dev, mtu=prev_mtu)
                        sysnet.set_mtu_expires(node, prev_mtu_expires)
                        if prev_ip_no_pmtu_disc is not None:
                            sysnet.set_ip_no_pmtu_disc(node, prev_ip_no_pmtu_disc)
                        """
                        If ipv6 address was not remowed it can't be set
                        second time.
                        """
                        try:
                            NetWorker.__set_ipv6_addr(dev, ipv6_addresses)
                        except:
                            pass

            wrapper.__name__ = test.__name__
            return wrapper

        return decorator

    def get_tso_state(self, dev):
        tso_state = NetWorker().__get_state(dev, "tcp-segmentation-offload")
        if tso_state == "on":
            self.tso_state = True
        else:
            self.tso_state = False

    def get_gro_state(self, dev):
        gro_state = NetWorker().__get_state(dev, "generic-receive-offload")
        if gro_state == "on":
            self.gro_state = True
        else:
            self.gro_state = False

    def get_gso_state(self, dev):
        gso_state = NetWorker().__get_state(dev, "generic-segmentation-offload")
        if gso_state == "on":
            self.gso_state = True
        else:
            self.gso_state = False

    def change_tso(self, dev, on=True):
        NetWorker().__set_state(dev, "tso", on)

    def change_gro(self, dev, on=True):
        NetWorker().__set_state(dev, "gro", on)

    def change_gso(self, dev, on=True):
        NetWorker().__set_state(dev, "gso", on)

    def _get_tcp_option(self, option_name):
        cmd = f"sysctl {option_name}"
        out = remote.tempesta.run_cmd(cmd)
        self.option_val = out[0].decode("utf-8").split(" = ")[-1].strip("\n")

    def _set_tcp_option(self, option_name, option_val):
        cmd = f"sysctl -w {option_name}={option_val}"
        out = remote.tempesta.run_cmd(cmd)

    def __run_test_tso_gro_gso(
        self, client, server, test, mtu, tso, gro, gso, option_name=None, option_val=None
    ):
        try:
            # Deproxy client and server run on the same node and network
            # interface, so, regardless where the Tempesta node resides, we can
            # change MTU on the local interface only to get the same MTU for
            # both the client and server connections.
            dev = NetWorker().__get_dev()
            prev_mtu_expires = sysnet.get_mtu_expires(remote.client)
            sysnet.set_mtu_expires(remote.client, 0)
            prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
        except Exception as err:
            self.fail(err)
        try:
            self.get_tso_state(dev)
            self.get_gro_state(dev)
            self.get_gso_state(dev)
            self.change_tso(dev, tso)
            self.change_gro(dev, gro)
            self.change_gso(dev, gso)
            if option_name and option_val:
                self._get_tcp_option(option_name)
                self._set_tcp_option(option_name, option_val)

            test(client, server)
        finally:
            if option_name:
                self._set_tcp_option(option_name, self.option_val)
                self.option_val = None
            self.change_tso(dev, self.tso_state)
            self.change_gro(dev, self.gro_state)
            self.change_gso(dev, self.gro_state)
            sysnet.change_mtu(remote.client, dev, prev_mtu)
            sysnet.set_mtu_expires(remote.client, prev_mtu_expires)

    def run_test_tso_gro_gso_disabled(self, client, server, test, mtu):
        self.__run_test_tso_gro_gso(client, server, test, mtu, False, False, False)

    def run_test_tso_gro_gso_enabled(self, client, server, test, mtu):
        self.__run_test_tso_gro_gso(client, server, test, mtu, True, True, True)

    def run_test_tso_gro_gso_def(
        self, client, server, test, mtu, option_name=None, option_val=None
    ):
        try:
            dev = NetWorker().__get_dev()
        except Exception as err:
            self.fail(err)

        tso = self.get_tso_state(dev)
        gro = self.get_gro_state(dev)
        gso = self.get_gso_state(dev)
        self.__run_test_tso_gro_gso(
            client, server, test, mtu, tso, gro, gso, option_name, option_val
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
