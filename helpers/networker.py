""" Helpers to control different network adapter settings. """

from helpers import remote, tf_cfg
from test_suite import sysnet

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NetWorker:
    @staticmethod
    def _get_ipv6_addr(dev):
        was_found = False
        cmd = f"ip -6 addr show dev {dev} | grep inet6"
        out = remote.client.run_cmd(cmd)
        out = out[0].decode("utf-8").split(" ")
        for val in out:
            if val == "inet6":
                was_found = True
                # Next value is address
                continue
            if was_found:
                return val.split("/")
        return None

    @staticmethod
    def _set_ipv6_addr(dev, addr, prefix):
        cmd = f"ip -6 addr add {addr}/{prefix} dev {dev}"
        out = remote.client.run_cmd(cmd)

    @staticmethod
    def _get_dev():
        dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
        return dev

    @staticmethod
    def _get_state(dev, what):
        cmd = f"ethtool --show-features {dev} | grep {what}"
        out = remote.client.run_cmd(cmd)
        return out[0].decode("utf-8").split(" ")[-1].strip("\n")

    @staticmethod
    def _set_state(dev, what, on=True):
        if on:
            cmd = f"ethtool -K {dev} {what} on"
        else:
            cmd = f"ethtool -K {dev} {what} off"
        out = remote.client.run_cmd(cmd)

    @staticmethod
    def __protect_ipv6_addr_on_dev(func, *args, **kwargs):
        dev = NetWorker._get_dev()
        cmd = f"ip -6 addr show dev {dev} | grep inet6"
        ipv6_addr = None
        was_found = False

        try:
            out = remote.client.run_cmd(cmd)
            out = out[0].decode("utf-8").split(" ")
            for val in out:
                if val == "inet6":
                    was_found = True
                    # Next value is address
                    continue
                if was_found:
                    ipv6_addr = val.split("/")
                    break
            return func(*args, **kwargs)
        finally:
            if ipv6_addr:
                cmd = f"ip -6 addr add {ipv6_addr[0]}/{ipv6_addr[1]} dev {dev}"
                remote.client.run_cmd(cmd)

    @staticmethod
    def protect_ipv6_addr_on_dev(func):
        """The decorator protect ipv6 device settings."""

        def func_wrapper(*args, **kwargs):
            return NetWorker.__protect_ipv6_addr_on_dev(func, *args, **kwargs)

        # we need to change name of function to work correctly with parametrize
        func_wrapper.__name__ = func.__name__

        return func_wrapper

    def mtu_ctx(self, node, dev, mtu):
        try:
            yield
        finally:
            sysnet.change_mtu(node, dev, mtu)

    def get_tso_state(self, dev):
        tso_state = self._get_state(dev, "tcp-segmentation-offload")
        if tso_state == "on":
            self.tso_state = True
        else:
            self.tso_state = False

    def get_gro_state(self, dev):
        gro_state = self._get_state(dev, "generic-receive-offload")
        if gro_state == "on":
            self.gro_state = True
        else:
            self.gro_state = False

    def get_gso_state(self, dev):
        gso_state = self._get_state(dev, "generic-segmentation-offload")
        if gso_state == "on":
            self.gso_state = True
        else:
            self.gso_state = False

    def change_tso(self, dev, on=True):
        self._set_state(dev, "tso", on)

    def change_gro(self, dev, on=True):
        self._set_state(dev, "gro", on)

    def change_gso(self, dev, on=True):
        self._set_state(dev, "gso", on)

    def _get_tcp_option(self, option_name):
        cmd = f"sysctl {option_name}"
        out = remote.tempesta.run_cmd(cmd)
        self.option_val = out[0].decode("utf-8").split(" = ")[-1].strip("\n")

    def _set_tcp_option(self, option_name, option_val):
        cmd = f"sysctl -w {option_name}={option_val}"
        out = remote.tempesta.run_cmd(cmd)

    def run_test_tso_gro_gso(
        self, client, server, test, mtu, tso, gro, gso, option_name=None, option_val=None
    ):
        try:
            # Deproxy client and server run on the same node and network
            # interface, so, regardless where the Tempesta node resides, we can
            # change MTU on the local interface only to get the same MTU for
            # both the client and server connections.
            dev = NetWorker._get_dev()
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
                NetWorker._get_tcp_option(option_name)
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

    def run_test_tso_gro_gso_disabled(self, client, server, test, mtu):
        self.run_test_tso_gro_gso(client, server, test, mtu, False, False, False)

    def run_test_tso_gro_gso_enabled(self, client, server, test, mtu):
        self.run_test_tso_gro_gso(client, server, test, mtu, True, True, True)

    def run_test_tso_gro_gso_def(
        self, client, server, test, mtu, option_name=None, option_val=None
    ):
        try:
            dev = self._get_dev()
        except Exception as err:
            self.fail(err)

        tso = self.get_tso_state(dev)
        gro = self.get_gro_state(dev)
        gso = self.get_gso_state(dev)
        self.run_test_tso_gro_gso(client, server, test, mtu, tso, gro, gso, option_name, option_val)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
