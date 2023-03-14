""" Helpers to control different network adapter settings. """

from helpers import remote, sysnet, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

class NetWorker:
    def _get_state(self, dev, what):
        cmd = f"ethtool --show-features {dev} | grep {what}"
        out = remote.client.run_cmd(cmd)
        return out[0].decode("utf-8").split(" ")[-1].strip("\n")

    def _set_state(self, dev, what, on=True):
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

    def run_test_tso_gro_gso(self, client, server, test, mtu, tso, gro, gso):
        try:
            # Deproxy client and server run on the same node and network
            # interface, so, regardless where the Tempesta node resides, we can
            # change MTU on the local interface only to get the same MTU for
            # both the client and server connections.
            dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
            prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
        except Error as err:
            self.fail(err)
        try:
            self.get_tso_state(dev)
            self.get_gro_state(dev)
            self.get_gso_state(dev)
            self.change_tso(dev, tso)
            self.change_gro(dev, gro)
            self.change_gso(dev, gso)

            test(client, server)
        finally:
            self.change_tso(dev, self.tso_state)
            self.change_gro(dev, self.gro_state)
            self.change_gso(dev, self.gro_state)
            sysnet.change_mtu(remote.client, dev, prev_mtu)

    def run_test_tso_gro_gso_disabled(self, client, server, test, mtu):
        self.run_test_tso_gro_gso(client, server, test, mtu, False, False, False)

    def run_test_tso_gro_gso_enabled(self, client, server, test, mtu):
        self.run_test_tso_gro_gso(client, server, test, mtu, True, True, True)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
