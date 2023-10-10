"""
Live reconfiguration stress test for sticky sessions.
"""

from helpers import control, tf_cfg

from . import reconf_stress

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"


class SchedSticky(reconf_stress.LiveReconfStress):
    sg_name = "default"
    sched = "ratio static"
    defconfig = (
        "cache 0;\n"
        "sticky {\n"
        "   cookie enforce;\n"
        '   secret "f00)9eR59*_/22";\n'
        "   sticky_sessions;\n"
        "}\n"
        "\n"
    )
    clients_num = min(int(tf_cfg.cfg.get("General", "concurrent_connections")), 1000)
    auto_vhosts = False

    def create_clients(self):
        # See test_sticky_sess_stress
        self.wrk = control.Wrk(threads=self.clients_num)
        self.wrk.connections = self.wrk.threads
        self.wrk.set_script("cookie-many-clients")
        self.clients = [self.wrk]

    def configure_srvs_start(self):
        reconf_stress.LiveReconfStress.configure_srvs_start(self)

    def configure_srvs_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_add(self)

    def configure_srvs_del(self):
        reconf_stress.LiveReconfStress.configure_srvs_del(self)

    def configure_srvs_del_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_del_add(self)

    def test_ratio_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start, self.configure_srvs_add)

    def test_ratio_del_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start, self.configure_srvs_del)

    def test_ratio_del_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start, self.configure_srvs_del_add)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
