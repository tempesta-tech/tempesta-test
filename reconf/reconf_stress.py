"""
Live reconfiguration stress test primitive.
"""

from threading import Thread
from time import sleep

from helpers import control, tempesta, tf_cfg
from testers import stress

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"


class LiveReconfStress(stress.StressTest):

    defconfig = ""
    sg_name = "default"
    auto_vhosts = True

    def setUp(self):
        self.addCleanup(self.cleanup_parent_teardown)
        self.addCleanup(self.cleanup_reconfig_thread)

    def cleanup_reconfig_thread(self):
        # Wait for reconfig thread if it's not finished (exception was thrown
        # during stress_reconfig_generic()
        if hasattr(self, "r_thread"):
            self.r_thread.join()

    def cleanup_parent_teardown(self):
        stress.StressTest.tearDown(self)

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        rm_srv_n = tempesta.servers_in_group() / 3
        add_srn_n = rm_srv_n
        const_srv_n = tempesta.servers_in_group() - rm_srv_n - add_srn_n

        self.rm_srvs = []
        self.add_srvs = []
        self.const_srvs = []
        self.servers = []

        for _ in range(int(rm_srv_n)):
            server = control.Nginx(listen_port=port)
            self.rm_srvs.append(server)
            port += 1
        for _ in range(int(const_srv_n)):
            server = control.Nginx(listen_port=port)
            self.const_srvs.append(server)
            port += 1
        for _ in range(int(add_srn_n)):
            server = control.Nginx(listen_port=port)
            self.add_srvs.append(server)
            port += 1

        # united array to start and stop all servers at once
        self.servers = self.rm_srvs + self.const_srvs + self.add_srvs

    def add_sg(self, config, sg_name, servers):
        sg = tempesta.ServerGroup(sg_name)
        for s in servers:
            sg.add_server(s.ip, s.config.port, s.conns_n)
        config.add_sg(sg)

    def make_config(self, sg_name, servers, defconfig=None):
        """Create new configuration for TempestaFW."""
        config = tempesta.Config(vhost_auto=self.auto_vhosts)
        if defconfig is None:
            defconfig = self.defconfig
        config.set_defconfig(defconfig)
        self.add_sg(config, sg_name, servers)
        return config

    def reconfig(self):
        sleep(int(tf_cfg.cfg.get("General", "Duration")) / 2)
        self.reconfigure_func()
        self.tempesta.reload()

    def assert_clients(self):
        """Check benchmark result: 502 errors may happen but only for short
        period of time (during reconfig)."""
        for c in self.clients:
            req, err, rate, _ = c.results()
            # Tempesta must be reconfigured in less that 1sec. Errors must not
            # happen after reconfig has finished.
            max_err = rate
            self.assertLess(err, max_err)

    def stress_reconfig_generic(self, configure_func, reconfigure_func):
        """Generic test routine for reconfig."""
        self.reconfigure_func = reconfigure_func
        control.servers_start(self.servers)
        configure_func()
        self.tempesta.start()

        self.r_thread = Thread(target=self.reconfig)
        self.r_thread.start()

        control.clients_run_parallel(self.clients)
        self.show_performance()
        self.tempesta.get_stats()

        self.r_thread.join()
        self.assert_clients()

    def tearDown(self):
        pass

    def configure_srvs_start(self):
        srvs = self.const_srvs + self.rm_srvs
        config = self.make_config(self.sg_name, srvs)
        self.tempesta.config = config

    def configure_srvs_add(self):
        srvs = self.const_srvs + self.rm_srvs + self.add_srvs
        config = self.make_config(self.sg_name, srvs)
        self.tempesta.config = config

    def configure_srvs_del(self):
        srvs = self.const_srvs
        config = self.make_config(self.sg_name, srvs)
        self.tempesta.config = config

    def configure_srvs_del_add(self):
        srvs = self.const_srvs + self.add_srvs
        config = self.make_config(self.sg_name, srvs)
        self.tempesta.config = config


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
