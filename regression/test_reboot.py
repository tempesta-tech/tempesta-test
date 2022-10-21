"""
Test TempestaFW reeboot under heavy load.
"""

from __future__ import print_function

from threading import Thread
from time import sleep

from helpers import control, remote, tf_cfg
from testers import stress

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"


class RebootUnderLoadTest(stress.StressTest):
    """Reboot under constant load"""

    restart_cycles = 10
    # Override test duration. Mostly there is no sense to load TempestaFW for a
    # long time before rebooting it.
    restart_timeout = 10
    # Timeout before first reboot.
    warm_timeout = 0

    def create_clients(self):
        self.wrk = control.Wrk()
        self.wrk.set_script("foo", content="")
        r_time = max(self.restart_timeout, 1) * (self.restart_cycles + 1)
        self.wrk.duration = r_time + self.warm_timeout + 1
        self.clients = [self.wrk]

    def reboot(self):
        sleep(self.warm_timeout)
        for i in range(self.restart_cycles):
            sleep(self.restart_timeout)
            tf_cfg.dbg(3, "\tReboot %d of %d" % (i + 1, self.restart_cycles))
            self.tempesta.stop()
            # Run random command on remote node to see if it is still alive.
            remote.tempesta.run_cmd("uname")
            self.tempesta.start()

    def reboot_routine(self, config):
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(config)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

        self.wrk.prepare()
        self.r_thread = Thread(target=self.reboot)
        self.r_thread.start()

        control.client_run_blocking(self.wrk)
        self.show_performance()

    def tearDown(self):
        if hasattr(self, "r_thread"):
            self.r_thread.join()
        stress.StressTest.tearDown(self)

    def test_proxy(self):
        config = "cache 0;\n"
        self.reboot_routine(config)

    def test_cache(self):
        config = "cache 2;\n" "cache_fulfill * *;\n"
        self.reboot_routine(config)


class RebootUnderLoadNoTimeoutTest(RebootUnderLoadTest):
    """No timeout between reboots"""

    restart_timeout = 0
    warm_timeout = 5


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
