from __future__ import print_function

import unittest

from helpers import control, dmesg, remote, stateful, tempesta, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


@util.deprecated("tester.TempestaTest")
class StressTest(unittest.TestCase):
    """Test Suite to use HTTP benchmarks as a clients. Can be used for
    functional testing of schedulers and stress testing for other components.
    """

    pipelined_req = 1
    tfw_msg_errors = False
    errors_500 = 0
    errors_502 = 0
    errors_504 = 0
    errors_connect = 0
    errors_read = 0
    errors_write = 0
    errors_timeout = 0

    def create_clients(self):
        """Override to set desired list of benchmarks and their options."""
        self.wrk = control.Wrk()
        self.wrk.set_script("foo", content="")
        self.clients = [self.wrk]

    def create_tempesta(self):
        """Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """Add all servers to default server group with default scheduler."""
        sg = tempesta.ServerGroup("default")
        for s in self.servers:
            sg.add_server(s.ip, s.config.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """Overrirde to create needed amount of upstream servers."""
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port)]

    def create_servers_helper(self, count, start_port=None):
        """Helper function to spawn `count` servers in default configuration.

        See comment in Nginx.get_stats().
        """
        if start_port is None:
            start_port = tempesta.upstream_port_start_from()
        self.servers = []
        for i in range(count):
            self.servers.append(control.Nginx(listen_port=(start_port + i)))

    def setUp(self):
        # Init members used in tearDown function.
        self.oops = dmesg.DmesgFinder()
        self.oops_ignore = []
        self.tempesta = None
        self.servers = []
        tf_cfg.dbg(3)  # Step to the next line after name of test case.
        tf_cfg.dbg(3, "\tInit test case...")
        if not remote.wait_available():
            raise Exception("Tempesta node is unavaliable")
        self.create_clients()
        self.create_servers()
        self.create_tempesta()
        # Cleanup part
        self.addCleanup(self.cleanup_check_dmesg)
        self.addCleanup(self.cleanup_servers)
        self.addCleanup(self.cleanup_tempesta)

    def cleanup_tempesta(self):
        if self.tempesta:
            self.tempesta.stop()
            if self.tempesta.state == stateful.STATE_ERROR:
                raise Exception("Error during stopping tempesta")

    def cleanup_servers(self):
        if self.servers:
            control.servers_stop(self.servers)
            for server in self.servers:
                if server.state == stateful.STATE_ERROR:
                    raise Exception("Error during stopping servers")

    def cleanup_check_dmesg(self):
        self.oops.update()
        for err in ["Oops", "WARNING", "ERROR"]:
            if err in self.oops_ignore:
                continue
            if len(self.oops.log_findall(err)) > 0:
                self.oops_ignore = []
                raise Exception(f"{err} happened during test on Tempesta")
        # Drop the list of ignored errors to allow set different errors masks
        # for different tests.
        self.oops_ignore = []
        del self.oops

    def force_stop(self):
        """Forcefully stop all servers."""
        # Call functions only if variables not None: there might be an error
        # before tempesta would be created.
        if self.tempesta:
            self.tempesta.force_stop()
        if self.servers:
            control.servers_force_stop(self.servers)

    def show_performance(self):
        if tf_cfg.v_level() < 2:
            return
        if tf_cfg.v_level() == 2:
            # Go to new line, don't mess up output.
            tf_cfg.dbg(2)
        req_total = err_total = rate_total = 0
        for c in self.clients:
            req, err, rate, _ = c.results()
            req_total += req
            err_total += err
            rate_total += rate
            tf_cfg.dbg(3, ("\tClient: errors: %d, requests: %d, rate: %d" % (err, req, rate)))
        tf_cfg.dbg(
            2,
            "\tClients in total: errors: %d, requests: %d, rate: %d"
            % (err_total, req_total, rate_total),
        )

    def assert_client(self, req, err, statuses):
        msg = "HTTP client detected %i/%i errors. Results: %s" % (err, req, str(statuses))
        e_500 = 0
        e_502 = 0
        e_504 = 0
        e_connect = 0
        e_read = 0
        e_write = 0
        e_timeout = 0

        # "named" statuses are wrk-dependent results
        if "connect_error" in statuses.keys():
            e_connect = statuses["connect_error"]
        if "read_error" in statuses.keys():
            e_read = statuses["read_error"]
        if "write_error" in statuses.keys():
            e_write = statuses["write_error"]
        if "timeout_error" in statuses.keys():
            e_timeout = statuses["timeout_error"]
        if 500 in statuses.keys():
            e_500 = statuses[500]
        if 502 in statuses.keys():
            e_502 = statuses[502]
        if 504 in statuses.keys():
            e_504 = statuses[504]

        self.errors_connect += e_connect
        self.errors_read += e_read
        self.errors_write += e_write
        self.errors_timeout += e_timeout
        self.errors_500 += e_500
        self.errors_502 += e_502
        self.errors_504 += e_504
        tf_cfg.dbg(2, "errors 500: %i" % e_500)
        tf_cfg.dbg(2, "errors 502: %i" % e_502)
        tf_cfg.dbg(2, "errors 504: %i" % e_504)
        tf_cfg.dbg(2, "errors connect: %i" % e_connect)
        tf_cfg.dbg(2, "errors read: %i" % e_read)
        tf_cfg.dbg(2, "errors write: %i" % e_write)
        tf_cfg.dbg(2, "errors timeout: %i" % e_timeout)
        self.assertGreater(req, 0, msg="No work was done by the client")
        self.assertEqual(err, e_500 + e_502 + e_504 + e_connect, msg=msg)

    def assert_clients(self):
        """Check benchmark result: no errors happen, no packet loss."""
        cl_req_cnt = 0
        cl_conn_cnt = 0
        self.errors_502 = 0
        self.errors_504 = 0
        self.errors_connect = 0
        self.errors_read = 0
        self.errors_write = 0
        self.errors_timeout = 0
        for c in self.clients:
            req, err, _, statuses = c.results()
            cl_req_cnt += req
            cl_conn_cnt += c.connections * self.pipelined_req
            self.assert_client(req, err, statuses)

        exp_min = cl_req_cnt
        # Positive allowance: this means some responses are missed by the client.
        # It is believed (nobody actually checked though...) that wrk does not
        # wait for responses to last requests in each connection before closing
        # it and does not account for those requests.
        # So, [0; concurrent_connections] responses will be missed by the client.
        exp_max = cl_req_cnt + cl_conn_cnt
        self.assertTrue(
            self.tempesta.stats.cl_msg_received >= exp_min
            and self.tempesta.stats.cl_msg_received <= exp_max,
            msg="Tempesta received bad number %d of messages, expected [%d:%d]"
            % (self.tempesta.stats.cl_msg_received, exp_min, exp_max),
        )

    def assert_tempesta(self):
        """Don't make asserts by default"""

        cl_conn_cnt = 0
        for c in self.clients:
            cl_conn_cnt += c.connections

        cl_parsing_err = self.tempesta.stats.cl_msg_parsing_errors
        srv_parsing_err = self.tempesta.stats.srv_msg_parsing_errors
        cl_other_err = self.tempesta.stats.cl_msg_other_errors
        srv_other_err = self.tempesta.stats.srv_msg_other_errors

        tf_cfg.dbg(2, "CL Msg parsing errors: %i" % cl_parsing_err)
        tf_cfg.dbg(2, "SRV Msg parsing errors: %i" % srv_parsing_err)
        tf_cfg.dbg(2, "CL Msg other errors: %i" % cl_other_err)
        tf_cfg.dbg(2, "SRV Msg other errors: %i" % srv_other_err)

    def assert_tempesta_strict(self):
        """Assert that tempesta had no errors during test."""
        msg = "Tempesta have %i errors in processing HTTP %s."
        cl_conn_cnt = 0
        for c in self.clients:
            cl_conn_cnt += c.connections

        cl_parsing_err = self.tempesta.stats.cl_msg_parsing_errors
        srv_parsing_err = self.tempesta.stats.srv_msg_parsing_errors
        cl_other_err = self.tempesta.stats.cl_msg_other_errors
        srv_other_err = self.tempesta.stats.srv_msg_other_errors

        tf_cfg.dbg(2, "CL Msg parsing errors: %i" % cl_parsing_err)
        tf_cfg.dbg(2, "SRV Msg parsing errors: %i" % srv_parsing_err)
        tf_cfg.dbg(2, "CL Msg other errors: %i" % cl_other_err)
        tf_cfg.dbg(2, "SRV Msg other errors: %i" % srv_other_err)

        err_msg = msg % (cl_parsing_err, "requests")
        self.assertEqual(cl_parsing_err, 0, msg=err_msg)
        err_msg = msg % (srv_parsing_err, "responses")
        self.assertEqual(srv_parsing_err, 0, msg=err_msg)
        if self.tfw_msg_errors:
            return

        # TODO: with self.errors_502 we should compare special counter for
        # backend connection error. But it is not present.
        total = self.errors_502 + self.errors_504 + self.errors_connect + self.errors_timeout
        err_msg = msg % (cl_other_err, "requests")
        self.assertLessEqual(cl_other_err, total, msg=err_msg)
        # See comment on "positive allowance" in `assert_clients()`
        expected_err = cl_conn_cnt
        err_msg = msg % (srv_other_err, "responses")
        self.assertLessEqual(srv_other_err, expected_err, msg=err_msg)

    def assert_servers(self):
        # Nothing to do for nginx in default configuration.
        # Implementers of this method should take into account the deficiency
        # of wrk described above.
        pass

    def servers_get_stats(self):
        control.servers_get_stats(self.servers)

    def generic_start_test(self, tempesta_defconfig):
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

    def generic_asserts_test(self):
        self.show_performance()
        # Tempesta statistics is valuable to client assertions.
        self.tempesta.get_stats()

        self.assert_clients()
        self.assert_tempesta()
        self.assert_servers()

    def generic_test_routine(self, tempesta_defconfig):
        """Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        self.generic_start_test(tempesta_defconfig)
        control.clients_run_parallel(self.clients)
        self.generic_asserts_test()


if __name__ == "__main__":
    unittest.main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
