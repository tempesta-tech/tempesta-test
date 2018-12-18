"""
Test for Hash scheduler under heavy load. Uri should be pinned to a single
server connection. Server owning that connection connection should get all the
requests. But when the connection is down, the load will be distributed to
another connection. Once primary connection is back online it should again
get all the load.

It's not possible to get per-connection request statistics from the backend,
so all the assertions in the tests below can be done only at server level.
Not a big problem since there is test_hash_func.py tests, which works at
per-connection level. Tests in this file extend test_hash_func by the
following checks:
- Hash scheduler performs as expected under significant load;
- Load distribution works as expected if backend connections are closed time to
time.
"""

import sys
from helpers import tempesta
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class BindToServer(stress.StressTest):
    """ Send requests with the same URI, only one connection (server) should be
    loaded, but a few other connections (servers) can get a little bit of the
    load while primary one is in failovering state.
    """

    ka_requests = sys.maxsize

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())
        for s in self.servers:
            s.config.set_ka(self.ka_requests)

    def configure_tempesta(self):
        """Configure Tempesta to use hash scheduler instead of default one.
        """
        stress.StressTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'

    def assert_servers(self):
        """Assert load distribution between servers. Only one server must pull
        mostly all the load. Other servers may also receive some requests while
        primary connection is not live.
        """
        reqs_exp = self.tempesta.stats.cl_msg_received
        self.servers_get_stats()

        loaded_servers = []
        for srv in self.servers:
            if srv.requests:
                loaded_servers.append((srv.requests, srv.get_name()))
        loaded_servers.sort(reverse=True)

        self.assertTrue(loaded_servers)
        reqs, _ = loaded_servers[0]
        self.assertAlmostEqual(reqs, reqs_exp, delta=(reqs_exp * 0.2),
                               msg="Only one server should got most of the load")

    def test_hash(self):
        self.generic_test_routine('cache 0;\n')


class BindToServerFailovering(BindToServer):
    """Server closes connections time to time, but not very frequently. So
    it will still get most of the load. Frequent connection closing will make
    hash scheduler to spread the load between multiple connections. Such
    situation can't be asserted automatically.

    ka_requests constant was chosen empirically. It's big enough to close
    connections once in a few seconds.
    """

    ka_requests = 50000

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
