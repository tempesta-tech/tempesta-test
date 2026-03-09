"""
Test for Hash scheduler under heavy load. Uri should be pinned to a single
server connection. Server owning that connection should get all the
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

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import copy

from framework.test_suite import tester

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests %s;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:${port};

        location / {
            return 200;
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class BindToServer(tester.TempestaTest):
    backends_count = 30

    ka_requests = 1000000000

    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    max_concurrent_streams 10000;
    frang_limits {http_strict_host_checking false;}

    sched hash;
    cache 0;
    """
        + "".join(
            "server ${server_ip}:80%s;\n" % (step if step > 9 else f"0{step}")
            for step in range(backends_count)
        )
    }

    backends_template = [
        {
            "id": f"nginx_{step}",
            "type": "nginx",
            "port": f"80{step}" if step > 9 else f"800{step}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for step in range(backends_count)
    ]

    clients = [
        {
            "id": "client",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    async def asyncSetUp(self):
        self.backends = copy.deepcopy(self.backends_template)
        for backend in self.backends:
            backend["config"] = backend["config"] % self.ka_requests
        await super().asyncSetUp()

    async def test_hash(self):
        """
        Send requests with the same URI, only one connection (server) should be
        loaded, but a few other connections (servers) can get a little bit of the
        load while primary one is in failovering state.
        """
        client = self.get_client("client")

        await self.start_all_services()
        await self.wait_while_busy(client)
        client.stop()

        self.__check_load_distribution_between_servers()

    def __check_load_distribution_between_servers(self):
        """
        Only one server must pull mostly all the load. Other servers may also receive
        some requests while primary connection is not live.
        """
        tempesta = self.get_tempesta()
        tempesta.get_stats()

        for server in self.get_servers():
            server.get_stats()

        loaded_servers = []
        for srv in self.get_servers():
            if srv.requests:
                loaded_servers.append(srv.requests)
        loaded_servers.sort(reverse=True)

        self.assertTrue(loaded_servers)
        self.assertAlmostEqual(
            loaded_servers[0],
            tempesta.stats.cl_msg_received,
            delta=(tempesta.stats.cl_msg_received * 0.2),
            msg="Only one server should got most of the load",
        )


class BindToServerFailovering(BindToServer):
    """
    Server closes connections time to time, but not very frequently. So
    it will still get most of the load. Frequent connection closing will make
    hash scheduler to spread the load between multiple connections. Such
    situation can't be asserted automatically.

    ka_requests constant was chosen empirically. It's big enough to close
    connections once in a few seconds.
    """

    ka_requests = 50000

    async def test_hash(self):
        await super(BindToServerFailovering, self).test_hash()
