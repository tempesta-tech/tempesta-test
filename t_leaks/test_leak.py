"""
Testing for memory leaks
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os.path
import re
import unittest
from time import sleep

from framework import tester
from helpers import remote, tf_cfg

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))
# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))


def drop_caches():
    """Drop caches"""
    remote.tempesta.run_cmd("echo 3 > /proc/sys/vm/drop_caches")
    sleep(1)


def file_exists(remote_file):
    """Check existence of file on Tempesta host"""
    if os.path.exists(remote_file):
        return True
    return False


def has_kmemleak():
    """Check presence of kmemleak"""
    return file_exists("/sys/kernel/debug/kmemleak")


def has_meminfo():
    """Check presence of meminfo"""
    return file_exists("/proc/meminfo")


def read_kmemleaks():
    """Get amount of kmemleak records"""
    kmemleakfile = "/sys/kernel/debug/kmemleak"
    if not has_kmemleak():
        tf_cfg.dbg(1, "kmemleak file does not exists")
        return -1
    cmd = 'cat %s | grep "unreferenced object" | wc -l' % kmemleakfile
    [stdout, stderr] = remote.tempesta.run_cmd(cmd)
    return int(stdout)


def get_memory_lines(*names):
    """Get values from /proc/meminfo"""
    if not has_meminfo():
        raise Exception("/proc/meminfo does not exist")
    [stdout, stderr] = remote.tempesta.run_cmd("cat /proc/meminfo")
    lines = []
    for name in names:
        line = re.search("%s:[ ]+([0-9]+)" % name, str(stdout))
        if line:
            lines.append(int(line.group(1)))
        else:
            raise Exception("Can not get %s from /proc/meminfo" % name)
    return lines


def slab_memory():
    """Get amount of slab used memory"""
    drop_caches()
    (slabmem,) = get_memory_lines("Slab")
    return slabmem


def free_and_cached_memory():
    """Measure free memory usage"""
    drop_caches()
    freemem, cached = get_memory_lines("MemFree", "Cached")
    return freemem + cached


class LeakTest(tester.TempestaTest):
    """Leaks testing"""

    memory_leak_thresold = 32 * 1024  # in kib

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 10;
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
        listen        ${server_ip}:8000;

        location / {
            root ${server_resources};
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        }
    ]

    clients = [
        {
            "id": "client-1",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

cache 0;
server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    def run_routine(self, backend, client):
        tempesta = self.get_tempesta()
        backend.start()
        tempesta.start()
        client.start()
        self.wait_while_busy(client)
        client.stop()
        tempesta.stop()
        backend.stop()

    def test_kmemleak(self):
        """Detecting leaks with kmemleak"""
        if not has_kmemleak():
            return unittest.TestCase.skipTest(self, "No kmemleak")

        nginx = self.get_server("nginx")
        client = self.get_client("client-1")

        kml1 = read_kmemleaks()
        self.run_routine(nginx, client)
        kml2 = read_kmemleaks()

        self.assertEqual(kml1, kml2)

    def test_slab_memory(self):
        """Detecting leaks with slab memory measure"""
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        nginx = self.get_server("nginx")
        client = self.get_client("client-1")

        used1 = slab_memory()
        self.run_routine(nginx, client)
        used2 = slab_memory()

        tf_cfg.dbg(2, "used %i kib of slab memory=%s kib - %s kib" % (used2 - used1, used2, used1))
        self.assertLess(used2 - used1, self.memory_leak_thresold)

    def test_used_memory(self):
        """Detecting leaks with total used memory measure"""
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        nginx = self.get_server("nginx")
        client = self.get_client("client-1")

        free_and_cached1 = free_and_cached_memory()
        self.run_routine(nginx, client)
        free_and_cached2 = free_and_cached_memory()

        used = free_and_cached1 - free_and_cached2
        tf_cfg.dbg(
            2,
            "used %i kib of memory = %s kib - %s kib" % (used, free_and_cached1, free_and_cached2),
        )
        self.assertLess(used, self.memory_leak_thresold)


class LeakTestH2(LeakTest):
    """Leaks testing for H2."""

    clients = [
        {
            "id": "client-1",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {CONCURRENT_CONNECTIONS}"
                f" --duration {DURATION}"
            ),
        },
    ]
