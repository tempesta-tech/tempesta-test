"""
Testing for memory leaks
"""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import re
from time import sleep

from testers import stress
from helpers import tf_cfg, control, tempesta, remote

from framework import tester

def drop_caches():
    """ Drop caches """
    remote.tempesta.run_cmd("echo 3 > /proc/sys/vm/drop_caches")
    sleep(1)

def file_exists(remote_file):
    """ Check existance of file on Tempesta host """
    check_cmd = "if [ -e %s ]; then echo -n yes; fi" % remote_file
    [stdout, stderr] = remote.tempesta.run_cmd(check_cmd)
    if stdout != "yes":
        return False
    return True

def has_kmemleak():
    """ Check presence of kmemleak """
    return file_exists("/sys/kernel/debug/kmemleak")

def has_meminfo():
    """ Check presence of meminfo """
    return file_exists("/proc/meminfo")

def read_kmemleaks():
    """ Get amount of kmemleak records """
    kmemleakfile = "/sys/kernel/debug/kmemleak"
    if not has_kmemleak():
        tf_cfg.dbg(1, "kmemleak file does not exists")
        return -1
    cmd = "cat %s | grep \"unreferenced object\" | wc -l" % kmemleakfile
    [stdout, stderr] = remote.tempesta.run_cmd(cmd)
    return int(stdout)

def get_memory_lines(*names):
    """ Get values from /proc/meminfo """
    if not has_meminfo():
        return -1
    [stdout, stderr] = remote.tempesta.run_cmd("cat /proc/meminfo")
    lines = []
    for name in names:
        line = re.search("%s:[ ]+([0-9]+)" % name, stdout)
        if line:
            lines.append(int(line.group(1)))
        else:
            lines.append(-1)
    return lines

def slab_memory():
    """ Get amount of slab used memory """
    drop_caches()
    slabmem, = get_memory_lines("Slab")
    return slabmem

def free_memory():
    """ Measure free memory usage """
    drop_caches()
    freemem, = get_memory_lines("MemFree")
    if freemem == -1:
        return -1
    return freemem

class LeakTest(tester.TempestaTest):
    """ Leaks testing """
    memory_leak_thresold = 32*1024 # in kib

    backends = [
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : """
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
            'id' : 'wrk',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        'config' : """
cache 0;
server ${server_ip}:8000;

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
        """ Detecting leaks with kmemleak """
        if not has_kmemleak():
            return unittest.TestCase.skipTest(self, "No kmemleak")

        nginx = self.get_server('nginx')
        wrk = self.get_client('wrk')

        kml1 = read_kmemleaks()
        self.run_routine(nginx, wrk)
        kml2 = read_kmemleaks()

        self.assertEqual(kml1, kml2)

    def test_slab_memory(self):
        """ Detecting leaks with slab memory measure """
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        nginx = self.get_server('nginx')
        wrk = self.get_client('wrk')

        used1 = slab_memory()
        self.run_routine(nginx, wrk)
        used2 = slab_memory()

        tf_cfg.dbg(2, "used %i kib of slab memory=%s kib - %s kib" % \
                    (used2 - used1, used2, used1))
        self.assertLess(used2 - used1, self.memory_leak_thresold)

    def test_used_memory(self):
        """ Detecting leaks with total used memory measure """
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        nginx = self.get_server('nginx')
        wrk = self.get_client('wrk')

        free1 = free_memory()
        self.run_routine(nginx, wrk)
        free2 = free_memory()

        tf_cfg.dbg(2, "used %i kib of memory = %s kib - %s kib" % \
                    (free1 - free2, free1, free2))
        self.assertLess(free1 - free2, self.memory_leak_thresold)
