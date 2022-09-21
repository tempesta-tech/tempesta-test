"""
Functional tests for connection_rate and connection_burst.
If the client creates too many connections, block them.
"""

from framework import tester
from helpers import dmesg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HttpConnBase(tester.TempestaTest):
    clients = [
        {
            'id' : 'deproxy' + str(x),
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        } for x in range(1, 6)
    ]

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n\r\n'
        }
    ]

    def do(self):
        klog = dmesg.DmesgFinder(ratelimited=False)
        requests = "GET / HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "Connection: close\r\n" \
                   "\r\n"
        deproxy_cl = [self.get_client(x["id"]) for x in self.clients]

        self.start_all_servers()
        self.start_tempesta()

        for cl in deproxy_cl:
            cl.start()

        self.deproxy_manager.start()

        for cl in deproxy_cl:
            cl.make_requests(requests)

        for cl in deproxy_cl:
            cl.wait_for_response(timeout=2)

        self.assertGreater(klog.warn_count(self.WARN_IP_ADDR), 0,
                           "Frang limits warning is incorrectly shown")

class HttpConnRate(HttpConnBase):
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    connection_rate 4;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections rate exceeded"

    def test(self):
        self.do()

class HttpConnBurst(HttpConnBase):
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    connection_burst 4;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections burst exceeded"

    def test(self):
        self.do()
