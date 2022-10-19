"""
Functional tests for connection_rate and connection_burst.
If the client creates too many connections, block them.
"""

from framework import tester
from helpers import dmesg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class HttpConnBase(tester.TempestaTest):
    clients = [
        {
            "id": "ab",
            "type": "external",
            "binary": "ab",
            "cmd_args": (
                "-c 2 -n 2 " + "-H 'Host: ' -H 'Connection: close' " + "http://${tempesta_ip}/"
            ),
        }
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.0 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    def do(self):
        klog = dmesg.DmesgFinder(ratelimited=False)
        clients = [self.get_client(x["id"]) for x in self.clients]

        self.start_all_servers()
        self.start_tempesta()

        self.deproxy_manager.start()

        for cl in clients:
            cl.start()

        for cl in clients:
            self.wait_while_busy(cl)

        self.warn_count += klog.warn_count(self.WARN_IP_ADDR)

        for cl in clients:
            cl.stop()


class HttpConnRateBlock(HttpConnBase):
    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    connection_rate 1;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections rate exceeded"

    def test(self):
        self.warn_count = 0
        self.do()
        self.assertGreater(self.warn_count, 0, "Frang limits warning is incorrectly shown")


class HttpConnBurstBlock(HttpConnBase):
    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    connection_burst 1;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections burst exceeded"

    def test(self):
        self.warn_count = 0
        self.do()
        self.assertGreater(self.warn_count, 0, "Frang limits warning is incorrectly shown")


class HttpConnRateUnblock(HttpConnBase):
    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    connection_rate 4;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections rate exceeded"

    def test(self):
        self.warn_count = 0
        self.do()
        self.assertEqual(self.warn_count, 0, "Frang limits warning is incorrectly shown")


class HttpConnBurstUnblock(HttpConnBase):
    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    connection_burst 4;
}
""",
    }

    WARN_IP_ADDR = "Warning: frang: new connections burst exceeded"

    def test(self):
        self.warn_count = 0
        self.do()
        self.assertEqual(self.warn_count, 0, "Frang limits warning is incorrectly shown")
