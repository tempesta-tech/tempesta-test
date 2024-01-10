"""
On the fly reconfiguration test for http scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestSchedHttpReconf(tester.TempestaTest):
    tempesta_orig = {
        "config": """
        listen 80 proto=http;

        cache 0;

        srv_group origin {
            server ${server_ip}:8080;
        }

        vhost origin{
            proxy_pass origin;
        }

        http_chain {
            -> origin;
        }
        """
    }

    tempesta_add_srv = {
        "config": """
        listen 80 proto=http;

        cache 0;
        
        srv_group origin {
            server ${server_ip}:8080;
        }
        
        srv_group alternate {
            server ${server_ip}:8081;
        }
        
        vhost origin{
            proxy_pass origin;
        }
        
        vhost alternate{
            proxy_pass alternate;
        }
        
        http_chain {
            uri == "/origin" -> origin;
            uri == "/alternate" -> alternate;
        }
        """
    }

    backends = [
        {
            "id": f"server-{uri}",
            "type": "deproxy",
            "port": f"808{num}",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                f"From: /{uri}\r\n"
                "Server: debian\r\n"
                "Content-length: 9\r\n"
                "\r\n"
                "test-data"
            ),
        }
        for num, uri in [(0, "origin"), (1, "alternate")]
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_reconfig_add_srvs(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_add_srv["config"])
        tempesta.reload()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
