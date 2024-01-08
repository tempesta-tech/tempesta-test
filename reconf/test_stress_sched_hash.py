"""
On the fly reconfiguration test for hash scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestSchedHashReconf(tester.TempestaTest):
    backends_count = 5

    tempesta_orig = {
        "config": """
        listen 80;
        listen 443 proto=h2;
    
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
    
        sched hash;
        cache 0;
    
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        """
    }

    tempesta_add_srv = {
        "config": """
        listen 80;
        listen 443 proto=h2;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        sched hash;
        cache 0;

        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;
        server ${server_ip}:8003;
        server ${server_ip}:8004;
        """
    }

    tempesta_replace_srv = {
        "config": """
        listen 80;
        listen 443 proto=h2;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        sched hash;
        cache 0;

        server ${server_ip}:8003;
        server ${server_ip}:8004;
        """
    }

    backends = [
        {
            "id": f"deproxy-{step}",
            "type": "deproxy",
            "port": f"800{step}",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nServer: deproxy\r\n\r\n",
            ),
        }
        for step in range(backends_count)
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_hash_add_srvs(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_add_srv["config"])
        tempesta.reload()

    def test_hash_del_srvs(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_add_srv["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        tempesta.reload()

    def test_hash_del_add_srvs(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_replace_srv["config"])
        tempesta.reload()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
