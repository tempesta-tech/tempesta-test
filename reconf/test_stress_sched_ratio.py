"""
On the fly reconfiguration test for ratio scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestSchedRatioReconf(tester.TempestaTest):
    tempesta_orig = {
        "config": """
        listen 80;
        server ${server_ip}:8000 conns_n=1 weight=75;
        server ${server_ip}:8001 conns_n=1 weight=50;

        cache 0;
        sched ratio static;
        """
    }

    tempesta_add_srv = {
        "config": """
        listen 80;
        server ${server_ip}:8000 conns_n=1 weight=90;
        server ${server_ip}:8001 conns_n=1 weight=75;
        server ${server_ip}:8002 conns_n=1 weight=50;
        server ${server_ip}:8003 conns_n=1 weight=50;

        cache 0;
        sched ratio static;
        """
    }

    tempesta_del_srv = {
        "config": """
        listen 80;
        server ${server_ip}:8000;

        cache 0;
        """
    }

    tempesta_add_sg = {
        "config": """
        listen 80 proto=http;

        cache 0;

        srv_group custom {
            server ${server_ip}:8000 conns_n=1 weight=10;
            server ${server_ip}:8001 conns_n=1 weight=9;
            
            sched ratio static;
        }

        vhost app{
            proxy_pass custom;
        }

        http_chain {
            -> app;
        }
        """
    }

    tempesta_dyn_sched = {
        "config": """
        listen 80;
        server ${server_ip}:8000;
        server ${server_ip}:8001;

        cache 0;
        sched ratio dynamic;
        """
    }

    tempesta_dyn_sched_for_sg = {
        "config": """
        listen 80 proto=http;

        cache 0;

        srv_group custom {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
            
            sched ratio dynamic;
        }

        vhost app{
            proxy_pass custom;
        }

        http_chain {
            -> app;
        }
        """
    }

    tempesta_pre_sched = {
        "config": """
        listen 80;
        server ${server_ip}:8000;
        server ${server_ip}:8001;

        cache 0;
        sched predict percentile 75 past=60 rate=20 ahead=2;
        """
    }

    tempesta_pre_sched_for_sg = {
        "config": """
        listen 80 proto=http;

        cache 0;

        srv_group custom {
            server ${server_ip}:8080;
            server ${server_ip}:8081;
            
            sched predict percentile 75 past=60 rate=20 ahead=2;
        }

        vhost app{
            proxy_pass custom;
        }

        http_chain {
            -> app;
        }
        """
    }

    backends = [
        {
            "id": f"server-{num}",
            "type": "deproxy",
            "port": f"800{num}",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: debian\r\n"
                "Content-length: 9\r\n"
                "\r\n"
                "test-data"
            ),
        }
        for num in range(4)
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_reconfig_add_srv(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_add_srv["config"])
        tempesta.reload()

    def test_reconfig_del_srv(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_del_srv["config"])
        tempesta.reload()

    def test_reconfig_add_sg(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_add_sg["config"])
        tempesta.reload()

    def test_reconfig_dyn_sched(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_dyn_sched["config"])
        tempesta.reload()

    def test_reconfig_dyn_sched_for_sg(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_dyn_sched_for_sg["config"])
        tempesta.reload()

    def test_reconfig_pre_sched(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_pre_sched["config"])
        tempesta.reload()

    def test_reconfig_pre_sched_for_sg(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_pre_sched_for_sg["config"])
        tempesta.reload()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
