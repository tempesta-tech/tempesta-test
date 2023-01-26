__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from framework import tester


class TestTempestaReconfiguring(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta_orig = {
        "config": """
        listen 443 proto=http;
        listen 444 proto=http;
        listen 445 proto=http;
        """
    }

    tempesta_alt_gt_socks = {
        "config": """
        listen 443 proto=http;
        listen 444 proto=http;
        listen 446 proto=http;
        listen 447 proto=http;
        """
    }

    tempesta_alt_le_socks = {
        "config": """
        listen 443 proto=http;
        listen 446 proto=http;
        """
    }

    tempesta_alt_bad_socks = {
        "config": """
        listen 500 proto=http;
        listen 501 proto=http;
        listen 502 proto=http;
        listen 503 proto=http;
        listen 504 proto=http;
        listen 8000 proto=http;
        listen 505 proto=http;
        listen 506 proto=http;
        listen 507 proto=http;
        listen 508 proto=http;
        listen 509 proto=http;
        """
    }

    def test_stop(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        os.system("sysctl -e -w net.tempesta.state=stop")
        tempesta.run_start()

    def test_reconf_gt_socks(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_alt_gt_socks["config"])
        tempesta.reload()

    def test_reconf_le_socks(self):
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_alt_le_socks["config"])
        tempesta.reload()

    def test_reconf_bad_socks(self):
        self.start_all_servers()
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        self.start_tempesta()

        tempesta.config.set_defconfig(self.tempesta_alt_bad_socks["config"])
        self.oops_ignore = ["ERROR"]
        tempesta.reload()
        tempesta.config.set_defconfig(self.tempesta_orig["config"])
        tempesta.run_start()
