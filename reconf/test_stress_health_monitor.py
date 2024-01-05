"""
On the fly reconfiguration test for server group
with health monitor.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester

TEMPESTA_CONFIG = """

listen 80 proto=http;

server_failover_http 404 50 5;
cache 0;

srv_group srv_grp1 {
    server ${server_ip}:8080;
}

vhost srv_grp1{
    proxy_pass srv_grp1;
}

http_chain {
    -> srv_grp1;
}
%s
"""

TEMPESTA_CONFIG_ADD_HM = """

listen 80 proto=http;

server_failover_http 404 50 5;
cache 0;

health_check monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}

srv_group srv_grp1 {
    server ${server_ip}:8080;
    server ${server_ip}:8081;

    health monitor1;
}

vhost srv_grp1{
    proxy_pass srv_grp1;
}

http_chain {
    -> srv_grp1;
}
%s
"""

TEMPESTA_CONFIG_ADD_SRV_GROUP = """

listen 80 proto=http;

server_failover_http 404 50 5;
cache 0;

health_check monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}


srv_group srv_grp1 {
    server ${server_ip}:8080;
    server ${server_ip}:8081;

    health monitor1;
}

srv_group srv_grp2 {
    server ${server_ip}:8082;
    server ${server_ip}:8083;

    health monitor1;
}

srv_group srv_grp3 {
    server ${server_ip}:8084;
    server ${server_ip}:8085;

    health monitor1;
}

vhost srv_grp1{
    proxy_pass srv_grp1;
}

vhost srv_grp2{
    proxy_pass srv_grp2;
}

vhost srv_grp3{
    proxy_pass srv_grp3;
}

http_chain {
    uri == "/server1" -> srv_grp1;
    uri == "/server2" -> srv_grp2;
    uri == "/server3" -> srv_grp3;
}
%s
"""

TEMPESTA_CONFIG_DEL_SRV_GROUP = """

listen 80 proto=http;

server_failover_http 404 50 5;
cache 0;

health_check monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}

srv_group srv_grp1 {
    server ${server_ip}:8080;
    server ${server_ip}:8081;

    health monitor1;
}

vhost srv_grp1{
    proxy_pass srv_grp1;
}

http_chain {
    -> srv_grp1;
}
%s
"""

SRV_GRP1 = [
    {
        "id": f"server{num}",
        "type": "deproxy",
        "port": f"800{num}",
        "response": "static",
        "response_content": (
            "HTTP/1.1 200 OK\r\n"
            "From: /server1\r\n"
            "Server: debian\r\n"
            "Content-length: 9\r\n"
            "\r\n"
            "test-data"
        ),
    }
    for num in range(2)
]

SRV_GRP2 = [
    {
        "id": f"server{num}",
        "type": "deproxy",
        "port": f"800{num}",
        "response": "static",
        "response_content": (
            "HTTP/1.1 200 OK\r\n"
            "From: /server2\r\n"
            "Server: debian\r\n"
            "Content-length: 9\r\n"
            "\r\n"
            "test-data"
        ),
    }
    for num in range(2, 4)
]

SRV_GRP3 = [
    {
        "id": f"server{num}",
        "type": "deproxy",
        "port": f"800{num}",
        "response": "static",
        "response_content": (
            "HTTP/1.1 200 OK\r\n"
            "From: /server3\r\n"
            "Server: debian\r\n"
            "Content-length: 9\r\n"
            "\r\n"
            "test-data"
        ),
    }
    for num in range(4, 6)
]


class TestReconfHealthMonitor(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    backends = SRV_GRP1 + SRV_GRP2 + SRV_GRP3

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def test_reconf_add_hm(self):
        self.start_all_servers()
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(TEMPESTA_CONFIG)
        self.start_tempesta()

        tempesta.config.set_defconfig(TEMPESTA_CONFIG_ADD_HM)
        tempesta.reload()

    def test_reconf_add_srv_group(self):
        self.start_all_servers()
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(TEMPESTA_CONFIG_ADD_HM)
        self.start_tempesta()

        tempesta.config.set_defconfig(TEMPESTA_CONFIG_ADD_SRV_GROUP)
        tempesta.reload()

    def test_reconf_del_srv_group(self):
        self.start_all_servers()
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(TEMPESTA_CONFIG_ADD_SRV_GROUP)
        self.start_tempesta()

        tempesta.config.set_defconfig(TEMPESTA_CONFIG_DEL_SRV_GROUP)
        tempesta.reload()

    def test_reconf_del_hm(self):
        self.start_all_servers()
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(TEMPESTA_CONFIG_ADD_HM)
        self.start_tempesta()

        tempesta.config.set_defconfig(TEMPESTA_CONFIG)
        tempesta.reload()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
