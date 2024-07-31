"""
Test TempestaFW reeboot under load.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers import remote, sysnet, tf_cfg


class TestReplay(tester.TempestaTest):
    clients = [
        {"id": "tcpreplay", "type": "external", "binary": "tcpreplay", "ssl": True, "cmd_args": ""}
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8080",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-length: 0\r\n" "\r\n"),
        },
        {
            "id": "deproxy_h2",
            "type": "deproxy",
            "port": "8443",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-length: 0\r\n" "\r\n"),
        },
    ]

    tempesta = {
        "config": """
            listen 192.168.122.100:443 proto=https,h2;
            listen 192.168.122.100:80 proto=http;

            access_log on;

            block_action attack reply;
            block_action error reply;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            srv_group h2 {
                server ${server_ip}:8443;
            }
            srv_group http {
                server ${server_ip}:8080;
            }

            vhost h2 {
                proxy_pass h2;
            }

            vhost http {
                proxy_pass http;
            }

            http_chain {
                mark == 1 -> http;
                ->h2;
            }
        """
    }

    def test_replay(self) -> None:
        self.start_all_services(client=False)

        ETH = sysnet.route_dst_ip(remote.tempesta, tf_cfg.cfg.get("Tempesta", "ip"))
        tcpreplay = self.get_client("tcpreplay")
        tcpreplay.options = [f"-i ens4 /tmp/tcpdump/replay.pcap"]

        tcpreplay.start()
        self.wait_while_busy(tcpreplay, timeout=100)
        tcpreplay.stop()

        print(tcpreplay.response_msg)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
