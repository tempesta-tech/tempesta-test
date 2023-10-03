"""
Tests for match SNI and host.
"""

from framework import tester
from helpers import dmesg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TLSMatchHostSni(tester.TempestaTest):
    clients = [
        {
            "id": "usual-client",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
            cache 0;
            listen 443 proto=https;

            frang_limits {
                http_strict_host_checking;
            }

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group srv_grp1 {
                server ${server_ip}:8000;
            }
            vhost tempesta-tech.com {
                proxy_pass srv_grp1;
            }
            # needed to trigger "vhost mismatch" event
            vhost dummy {
                proxy_pass srv_grp1;
            }
            # Any request can be served.
            http_chain {
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> dummy;
            }
        """
    }

    TLS_WARN = "Warning: frang: vhost by SNI doesn't match vhost by authority"

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server("0")
        self.assertTrue(srv.wait_for_connections(timeout=1))

    def test_host_sni_mismatch(self):
        """With the `http_strict_host_checking` limit, the host header and SNI name
        must be identical. Otherwise request will be filtered. After client
        send a request that doesnt match his SNI, t is blocked
        """
        self.start_all()
        klog = dmesg.DmesgFinder(disable_ratelimit=True)

        deproxy_cl = self.get_client("usual-client")
        deproxy_cl.start()

        # case 1 (sni match)
        deproxy_cl.make_request(("GET / HTTP/1.1\r\n" "Host: tempesta-tech.com\r\n" "\r\n"))
        deproxy_cl.wait_for_response()
        self.assertEqual(1, len(deproxy_cl.responses))

        # case 2 (sni mismatch)
        deproxy_cl.make_request(("GET / HTTP/1.1\r\n" "Host: example.com\r\n" "\r\n"))
        deproxy_cl.wait_for_response()
        self.assertEqual(1, len(deproxy_cl.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertTrue(klog.find(self.TLS_WARN), "Frang limits warning is not shown")
