"""
TLS Stress tests - load Tempesta FW with multiple TLS connections.
"""

from helpers import dmesg, remote
from helpers.x509 import CertGenerator
from run_config import CONCURRENT_CONNECTIONS, DURATION, THREADS
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


class StressTls(tester.TempestaTest):
    backends = [
        {
            "id": "0",
            "type": "nginx",
            "check_ports": [
                {
                    "ip": "${server_ip}",
                    "port": "8000",
                }
            ],
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
                pid ${pid};
                worker_processes    auto;
                events {
                    worker_connections 1024;
                    use epoll;
                }
                http {
                    keepalive_timeout ${server_keepalive_timeout};
                    keepalive_requests ${server_keepalive_requests};
                    sendfile        on;
                    tcp_nopush      on;
                    tcp_nodelay     on;
                    open_file_cache max=1000;
                    open_file_cache_valid 30s;
                    open_file_cache_min_uses 2;
                    open_file_cache_errors off;
                    error_log /dev/null emerg;
                    access_log off;
                    server {
                        listen       ${server_ip}:8000;
                        location / {
                            return 200;
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
            "id": "0",
            "type": "wrk",
            "addr": "${tempesta_ip}:443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;

            # wrk sends IP address in SNI, so we test the option here.
            tls_match_any_server_name;
            frang_limits {http_strict_host_checking false;}

            server ${server_ip}:8000;
        """
    }

    @dmesg.limited_rate_on_tempesta_node
    def test(self):
        self.start_all_servers()
        self.start_tempesta()

        wrk = self.get_client("0")
        wrk.set_script("foo", content="")
        # Wrk can't handle very big amound of TLS connections.
        wrk.connections = min(int(CONCURRENT_CONNECTIONS), 100)
        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()

        self.assertTrue(200 in wrk.statuses)
        self.assertGreater(wrk.statuses[200], 0)


class TlsHandshakeDheRsaTest(tester.TempestaTest):
    clients = [
        {
            "id": "tls-perf-DHE-RSA-AES128-GCM-SHA256",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": (
                "-c DHE-RSA-AES128-GCM-SHA256 -C prime256v1 -l %s -t %s -T %s ${tempesta_ip} 443"
                % (CONCURRENT_CONNECTIONS, THREADS, DURATION)
            ),
        },
        {
            "id": "tls-perf-DHE-RSA-AES256-GCM-SHA384",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": (
                "-c DHE-RSA-AES256-GCM-SHA384 -C prime256v1 -l %s -t %s -T %s ${tempesta_ip} 443"
                % (CONCURRENT_CONNECTIONS, THREADS, DURATION)
            ),
        },
        {
            "id": "tls-perf-DHE-RSA-AES128-CCM",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": (
                "-c DHE-RSA-AES128-CCM -C prime256v1 -l %s -t %s -T %s ${tempesta_ip} 443"
                % (CONCURRENT_CONNECTIONS, THREADS, DURATION)
            ),
        },
        {
            "id": "tls-perf-DHE-RSA-AES256-CCM",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": (
                "-c DHE-RSA-AES256-CCM -C prime256v1 -l %s -t %s -T %s ${tempesta_ip} 443"
                % (CONCURRENT_CONNECTIONS, THREADS, DURATION)
            ),
        },
    ]

    tempesta_tmpl = """
        cache 0;
        listen 443 proto=https;

        tls_certificate %s;
        tls_certificate_key %s;
        tls_match_any_server_name;

        srv_group srv_grp1 {
            server ${server_ip}:8000;
        }
        vhost tempesta-tech.com {
            proxy_pass srv_grp1;
        }
        http_chain {
            host == "tempesta-tech.com" -> tempesta-tech.com;
            -> block;
        }
    """

    def setUp(self):
        self.cgen = CertGenerator()
        self.cgen.key = {"alg": "rsa", "len": 4096}
        self.cgen.sign_alg = "sha256"
        self.cgen.generate()

        cert_path, key_path = self.cgen.get_file_paths()
        remote.tempesta.copy_file(cert_path, self.cgen.serialize_cert().decode())
        remote.tempesta.copy_file(key_path, self.cgen.serialize_priv_key().decode())

        self.tempesta = {
            "config": self.tempesta_tmpl % (cert_path, key_path),
            "custom_cert": True,
        }
        tester.TempestaTest.setUp(self)

    def check_alg(self, alg):
        tls_perf = self.get_client(alg)

        self.start_all_servers()
        self.start_tempesta()
        tls_perf.start()
        self.wait_while_busy(tls_perf)
        tls_perf.stop()

        self.assertFalse(tls_perf.stderr)

    def test_DHE_RSA_AES128_GCM_SHA256(self):
        self.check_alg("tls-perf-DHE-RSA-AES128-GCM-SHA256")

    def test_DHE_RSA_AES256_GCM_SHA384(self):
        self.check_alg("tls-perf-DHE-RSA-AES256-GCM-SHA384")

    def test_DHE_RSA_AES128_CCM(self):
        self.check_alg("tls-perf-DHE-RSA-AES128-CCM")

    def test_DHE_RSA_AES256_CCM(self):
        self.check_alg("tls-perf-DHE-RSA-AES256-CCM")


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
