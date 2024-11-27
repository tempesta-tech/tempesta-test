from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from helpers import dmesg, remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator

from .common import AccessLogLine


def backends(status_code):
    return [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
                pid ${pid};
                worker_processes  auto;

                events {
                    worker_connections   1024;
                    use epoll;
                }

                http {
                    keepalive_timeout ${server_keepalive_timeout};
                    keepalive_requests ${server_keepalive_requests};
                    sendfile         on;
                    tcp_nopush       on;
                    tcp_nodelay      on;

                    open_file_cache max=1000;
                    open_file_cache_valid 30s;
                    open_file_cache_min_uses 2;
                    open_file_cache_errors off;

                    # [ debug | info | notice | warn | error | crit | alert | emerg ]
                    # Fully disable log errors.
                    error_log /dev/null emerg;

                    # Disable access log altogether.
                    access_log off;

                    server {
                        listen        ${server_ip}:8000;

                        location / {
                            return %d%s;
                        }
                        location /nginx_status {
                            stub_status on;
                        }
                    }
                }
                """
            % (status_code, "" if status_code / 100 != 3 else " http://non-existent-site"),
        }
    ]


def tempesta(extra=""):
    return {
        "config": """
           listen 443 proto=h2;
           access_log dmesg;
           %s

            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

           """
        % extra
    }


def clients(uri="/"):
    return [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-k "
                " --resolve tempesta-tech.com:443:${tempesta_ip} https://tempesta-tech.com%s" % uri
            ),
        },
    ]


def generate_certificate(cn="tempesta-tech.com", san=None, cert_name="tempesta"):
    """Generate and upload certificate with given
    common name and  list of Subject Alternative Names.
    Name generated files as `cert_name`.crt and `cert_name`.key.
    """
    workdir = tf_cfg.cfg.get("Tempesta", "workdir")

    cgen = CertGenerator(
        cert_path=f"{workdir}/{cert_name}.crt", key_path=f"{workdir}/{cert_name}.key"
    )
    cgen.CN = cn
    cgen.san = san
    cgen.generate()

    cert_path, key_path = cgen.get_file_paths()
    remote.tempesta.copy_file(cert_path, cgen.serialize_cert().decode())
    remote.tempesta.copy_file(key_path, cgen.serialize_priv_key().decode())

    return cgen


def remove_certs(cert_files_):
    for cert in cert_files_:
        os.remove(cert)


# Some tests for access_log over HTTP/2.0
class CurlTestBase(tester.TempestaTest):
    clients = clients()

    def run_curl(self, curl):
        self.start_all_clients()
        self.wait_while_busy(curl)
        self.assertEqual(
            0,
            curl.returncode,
            msg=("Curl return code is not 0. Received - {0}.".format(curl.returncode)),
        )
        curl.stop()

    def run_test(self, status_code=200, is_frang=False):
        klog = dmesg.DmesgFinder(disable_ratelimit=True)
        curl = self.get_client("curl")
        referer = "http2-referer-%d" % status_code
        user_agent = "http2-user-agent-%d" % status_code
        curl.options.append('-e "%s"' % referer)
        curl.options.append('-A "%s"' % user_agent)
        generate_certificate()
        self.start_all_servers()
        self.start_tempesta()

        if is_frang:
            try:
                self.run_curl(curl)
            except Exception:
                pass
        else:
            self.run_curl(curl)

        nginx = self.get_server("nginx")
        nginx.get_stats()
        self.assertEqual(
            0 if is_frang else 1,
            nginx.requests,
            msg="Unexpected number forwarded requests to backend",
        )
        msg = AccessLogLine.from_dmesg(klog)
        self.assertTrue(msg is not None, "No access_log message in dmesg")
        self.assertEqual(msg.method, "GET", "Wrong method")
        self.assertEqual(msg.status, status_code, "Wrong HTTP status")
        self.assertEqual(msg.user_agent, user_agent)
        self.assertEqual(msg.referer, referer)
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        remove_certs([f"{workdir}/tempesta.crt", f"{workdir}/tempesta.key"])
        return msg


class Response200Test(CurlTestBase):
    backends = backends(200)
    tempesta = tempesta()

    def test_tempesta(self):
        self.run_test(200)


class Response204Test(CurlTestBase):
    backends = backends(204)
    tempesta = tempesta()

    def test_tempesta(self):
        self.run_test(204)


class Response302Test(CurlTestBase):
    backends = backends(302)
    tempesta = tempesta()

    def test_tempesta(self):
        self.run_test(302)


class Response404Test(CurlTestBase):
    backends = backends(404)
    tempesta = tempesta()

    def test_tempesta(self):
        self.run_test(404)


class Response500Test(CurlTestBase):
    backends = backends(500)
    tempesta = tempesta()

    def test_tempesta(self):
        self.run_test(500)


class FrangTest(CurlTestBase):
    backends = backends(200)
    tempesta = tempesta(
        """
            frang_limits {
                ip_block off;
                http_uri_len 10;
            }
    """
    )
    clients = clients("/some-uri-longer-than-10-symbols")

    def test_tempesta(self):
        msg = self.run_test(403, True)
        self.assertEqual(msg.uri, "/some-uri-longer-than-10-symbols")


class TruncateUriTest(CurlTestBase):
    backends = backends(200)
    tempesta = tempesta()
    base_uri = "/truncated-uri"
    clients = clients(base_uri + "_" * 1000)

    def test_tempesta(self):
        msg = self.run_test(200)
        self.assertEqual(msg.uri[: len(self.base_uri)], self.base_uri, "Invalid URI")
        self.assertEqual(msg.uri[-3:], "...", "URI does not look like truncated")
