from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import os
from helpers import dmesg
from .common import AccessLogLine
from framework.x509 import CertGenerator


def backends(status_code):
    return [
        {
            'id': 'nginx',
            'type': 'nginx',
            'port': '8000',
            'status_uri': 'http://${server_ip}:8000/nginx_status',
            'config':
                """
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
                """ % (status_code,
                       "" if status_code / 100 != 3 else " http://non-existent-site")
        }
    ]


def tempesta(extra=''):
    return {
        'config':
            """
           listen 443 proto=h2;
           access_log on;
           %s

            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/cert.pem;
            tls_certificate_key ${tempesta_workdir}/key.pem;

           """ % extra
    }


def clients(uri='/'):
    return [
        {
            'id': 'curl',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': (
                    '-k '
                    'https://${tempesta_ip}%s ' % uri
            )
        },
    ]


def gen_cert(host_name):
    cert_path = "/tmp/tempesta/cert.pem"
    key_path = "/tmp/tempesta/key.pem"
    cgen = CertGenerator(cert_path, key_path)
    cgen.CN = host_name
    cgen.generate()


def remove_certs(cert_files_):
    for cert in cert_files_:
        os.remove(cert)


# Some tests for access_log over HTTP/2.0
class CurlTestBase(tester.TempestaTest):
    clients = clients()
    
    def run_curl(self):
        curl = self.get_client('curl')
        curl.run_start()
        curl.proc_results = curl.resq.get(True, 1)
        self.assertEqual(0, curl.returncode,
                         msg=("Curl return code is not 0 (%d)." %
                              (curl.returncode)))

    def run_test(self, status_code=200, is_frang=False):
        klog = dmesg.DmesgFinder(ratelimited=False)
        curl = self.get_client('curl')
        referer = 'http2-referer-%d' % status_code
        user_agent = 'http2-user-agent-%d' % status_code
        curl.options.append('-e "%s"' % referer)
        curl.options.append('-A "%s"' % user_agent)
        gen_cert('127.0.0.1')
        self.start_all_servers()
        self.start_tempesta()

        if is_frang:
            try:
                self.run_curl()
            except Exception:
                pass
        else:
            self.run_curl()

        nginx = self.get_server('nginx')
        nginx.get_stats()
        self.assertEqual(0 if is_frang else 1, nginx.requests,
                         msg="Unexpected number forwarded requests to backend")
        msg = AccessLogLine.from_dmesg(klog)
        self.assertTrue(msg is not None, "No access_log message in dmesg")
        self.assertEqual(msg.method, 'GET', 'Wrong method')
        self.assertEqual(msg.status, status_code, 'Wrong HTTP status')
        self.assertEqual(msg.user_agent, user_agent)
        self.assertEqual(msg.referer, referer)
        remove_certs(["/tmp/tempesta/key.pem", "/tmp/tempesta/cert.pem"])
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
    tempesta = tempesta("""
            frang_limits {
                ip_block off;
                http_uri_len 10;
            }
    """)
    clients = clients('/some-uri-longer-than-10-symbols')

    def test_tempesta(self):
        msg = self.run_test(403, True)
        self.assertEqual(msg.uri, '/some-uri-longer-than-10-symbols')


class TruncateUriTest(CurlTestBase):
    backends = backends(200)
    tempesta = tempesta()
    base_uri = '/truncated-uri'
    clients = clients(base_uri + '_' * 1000)

    def test_tempesta(self):
        msg = self.run_test(200)
        self.assertEqual(msg.uri[:len(self.base_uri)], self.base_uri,
                         'Invalid URI')
        self.assertEqual(msg.uri[-3:], '...',
                         'URI does not look like truncated')
