import unittest

from framework import docker_server, tester
from framework.curl_client import CurlResponse
from helpers import tf_cfg

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))


class TestTempestaTechSite(tester.TempestaTest):
    backends = [
        {
            "id": "tempesta_tech_site",
            "type": "lxc",
            "container_name": "tempesta-site-stage",
            "ports": {8003: 80},
            "server_ip": "192.168.122.53",
            "healthcheck_command": "curl --fail localhost",
        },
    ]

    clients = [
        {
            "id": "get",
            "type": "curl",
            "headers": {
                "Host": "tempesta-tech.com",
            },
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2;

            cache 2;
            cache_fulfill * *;
            cache_methods GET HEAD;
            cache_purge;
            # Allow purging from the containers (upstream), localhost (VM) and the host.
            cache_purge_acl ${server_ip} 127.0.0.1 192.168.122.1;

            access_log on;

            frang_limits {
                    request_rate 200;
                    http_method_override_allowed true;
                    http_methods post put get;
            }

            block_action attack reply;
            block_action error reply;

            # Make WordPress to work over TLS.
            # See https://tempesta-tech.com/knowledge-base/WordPress-tips-and-tricks/
            req_hdr_add X-Forwarded-Proto "https";

            resp_hdr_set Strict-Transport-Security "max-age=31536000; includeSubDomains";

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group default {
                    server ${server_ip}:8003;
            }

            vhost default {
                    tls_match_any_server_name;
                    proxy_pass default;
            }

            http_chain {
                # Redirect old URLs from the old static website
                uri == "/index"		-> 301 = /;
                uri == "/development-services" -> 301 = /network-security-performance-analysis;

                # Proably outdated redirects
                uri == "/index.html"	-> 301 = /;
                uri == "/services"	-> 301 = /development-services;
                uri == "/services.html"	-> 301 = /development-services;
                uri == "/c++-services"	-> 301 = /development-services;
                uri == "/company.html"	-> 301 = /company;
                uri == "/blog/fast-programming-languages-c-c++-rust-assembly" -> 301 = /blog/fast-programming-languages-c-cpp-rust-assembly;

                    -> default;
            }
        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(10))

    def restart_client(self, client):
        if client.is_running():
            client.stop()
        client.start()
        if not client.is_running():
            raise Exception("Can not start client")

    def get_response(self, client) -> CurlResponse:
        self.restart_client(client)
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def test_get_resource(self):
        self.start_all()
        client = self.get_client("get")
        for uri, expected_code in [
            ("/license.txt", 200),
            ("/wp-content/uploads/2023/10/tfw_wp_http2-150x150.png", 200),  # small image
            ("/wp-content/uploads/2023/10/tfw_wp_http2-1536x981.png", 200),  # large image
            ("/", 200),  # index
            ("/knowledge-base/DDoS-mitigation/", 200),  # blog post
            # ("/?page_id=2", 200),  # page
            # ("/generated.php", 200),
            ("/404-absolutely/doesnt-exist", 404),
        ]:
            with self.subTest("GET", uri=uri):
                client.set_uri(uri)
                response = self.get_response(client)
                self.assertEqual(response.status, expected_code, response)
                self.assertFalse(response.stderr)
                length = response.headers.get("content-length")
                if length:
                    self.assertEqual(len(response.stdout_raw), int(length))
                self.assertNotIn("age", response.headers)
