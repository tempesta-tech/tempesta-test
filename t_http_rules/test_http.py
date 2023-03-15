"""
Set of tests to verify HTTP rules processing correctness (in one HTTP chain).
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers import checks_for_tests as checks


class HttpRules(tester.TempestaTest):
    options = [
        ("uri_p", "/static/index.html", None, None),
        ("uri_s", "/script.php", None, None),
        ("host_p", "/", "host", "static.example.com"),
        ("host_s", "/", "host", "s.tempesta-tech.com"),
        ("host_e", "/", "host", "foo.example.com"),
        ("hdr_h_p", "/", "host", "bar.example.com"),
        ("hdr_h_s", "/", "host", "test.natsys-lab.com"),
        ("hdr_h_e", "/", "host", "buzz.natsys-lab.com"),
        ("hdr_r_e", "/", "referer", "example.com"),
        ("hdr_r_s", "/", "referer", "http://example.com"),
        ("hdr_r_p", "/", "referer", "http://example.com/cgi-bin/show.pl"),
        ("hdr_raw_e", "/", "from", "testuser@example.com"),
        ("hdr_raw_p", "/", "warning", "172 misc warning"),
        ("default", "/", None, None),
    ]

    tempesta = {
        "config": """
listen 80;        
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

srv_group uri_p {server ${server_ip}:8000;}
srv_group uri_s {server ${server_ip}:8001;}
srv_group host_p {server ${server_ip}:8002;}
srv_group host_s {server ${server_ip}:8003;}
srv_group host_e {server ${server_ip}:8004;}
srv_group hdr_h_p {server ${server_ip}:8005;}
srv_group hdr_h_s {server ${server_ip}:8006;}
srv_group hdr_h_e {server ${server_ip}:8007;}
srv_group hdr_r_e {server ${server_ip}:8008;}
srv_group hdr_r_s {server ${server_ip}:8009;}
srv_group hdr_r_p {server ${server_ip}:8010;}
srv_group hdr_raw_e {server ${server_ip}:8011;}
srv_group hdr_raw_p {server ${server_ip}:8012;}
server ${server_ip}:8013;

vhost uri_p {proxy_pass uri_p;}
vhost uri_s {proxy_pass uri_s;}
vhost host_p {proxy_pass host_p;}
vhost host_s {proxy_pass host_s;}
vhost host_e {proxy_pass host_e;}
vhost hdr_h_p {proxy_pass hdr_h_p;}
vhost hdr_h_s {proxy_pass hdr_h_s;}
vhost hdr_h_e {proxy_pass hdr_h_e;}
vhost hdr_r_e {proxy_pass hdr_r_e;}
vhost hdr_r_s {proxy_pass hdr_r_s;}
vhost hdr_r_p {proxy_pass hdr_r_p;}
vhost hdr_raw_e {proxy_pass hdr_raw_e;}
vhost hdr_raw_p {proxy_pass hdr_raw_p;}
vhost default {proxy_pass default;}

http_chain {
  uri == "/static*" -> uri_p;
  uri == "*.php" -> uri_s;
  host == "static.*" -> host_p;
  host == "*tempesta-tech.com" -> host_s;
  host == "foo.example.com" -> host_e;
  hdr Host == "bar.*" -> hdr_h_p;
  hdr host == "buzz.natsys-lab.com" -> hdr_h_e;
  hdr Host == "*natsys-lab.com" -> hdr_h_s;
  hdr Referer ==  "example.com" -> hdr_r_e;
  hdr Referer ==  "*.com" -> hdr_r_s;
  hdr referer ==  "http://example.com*" -> hdr_r_p;
  hdr From ==  "testuser@example.com" -> hdr_raw_e;
  hdr Warning ==  "172 *" -> hdr_raw_p;
  -> default;
}
"""
    }

    backends = [
        {
            "id": step,
            "type": "deproxy",
            "port": f"800{step}" if step < 10 else f"80{step}",
            "response": "static",
            "response_content": "",
        }
        for step in range(len(options))
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    requests_n = 1

    def test_scheduler(self):
        """
        All requests must be forwarded to the right vhosts and
        server groups according to rule in http_chain.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        for _ in range(self.requests_n):
            step = 0
            for option in self.options:
                server = self.get_server(step)
                server.set_response(
                    "HTTP/1.1 200 OK\r\n"
                    + "Date: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
                    + "Connection: keep-alive\r\n"
                    + "Server: deproxy\r\n"
                    + f"Content-Length: {step}\r\n\r\n"
                    + ("x" * step)
                )

                client.send_request(
                    self.request_with_options(
                        path=option[1],
                        header_name=option[2] if option[2] is not None else "",
                        header_value=option[3],
                    ),
                    "200",
                )

                self.assertIsNotNone(server.last_request)
                self.assertIn(option[1], str(server.last_request))
                if option[2] is not None:
                    self.assertIn(option[3], str(server.last_request))

                self.assertEqual("x" * step, client.last_response.body)

                step += 1

    @staticmethod
    def request_with_options(path, header_name, header_value):
        host_header = "Host: localhost\r\n" if header_name.lower() != "host" else ""
        optional_header = f"{header_name}: {header_value}\r\n" if header_name else ""
        return (
            f"GET {path} HTTP/1.1\r\n"
            + host_header
            + optional_header
            + "Connection: keep-alive\r\n\r\n"
        )


class HttpRulesH2(HttpRules):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    requests_n = 2  # client send headers as bytes from dynamic table

    def test_scheduler(self):
        super(HttpRulesH2, self).test_scheduler()

    @staticmethod
    def request_with_options(path, header_name, header_value):
        request = [
            (":path", path),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        if header_name.lower() != "host":
            request.append((":authority", "localhost"))
        if header_name:
            request.append((header_name.lower(), header_value))

        return request


class HttpRulesBackupServers(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;        
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;
srv_group primary {server ${server_ip}:8000;}
srv_group backup {server ${server_ip}:8001;}

vhost host {
    proxy_pass primary backup=backup;
}
http_chain {
    -> host;
}
"""
    }

    backends = [
        {
            "id": "primary",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
        {
            "id": "backup",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    request = f"GET / HTTP/1.1\r\n" + "Host: debian\r\n\r\n"

    def test_scheduler(self):
        """
        Tempesta must forward requests to backup server if primary server is disabled.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        primary_server = self.get_server("primary")
        backup_server = self.get_server("backup")

        client.send_request(self.request, "200")
        got_requests = len(primary_server.requests)

        primary_server.stop()
        client.send_request(self.request, "200")

        primary_server.start()
        primary_server.wait_for_connections(3)
        client.send_request(self.request, "200")
        got_requests += len(primary_server.requests)

        self.assertEqual(2, got_requests)
        self.assertEqual(1, len(backup_server.requests))
        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_received=3,
            cl_msg_forwarded=3,
            srv_msg_received=3,
            srv_msg_forwarded=3,
        )


class HttpRulesBackupServersH2(HttpRulesBackupServers):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def test_scheduler(self):
        super(HttpRulesBackupServersH2, self).test_scheduler()
