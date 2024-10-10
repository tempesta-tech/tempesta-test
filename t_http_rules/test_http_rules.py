"""
Set of tests to verify HTTP rules processing correctness (in one HTTP chain).
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from test_suite import tester


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
frang_limits {http_strict_host_checking false;}
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
        client.server_hostname = "tempesta-tech.com"
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


class TestHostBase(tester.TempestaTest):
    tempesta = {
        "config": """
    listen 80;        
    listen 443 proto=h2;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;

    srv_group req_host {server ${server_ip}:8000;}
    srv_group host_header {server ${server_ip}:8001;}
    srv_group bad {server ${server_ip}:8002;}

    frang_limits {http_strict_host_checking false;}
    vhost req_host {proxy_pass req_host;}
    vhost host_header {proxy_pass host_header;}
    vhost bad {proxy_pass bad;}


    http_chain {
      host == "*tempesta-tech.com" -> req_host;
      hdr host == "*natsys-lab.com" -> host_header;
      -> bad;
    }
    """
    }

    backends = [
        {
            "id": step,
            "type": "deproxy",
            "port": f"800{step}" if step < 10 else f"80{step}",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
                + "Connection: keep-alive\r\n"
                + "Server: deproxy\r\n"
                + f"Content-Length: 0\r\n\r\n"
            ),
        }
        for step in range(3)
    ]

    def send_request_and_check_server_request(self, request: str or list, server_id: int):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(request, "200")

        server = self.get_server(server_id)
        self.assertIsNotNone(
            server.last_request, "Tempesta forwarded request without following http_tables."
        )


class TestHost(TestHostBase):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_host_in_uri(self):
        """Host from url has first priority."""
        self.send_request_and_check_server_request(
            request=(f"GET http://tempesta-tech.com/ HTTP/1.1\r\n" + "Host: badhost\r\n" + "\r\n"),
            server_id=0,
        )

    def test_hdr_host_in_uri(self):
        """Host from url is not `hdr host`."""
        self.send_request_and_check_server_request(
            request=(f"GET http://natsys-lab.com/ HTTP/1.1\r\n" + "Host: badhost\r\n" + "\r\n"),
            server_id=2,
        )

    def test_host_in_host_header(self):
        """Host header has second priority."""
        self.send_request_and_check_server_request(
            request=(f"GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
            server_id=0,
        )

    def test_host_in_forwarded_header(self):
        """Forwarded header does not override host."""
        self.send_request_and_check_server_request(
            request=(
                f"GET / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Forwarded: host=tempesta-tech.com\r\n"
                + "\r\n"
            ),
            server_id=2,
        )

    def test_hdr_host_in_forwarded_header(self):
        """Forwarded header does not override host header."""
        self.send_request_and_check_server_request(
            request=(
                f"GET / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Forwarded: host=natsys-lab.com\r\n"
                + "\r\n"
            ),
            server_id=2,
        )

    def test_forwarded_header_first(self):
        """Forwarded header does not set hdr host."""
        self.send_request_and_check_server_request(
            request=(
                f"GET / HTTP/1.1\r\n"
                + "Forwarded: host=natsys-lab.com\r\n"
                + "Host: localhost\r\n"
                + "\r\n"
            ),
            server_id=2,
        )

    def test_forwarded_header_first_2(self):
        """Forwarded header does not set host."""
        self.send_request_and_check_server_request(
            request=(
                f"GET / HTTP/1.1\r\n"
                + "Forwarded: host=tempesta-tech.com\r\n"
                + "Host: localhost\r\n"
                + "\r\n"
            ),
            server_id=2,
        )

    def test_different_host_in_uri_and_host_header(self):
        """Host from url has priority over headers."""
        self.send_request_and_check_server_request(
            request=(f"GET http://natsys-lab.com/ HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"),
            server_id=2,
        )
