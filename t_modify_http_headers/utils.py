__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class AddHeaderBase(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    request: str or list
    cache: bool
    directive: str

    def update_tempesta_config(self, config: str):
        tempesta = self.get_tempesta()
        cache = "cache 2;\ncache_fulfill * *;\n" if self.cache else "cache 0;"
        tempesta.config.defconfig += config + "\n" + cache

    def base_scenario(self, config: str, expected_headers: list):
        client = self.get_client("deproxy-1")
        server = self.get_server("deproxy")

        self.update_tempesta_config(config=config)

        self.start_all_services()

        for _ in range(2 if self.cache else 1):
            client.send_request(self.request, "200")

            for header in expected_headers:
                if self.directive in ["req_hdr_set", "req_hdr_add"]:
                    self.assertIn(header[1], list(server.last_request.headers.find_all(header[0])))
                    self.assertNotIn(
                        header[1], list(client.last_response.headers.find_all(header[0]))
                    )
                else:
                    self.assertIn(header[1], list(client.last_response.headers.find_all(header[0])))
                    self.assertNotIn(
                        header[1], list(server.last_request.headers.find_all(header[0]))
                    )

        return client, server


class H2Config:
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":authority", "localhost"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
