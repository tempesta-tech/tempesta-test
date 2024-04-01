"""
Functional test for hash scheduler. Requested URI must be pinned to specific
server connection, thus repeated request to the same URI will go to the same
server connection.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class HashScheduler(tester.TempestaTest):
    backends_count = 5

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 2147483647;

sched hash;
cache 0;
"""
        + "".join("server ${server_ip}:800%s;\n" % step for step in range(backends_count))
    }

    backends = [
        {
            "id": f"deproxy-{step}",
            "type": "deproxy",
            "port": f"800{step}",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nServer: deproxy\r\n\r\n"),
        }
        for step in range(backends_count)
    ]

    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    # Total number of requests
    messages = 100
    # Number of different Uris
    uri_n = 10

    def test_hash_scheduler(self):
        """Check that the same server connection is used for the same resource."""
        client = self.get_client("deproxy")

        self.start_all_services()

        for _ in range(self.messages):
            for uri in range(self.uri_n):
                client.make_request(self._generate_request(uri))

        client.wait_for_response()

        self.__check_distribution_of_requests()

    @staticmethod
    def _generate_request(uri):
        return f"GET /resource-{uri} HTTP/1.1\r\nHost: localhost\r\n\r\n"

    def __check_distribution_of_requests(self):
        uri_list = list()
        for step in range(self.backends_count):
            server = self.get_server(f"deproxy-{step}")
            requests_uri = set()
            for request in server.requests:
                requests_uri.add(request.uri[-1])
            uri_list.extend(requests_uri)

        for uri in range(self.uri_n):
            self.assertEqual(
                uri_list.count(str(uri)), 1, "Tempesta sent request to another backends."
            )
