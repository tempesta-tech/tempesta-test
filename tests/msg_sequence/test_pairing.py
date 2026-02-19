"""
Test for 'Paired request missing, HTTP Response Splitting attack?' error
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.helpers import dmesg
from framework.test_suite import tester
from framework.test_suite.marks import parameterize_class

DEPROXY_CLIENT = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class PairingTest(tester.TempestaTest):
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

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    @dmesg.unlimited_rate_on_tempesta_node
    async def test_disconnect_client(self):
        """Tempesta forwards requests from client to backend, but client
        disconnects before Tempesta received responses from backend. Responses
        must be evicted, no 'Paired request missing' messages are allowed.
        """

        chain_size = 2
        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        request = client.create_request(method="GET", headers=[])
        for _ in range(chain_size):
            client.make_request(request)

        await server.wait_for_requests(n=chain_size, strict=True)
        client.stop()

        server.set_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        client.start()
        await client.send_request(request, "200")

        self.assertTrue(
            await self.loggers.dmesg.find(dmesg.WARN_SPLIT_ATTACK, cond=dmesg.amount_zero),
            msg=("Got '%s'" % dmesg.WARN_SPLIT_ATTACK),
        )
