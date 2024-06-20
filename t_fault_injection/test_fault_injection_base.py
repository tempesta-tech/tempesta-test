"""Bpf tests to check error handlings."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.parameterize import param, parameterize
from framework.x509 import CertGenerator
from helpers import dmesg, remote


class TestFailFunction(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy_h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000;
        """
    }

    @parameterize.expand(
        [
            param(name="tfw_cli_conn_alloc", id="deproxy", msg="can't allocate a new client connection", retval=0),
            param(name="tfw_client_obtain", id="deproxy", msg="can't obtain a client for frang accounting", retval=0),
            param(name="tfw_h2_context_init", id="deproxy_h2", msg="cannot establish a new h2 connection", retval=-12)
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, id, msg, retval):
        """
        Basic test to check how Tempesta FW works when some internal
        function fails. Function should be marked as ALLOW_ERROR_INJECTION
        in Tempesta FW source code.
        """
        self.start_all_services(client=False)

        # Write function name to special debug fs file. 
        cmd = f"echo {name} > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)
        # Write return code, which this function should return instead of
        # real return code.
        cmd = f"printf %#x {retval} > /sys/kernel/debug/fail_function/{name}/retval"
        out = remote.client.run_cmd(cmd)

        # Write probability in percent. 100 - function never executed
        # and return previously set return code every time, while error
        # injection works.
        cmd = "echo 100 > /sys/kernel/debug/fail_function/probability"
        out = remote.client.run_cmd(cmd)
        # If probability is equal to 100 should always be equal to zero.
        cmd = "echo 0 > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Specifies how many times failures may happen at most.
        # A value of -1 means “no limit”.
        cmd = "printf %#x -1 > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)

        client = self.get_client(id)
        request = client.create_request(method="GET", headers=[])
        client.start()

        self.oops_ignore = ["ERROR"]
        client.make_request(request)
        self.assertFalse(client.wait_for_response(3))
        self.assertTrue(client.wait_for_connection_close())

        # Disable error injection
        cmd = "echo 0 > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)
        # Remove function from fault injection list
        cmd = "echo > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)

        self.assertTrue(
            self.oops.find(msg, cond=dmesg.amount_positive),
            "Tempesta doesn't report error",
        )
