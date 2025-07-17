"""Bpf tests to check error handlings."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
import threading

from h2.connection import ConnectionInputs
from hyperframe.frame import HeadersFrame, PingFrame, WindowUpdateFrame

from framework.deproxy_client import HuffmanEncoder
from helpers import deproxy, dmesg, remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
from helpers.error import ProcessBadExitStatusException
from helpers.deproxy import HttpMessage
from helpers.networker import NetWorker
from test_suite import marks, sysnet, tester
from test_suite.custom_error_page import CustomErrorPageGenerator

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))
# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))


class TestFailFunctionBase(tester.TempestaTest):
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
            "id": "deproxy_ssl",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
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
            listen 443 proto=h2,https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000 conns_n=1;
            
            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    def tearDown(self):
        self.teardown_fail_function_test()
        tester.TempestaTest.tearDown(self)

    @staticmethod
    def setup_fail_page_alloc(times, probability, interval, space):
        cmd = f"echo {probability} > /sys/kernel/debug/fail_page_alloc/probability"
        out = remote.client.run_cmd(cmd)
        cmd = f"echo {interval} > /sys/kernel/debug/fail_page_alloc/interval"
        out = remote.client.run_cmd(cmd)
        cmd = f"echo {space} > /sys/kernel/debug/fail_page_alloc/space"
        out = remote.client.run_cmd(cmd)
        cmd = f"printf %#x {times} > /sys/kernel/debug/fail_page_alloc/times"
        out = remote.client.run_cmd(cmd)

    @staticmethod
    def setup_fail_function_test(func_name, times, retval, probability, interval, space):
        # Write function name to special debug fs file.
        cmd = f"echo {func_name} > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)
        # Write return code, which this function should return instead of
        # real return code.
        cmd = f"printf %#x {retval} > /sys/kernel/debug/fail_function/{func_name}/retval"
        out = remote.client.run_cmd(cmd)

        # Write probability in percent. 100 - function never executed
        # and return previously set return code every time, while error
        # injection works.
        cmd = f"echo {probability} > /sys/kernel/debug/fail_function/probability"
        out = remote.client.run_cmd(cmd)
        # If probability is equal to 100 should always be equal to zero.
        cmd = f"echo {interval} > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Fault injection is suppressed until space became equal to zero.
        cmd = f"echo {space} > /sys/kernel/debug/fail_function/space"
        out = remote.client.run_cmd(cmd)
        # Specifies how many times failures may happen at most.
        # A value of -1 means “no limit”.
        cmd = f"printf %#x {times} > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)

    @staticmethod
    def teardown_fail_function_test():
        # Remove function from fault injection list.
        cmd = "echo > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)
        # Restore times.
        cmd = f"printf %#x 1 > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)
        # Restore probability.
        cmd = f"echo 0 > /sys/kernel/debug/fail_function/probability"
        out = remote.client.run_cmd(cmd)
        # Restore interval.
        cmd = f"echo 1 > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Restore space.
        cmd = f"echo 0 > /sys/kernel/debug/fail_function/space"
        out = remote.client.run_cmd(cmd)


class TestFailFunction(TestFailFunctionBase, NetWorker):
    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_cli_conn_alloc",
                func_name="tfw_cli_conn_alloc",
                id="deproxy",
                msg="can't allocate a new client connection",
                times=-1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=0,
            ),
            marks.Param(
                name="tfw_client_obtain",
                func_name="tfw_client_obtain",
                id="deproxy",
                msg="can't obtain a client for frang accounting",
                times=-1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=0,
            ),
            marks.Param(
                name="tfw_hpack_init",
                func_name="tfw_hpack_init",
                id="deproxy_h2",
                msg="cannot establish a new h2 connection",
                times=-1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_expand_head_tail",
                func_name="ss_skb_expand_head_tail",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_to_sgvec_with_new_pages",
                func_name="ss_skb_to_sgvec_with_new_pages",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="tfw_h2_stream_xmit_prepare_resp",
                func_name="tfw_h2_stream_xmit_prepare_resp",
                id="deproxy_h2",
                msg=None,
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="tfw_h2_entail_stream_skb",
                func_name="tfw_h2_entail_stream_skb",
                id="deproxy_h2",
                msg=None,
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="crypto_alloc_aead_atomic_ssl",
                func_name="crypto_alloc_aead_atomic",
                id="deproxy_ssl",
                msg=None,
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="crypto_alloc_aead_atomic_h2",
                func_name="crypto_alloc_aead_atomic",
                id="deproxy_h2",
                msg=None,
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="crypto_alloc_shash_atomic_ssl",
                func_name="crypto_alloc_shash_atomic",
                id="deproxy_ssl",
                msg="Cannot setup hash ctx",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="crypto_alloc_shash_atomic_h2",
                func_name="crypto_alloc_shash_atomic",
                id="deproxy_h2",
                msg="Cannot setup hash ctx",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="mpi_profile_clone_ssl",
                func_name="__mpi_profile_clone",
                id="deproxy_ssl",
                msg="Can't allocate a crypto memory profile",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="mpi_profile_clone_h2",
                func_name="__mpi_profile_clone",
                id="deproxy_h2",
                msg="Can't allocate a crypto memory profile",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, func_name, id, msg, times, response, retval):
        self._test(name, func_name, id, msg, times, response, retval)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="ss_skb_to_sgvec_with_new_pages_long_resp",
                func_name="ss_skb_to_sgvec_with_new_pages",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "100000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 100000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_expand_head_tail_long_resp",
                func_name="ss_skb_to_sgvec_with_new_pages",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "100000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 100000,
                ),
                retval=-12,
            ),
        ]
    )
    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 100,
            }
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_mtu_100(self, name, func_name, id, msg, times, response, retval):
        self._test(name, func_name, id, msg, times, response, retval)

    def _test(self, name, func_name, id, msg, times, response, retval):
        """
        Basic test to check how Tempesta FW works when some internal
        function fails. Function should be marked as ALLOW_ERROR_INJECTION
        in Tempesta FW source code.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response(response)
        self.start_all_services(client=False)

        self.setup_fail_function_test(
            func_name, times=times, retval=retval, probability=100, interval=0, space=0
        )
        client = self.get_client(id)
        request = client.create_request(method="GET", headers=[])
        client.start()

        self.oops_ignore = ["ERROR"]
        client.make_request(request)

        # This is necessary to be sure that Tempesta FW write
        # appropriate message in dmesg.
        self.assertFalse(client.wait_for_response(3))
        self.assertTrue(client.wait_for_connection_close())

        if msg:
            self.assertTrue(
                self.loggers.dmesg.find(msg, cond=dmesg.amount_positive),
                "Tempesta doesn't report error",
            )


class TestFailFunctionPrepareResp(TestFailFunctionBase):
    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 100,
            }
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_tfw_h2_prep_resp_for_error_response(self):
        """
        Basic test to check how Tempesta FW works when some internal
        function fails. Function should be marked as ALLOW_ERROR_INJECTION
        in Tempesta FW source code.
        """

        server = self.get_server("deproxy")
        server.conns_n = 1
        self.disable_deproxy_auto_parser()

        header = ("qwerty", "x" * 1500000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: 0\r\n\r\n"
        )
        self.start_all_services(client=False)

        self.setup_fail_function_test(
            "tfw_h2_append_predefined_body",
            times=-1,
            retval=-12,
            probability=100,
            interval=0,
            space=0,
        )
        client = self.get_client("deproxy_h2")
        request1 = client.create_request(method="GET", headers=[])
        request2 = client.create_request(method="GET", headers=[("Content-Type", "!!!!")])
        client.start()

        client.update_initial_settings(max_header_list_size=1600000)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta foes not returns SETTINGS frame with ACK flag.",
        )

        self.oops_ignore = ["ERROR"]
        client.make_request(request1)
        server.wait_for_requests(1)
        client.make_request(request2)

        # This is necessary to be sure that Tempesta FW write
        # appropriate message in dmesg.
        self.assertFalse(client.wait_for_response(3))
        self.assertTrue(client.wait_for_connection_close())

    @dmesg.unlimited_rate_on_tempesta_node
    def test_tfw_h2_prep_resp_for_sticky_ccokie(self):
        server = self.get_server("deproxy")
        server.conns_n = 1
        self.disable_deproxy_auto_parser()

        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.js.tpl {workdir}")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.tpl {workdir}/js1.tpl")

        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = (
            new_config
            + """
            sticky {
                cookie enforce name=cname max_misses=5;
                js_challenge resp_code=503 delay_min=1 delay_range=3 %s/js1.html;
            }
        """
            % workdir
        )

        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        ),

        self.start_all_services(client=False)
        self.setup_fail_function_test(
            "tfw_h2_append_predefined_body",
            times=1,
            retval=-12,
            probability=100,
            interval=0,
            space=0,
        )
        client = self.get_client("deproxy_h2")
        request = client.create_request(method="GET", headers=[("accept", "text/html")])
        client.start()

        self.oops_ignore = ["ERROR"]
        client.make_request(request)

        # This is necessary to be sure that Tempesta FW write
        # appropriate message in dmesg.
        self.assertTrue(client.wait_for_response(3))
        self.assertEqual(client.last_response.status, "500")
        self.assertTrue(client.wait_for_connection_close())


class TestFailFunctionPipelinedResponses(TestFailFunctionBase):
    clients = [
        {
            "id": "deproxy_1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_3",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    clients_ids = ["deproxy_1", "deproxy_2", "deproxy_3"]

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_http_msg_create_sibling",
                func_name="tfw_http_msg_create_sibling",
                id="deproxy_h2",
                msg="Can't create pipelined response",
                times=-1,
                retval=0,
            )
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, func_name, id, msg, times, retval):
        srv = self.get_server("deproxy")
        srv.pipelined = 3
        srv.conns_n = 1
        self.start_all_services(client=False)
        self.setup_fail_function_test(
            func_name, times=times, retval=retval, probability=100, interval=0, space=0
        )

        i = 0
        for id in self.clients_ids:
            i = i + 1
            client = self.get_client(id)
            request = client.create_request(method="GET", headers=[])
            client.start()
            client.make_request(request)
            srv.wait_for_requests(i)

        i = 0
        for id in self.clients_ids:
            i = i + 1
            client = self.get_client(id)
            if i >= 2:
                self.assertFalse(client.wait_for_response(1))
            else:
                self.assertTrue(client.wait_for_response())
                self.assertTrue(client.last_response.status, "200")
        self.assertTrue(
            self.loggers.dmesg.find(msg, cond=dmesg.amount_positive),
            "Tempesta doesn't report error",
        )

        srv.wait_for_connections()
        req_count = i

        i = 0
        j = 0
        for id in self.clients_ids:
            i = i + 1
            client = self.get_client(id)
            if i >= 2:
                j = j + 1
                self.assertTrue(srv.wait_for_requests(req_count + j))
                srv.flush()
                self.assertTrue(client.wait_for_response())
                self.assertEqual(client.last_response.status, "200")


class TestFailFunctionStaleFwd(TestFailFunctionBase):
    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000;

            frang_limits {
                http_strict_host_checking false;
            }

            cache 2;
            cache_fulfill * *;
            cache_use_stale 4* 5*;
    """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_http",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy",
                resp2_headers=[],
                hang_on_req_num=0,
                expected_code="502",
            ),
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_h2",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy_h2",
                resp2_headers=[],
                hang_on_req_num=0,
                expected_code="502",
            ),
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_invalid_resp_http",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy",
                resp2_headers=[("hd>r", "v")],
                hang_on_req_num=0,
                expected_code="502",
            ),
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_invalid_resp_h2",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy_h2",
                resp2_headers=[("hd>r", "v")],
                hang_on_req_num=0,
                expected_code="502",
            ),
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_noresp_http",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy",
                resp2_headers=[],
                hang_on_req_num=2,
                expected_code="504",
            ),
            marks.Param(
                name="tfw_http_resp_do_fwd_stale_noresp_h2",
                func_name="tfw_cache_build_resp_stale",
                client="deproxy_h2",
                resp2_headers=[],
                hang_on_req_num=2,
                expected_code="504",
            ),
        ]
    )
    def test(
        self,
        name,
        func_name,
        client,
        resp2_headers,
        hang_on_req_num,
        expected_code,
    ):
        """
        Test the failure of sending a stale response. In this case we expect origin error code.
        """
        server = self.get_server("deproxy")
        server.hang_on_req_num = hang_on_req_num
        self.start_all_services()

        self.setup_fail_function_test(
            func_name, times=-1, retval=0, probability=100, interval=0, space=0
        )

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=[("Content-Length", "0"), ("cache-control", "max-age=1")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            "200",
            3,
        )

        # Wait while response become stale
        time.sleep(3)

        server.set_response(
            deproxy.Response.create(
                status="502",
                headers=[("Content-Length", "0")] + resp2_headers,
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client.send_request(
            client.create_request(
                method="GET",
                uri="/",
                headers=[],
            ),
            expected_code,
            3,
        )

        # expect not cached response
        self.assertIsNone(client.last_response.headers.get("age", None), None)


class TestFailOnReload(TestFailFunctionBase):
    """
    We should cleanup call `teardown_fail_function_test` before
    Tempesta will be unloaded! Otherwise fail function will be
    cleared incorrectly during Tempesta FW unload. Wait until
    error message and immediately cleanup.
    """

    def _do_control(self, msg):
        while True:
            if self.loggers.dmesg.find(msg, cond=dmesg.amount_positive):
                break
        self.teardown_fail_function_test()

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_sched_ratio_rtodata_get",
                func_name="tfw_sched_ratio_rtodata_get",
                new_config=None,
                msg="Unable to start module",
                times=-1,
                retval=0,
            ),
            marks.Param(
                name="tfw_sched_ratio_srvdesc_setup_srv",
                func_name="tfw_sched_ratio_srvdesc_setup_srv",
                new_config="""
                    srv_group new { 
                        server 127.0.0.1:8001;
                    }
                """,
                msg="Unable to start module",
                times=-1,
                retval=-12,
            ),
            marks.Param(
                name="tfw_srv_conn_alloc",
                func_name="tfw_srv_conn_alloc",
                new_config=None,
                msg="Unable to start module",
                times=-1,
                retval=0,
            ),
            marks.Param(
                name="tfw_apm_ref_create",
                func_name="tfw_apm_ref_create",
                new_config=None,
                msg="Unable to start module",
                times=-1,
                retval=-12,
            ),
        ]
    )
    def test(self, name, func_name, new_config, msg, times, retval):
        server = self.get_server("deproxy")
        server.conns_n = 1
        self.start_all_services(client=False)
        self.setup_fail_function_test(
            func_name, times=times, retval=retval, probability=100, interval=0, space=0
        )
        with self.assertRaises(
            expected_exception=ProcessBadExitStatusException,
        ):
            self.oops_ignore = ["ERROR"]
            if new_config:
                old_config = self.get_tempesta().config.defconfig
                self.get_tempesta().config.defconfig = old_config + new_config
            control_thread = threading.Thread(target=self._do_control, args=(msg,))
            control_thread.daemon = True
            control_thread.start()
            self.get_tempesta().reload()

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tdb_alloc_blk",
                func_name="tdb_alloc_blk",
                new_config=None,
                msg="Unable to start module",
                times=-1,
                retval=0,
                space=0,
            )
        ]
    )
    def test(self, name, func_name, new_config, msg, times, retval, space):
        server = self.get_server("deproxy")
        server.conns_n = 1
        self.start_all_services(client=False)
        self.setup_fail_function_test(
            func_name, times=times, retval=retval, probability=100, interval=0, space=space
        )
        self.get_tempesta().reload()

        client = self.get_client("deproxy")
        client.start()
        self.oops_ignore = ["ERROR"]
        client.make_request(client.create_request(method="GET", headers=[]))
        self.assertFalse(client.wait_for_response())
        self.assertTrue(client.wait_for_connection_close())


class TestStress(TestFailFunctionBase):
    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
            "cmd_args": (
                " https://${tempesta_ip}:443",
                f" --connections {CONCURRENT_CONNECTIONS}" f" --threads {THREADS}",
                f" --duration {DURATION}" f" ----timeout 0",
            ),
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2,https;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000 conns_n=32;
            
            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="wrk",
                client_id="wrk",
            ),
            marks.Param(
                name="h2load",
                client_id="h2load",
            ),
        ]
    )
    def test_connect(self, name, client_id):
        server = self.get_server("deproxy")
        server.conns_n = 32
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        self.get_tempesta().start()
        server.start()

        self.setup_fail_function_test(
            "ss_inet_create", times=-1, retval=-105, probability=100, interval=5, space=0
        )
        self.setup_fail_function_test(
            "ss_connect", times=-1, retval=-105, probability=100, interval=3, space=0
        )
        self.oops_ignore = ["ERROR"]

        client = self.get_client(client_id)
        client.start()
        self.wait_while_busy(client, timeout=20)
        client.stop()

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="wrk",
                client_id="wrk",
            ),
            marks.Param(
                name="h2load",
                client_id="h2load",
            ),
        ]
    )
    def test_mem(self, name, client_id):
        server = self.get_server("deproxy")
        server.conns_n = 32
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        self.start_all_services(client=False)
        self.setup_fail_page_alloc(times=1, probability=10, interval=100, space=0)
        self.oops_ignore = ["ERROR"]

        client = self.get_client(client_id)
        client.start()
        self.wait_while_busy(client, timeout=20)
        client.stop()
