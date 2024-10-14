"""Bpf tests to check error handlings."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import ConnectionInputs
from hyperframe.frame import HeadersFrame, PingFrame, WindowUpdateFrame

from framework.deproxy_client import HuffmanEncoder
from helpers import deproxy, dmesg, remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
from helpers.deproxy import HttpMessage
from helpers.networker import NetWorker
from test_suite import marks, sysnet, tester
from test_suite.custom_error_page import CustomErrorPageGenerator


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

            server ${server_ip}:8000 conns_n=1;
            
            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    @staticmethod
    def setup_fail_function_test(func_name, times, retval):
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
        cmd = "echo 100 > /sys/kernel/debug/fail_function/probability"
        out = remote.client.run_cmd(cmd)
        # If probability is equal to 100 should always be equal to zero.
        cmd = "echo 0 > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Specifies how many times failures may happen at most.
        # A value of -1 means “no limit”.
        cmd = f"printf %#x {times} > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)

    @staticmethod
    def teardown_fail_function_test():
        # Remove function from fault injection list
        cmd = "echo > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)
        # Restore times
        cmd = f"printf %#x -1 > /sys/kernel/debug/fail_function/times"
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
                mtu=None,
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
                mtu=None,
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
                mtu=None,
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
                mtu=None,
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
                mtu=100,
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
                mtu=None,
                retval=-12,
            ),
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
                mtu=100,
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
                mtu=None,
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
                mtu=None,
                retval=-12,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, func_name, id, msg, times, response, mtu, retval):
        if mtu:
            try:
                dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
                prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
                self._test(name, func_name, id, msg, times, response, retval)
            finally:
                sysnet.change_mtu(remote.client, dev, prev_mtu)
        else:
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

        self.setup_fail_function_test(func_name, times, retval)
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
                self.oops.find(msg, cond=dmesg.amount_positive),
                "Tempesta doesn't report error",
            )

        # This should be called in case if test fails also
        self.teardown_fail_function_test()


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
        self.setup_fail_function_test(func_name, times, retval)

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
            self.oops.find(msg, cond=dmesg.amount_positive),
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
                self.assertEqual(client._last_response.status, "200")

        # This should be called in case if test fails also
        self.teardown_fail_function_test()


class TestFailFunctionBlockAction(TestFailFunctionBase):
    tempesta_tmpl = """
            listen 80;
            listen 443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack %s;
            block_action error %s;
            %s

            server ${server_ip}:8000 conns_n=1;
            
            frang_limits {
                http_strict_host_checking false;
            }
    """

    ERROR_RESPONSE_BODY = "a" * 1000
    INITIAL_WINDOW_SIZE = 100
    resp_tempesta_conf = "response_body 4* {0};"

    def _generate_custom_error_page(self, data):
        workdir = tf_cfg.cfg.get("General", "workdir")
        cpage_gen = CustomErrorPageGenerator(data=data, f_path=f"{workdir}/4xx.html")
        path = cpage_gen.get_file_path()
        remote.tempesta.copy_file(path, data)
        return path

    def setUp(self):
        path = self._generate_custom_error_page(self.ERROR_RESPONSE_BODY)
        self.tempesta = {
            "config": self.tempesta_tmpl % ("reply", "reply", self.resp_tempesta_conf.format(path)),
        }
        TestFailFunctionBase.setUp(self)

    @marks.Parameterize.expand(
        [
            # Error occurs when we receive ping frame Conn_Stop
            # bit is not set, so Tempesta FW immediately closes
            # connection and stops process any other frames.
            marks.Param(
                name="tfw_h2_send_ping_0",
                func_name="tfw_h2_send_ping",
                times=-1,
                retval=-12,
                increment=1,
                count=999,
                frame_num=0,
                frame=PingFrame(0),
                expect_response=False,
            ),
            # Error occurs when Tempesta FW process invalid request,
            # Tempesta FW continue to process frames, but doesn't
            # skip any types of frames except WINDOW_UPDATE, so
            # `tfw_h2_send_ping` never called.
            marks.Param(
                name="tfw_h2_send_ping_1",
                func_name="tfw_h2_send_ping",
                times=-1,
                retval=-12,
                increment=100,
                count=9,
                frame_num=1,
                frame=PingFrame(0),
                expect_response=True,
            ),
            marks.Param(
                name="tfw_h2_send_ping_2",
                func_name="tfw_h2_send_ping",
                times=-1,
                retval=-12,
                increment=100,
                count=9,
                frame_num=2,
                frame=PingFrame(0),
                expect_response=True,
            ),
            # Error occurs when Tempesta FW process invalid request,
            # but next error occurs when Tempsta FW process invlid
            # WINDOW_UPDATE frame. Tempesta FW immediately closes
            # connection.
            marks.Param(
                name="tfw_h2_wnd_update_process",
                func_name="tfw_h2_wnd_update_process",
                times=-1,
                retval=-12,
                increment=10,
                count=90,
                frame_num=0,
                frame=WindowUpdateFrame(0),
                expect_response=False,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(
        self,
        name,
        func_name,
        times,
        retval,
        increment,
        count,
        frame_num,
        frame,
        expect_response,
    ):
        server = self.get_server("deproxy")
        server.conns_n = 1
        self.start_all_services(client=False)

        self.setup_fail_function_test(func_name, times, retval)
        client = self.get_client("deproxy_h2")
        client.start()
        client.update_initial_settings(initial_window_size=self.INITIAL_WINDOW_SIZE)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta does not returns SETTINGS frame with ACK flag.",
        )

        client.auto_flow_control = False

        stream = client.init_stream_for_send(client.stream_id)
        stream_id = client.stream_id

        headers_frame = HeadersFrame(
            stream_id=stream_id,
            data=HuffmanEncoder().encode(
                [
                    (":authority", "good.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "GET"),
                    ("Content-Type", "invalid"),
                ]
            ),
            flags=["END_HEADERS", "END_STREAM"],
        )

        stream = client.h2_connection.streams[stream_id]
        stream_wnd_update_frame = b""
        for _ in range(0, count):
            stream_wnd_update_frame += stream.increase_flow_control_window(increment)[0].serialize()
            client.h2_connection.increment_flow_control_window(increment)

        to_send = [
            headers_frame.serialize(),
            client.h2_connection.data_to_send(),
            stream_wnd_update_frame,
        ]
        client.h2_connection.clear_outbound_data_buffer()
        to_send.insert(frame_num, frame.serialize())

        client.send_bytes(
            b"".join(to_send),
            expect_response=True,
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertEqual(client.ping_received, 0)
        if expect_response:
            self.assertIsNotNone(client.last_response)
            self.assertEqual(client.last_response.status, "400")
            self.assertEqual(client.last_response.body, self.ERROR_RESPONSE_BODY)
        else:
            self.assertFalse(client.last_response)

        self.teardown_fail_function_test()
