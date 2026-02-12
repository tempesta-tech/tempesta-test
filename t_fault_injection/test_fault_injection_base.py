"""Bpf tests to check error handlings."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import re
import time

from h2.connection import ConnectionInputs
from hyperframe.frame import HeadersFrame, PingFrame, WindowUpdateFrame

from framework.deproxy_client import HuffmanEncoder
from helpers import deproxy, dmesg, error, remote, tf_cfg
from helpers.cert_generator_x509 import CertGenerator
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

SERVER_IP = tf_cfg.cfg.get("Server", "ip")
TEMPESTA_WORKDIR = tf_cfg.cfg.get("Tempesta", "workdir")

EXTRA_SERVERS = f"""
server {SERVER_IP}:8001;
server {SERVER_IP}:8002;
server {SERVER_IP}:8003;
server {SERVER_IP}:8004;
                """


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

    @staticmethod
    def setup_fail_function_test(func_name, probability, times, space, retval):
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
        cmd = f"echo 0 > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Specifies how many times failures may happen at most.
        # A value of -1 means “no limit”.
        cmd = f"printf %#x {times} > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)
        # Specifies how many times function is called without failuers.
        # A value of 0 means "immediately".
        cmd = f"echo {space} > /sys/kernel/debug/fail_function/space"
        cmd = remote.client.run_cmd(cmd)

    @staticmethod
    def teardown_fail_function_test():
        # Remove function from fault injection list
        cmd = f"echo > /sys/kernel/debug/fail_function/inject"
        out = remote.client.run_cmd(cmd)
        # Restore probability
        cmd = f"echo 0 > /sys/kernel/debug/fail_function/probability"
        out = remote.client.run_cmd(cmd)
        # Restore interval
        cmd = f"echo 1 > /sys/kernel/debug/fail_function/interval"
        out = remote.client.run_cmd(cmd)
        # Restore times
        cmd = f"printf %#x 1 > /sys/kernel/debug/fail_function/times"
        out = remote.client.run_cmd(cmd)
        # Restore space
        cmd = f"echo 0 > /sys/kernel/debug/fail_function/space"
        cmd = remote.client.run_cmd(cmd)

    def setUp(self):
        super().setUp()
        self.addCleanup(TestFailFunctionBase.teardown_fail_function_test)


class TestFailFunctionBaseStress(TestFailFunctionBase):
    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2,https;

            cache 2;
            cache_fulfill * *;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000 conns_n=1;

            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    clients = [
        {
            "id": "wrk_http",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --connections {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --duration {DURATION}"
            ),
        },
        {
            "id": "wrk_https",
            "type": "wrk",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --connections {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --duration {DURATION}"
            ),
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]


class TestStress(TestFailFunctionBaseStress):
    @marks.Parameterize.expand(
        [
            marks.Param(name="tdb", func_name="tdb_alloc_blk", client_id="h2load", retval=0),
            marks.Param(
                name="pool_alloc_wrk_http",
                func_name="tfw_pool_alloc_pages",
                client_id="wrk_http",
                retval=0,
            ),
            marks.Param(
                name="pool_alloc_wrk_https",
                func_name="tfw_pool_alloc_pages",
                client_id="wrk_https",
                retval=0,
            ),
            marks.Param(
                name="pool_alloc_h2load",
                func_name="tfw_pool_alloc_pages",
                client_id="h2load",
                retval=0,
            ),
            marks.Param(
                name="tfw_h2_add_stream",
                func_name="tfw_h2_add_stream",
                client_id="h2load",
                retval=0,
            ),
        ]
    )
    def test_stress(self, name, func_name, client_id, retval):
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        self.start_all_services(client=False)

        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 10, -1, 0, 0)
        client = self.get_client(client_id)

        self.oops_ignore = ["ERROR"]
        client.start()
        self.wait_while_busy(client, timeout=50)
        client.stop()


class TestSchedConfig(TestFailFunctionBase):
    backends = [
        {
            "id": "deproxy_1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy_2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy_3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy_4",
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
        {
            "id": "deproxy_5",
            "type": "deproxy",
            "port": "8004",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    base_tempesta_config = f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
"""

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_sched_ratio_srvdesc_setup_srv_1",
                func_name="tfw_sched_ratio_srvdesc_setup_srv",
                extra_config=EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sched_ratio_srvdesc_setup_srv_2",
                func_name="tfw_sched_ratio_srvdesc_setup_srv",
                extra_config=EXTRA_SERVERS,
                space=2,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sched_ratio_srvdesc_setup_srv_3",
                func_name="tfw_sched_ratio_srvdesc_setup_srv",
                extra_config=EXTRA_SERVERS,
                space=3,
                retval=-12,
            ),
            marks.Param(
                name="tfw_server_create_1",
                func_name="tfw_server_create",
                extra_config=EXTRA_SERVERS,
                space=1,
                retval=0,
            ),
            marks.Param(
                name="tfw_server_create_2",
                func_name="tfw_server_create",
                extra_config=EXTRA_SERVERS,
                space=2,
                retval=0,
            ),
            marks.Param(
                name="tfw_srv_conn_alloc_1",
                func_name="tfw_srv_conn_alloc",
                extra_config=EXTRA_SERVERS,
                space=1,
                retval=0,
            ),
            marks.Param(
                name="tfw_srv_conn_alloc_4",
                func_name="tfw_srv_conn_alloc",
                extra_config=EXTRA_SERVERS,
                space=4,
                retval=0,
            ),
            marks.Param(
                name="tfw_apm_data_init_1",
                func_name="tfw_apm_data_init",
                extra_config=f"""
health_check auto {{
    request     "GET / HTTP/1.0\r\n\r\n";
    request_url "/";
    resp_code   200;
    resp_crc32    auto;
    timeout     3;
}}
health auto;
"""
                + EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
            marks.Param(
                name="tfw_apm_data_init_3",
                func_name="tfw_apm_data_init",
                extra_config=f"""
health_check auto {{
    request     "GET / HTTP/1.0\r\n\r\n";
    request_url "/";
    resp_code   200;
    resp_crc32    auto;
    timeout     3;
}}

health auto;
"""
                + EXTRA_SERVERS,
                space=3,
                retval=-12,
            ),
            marks.Param(
                name="tfw_listen_sock_add_1",
                func_name="tfw_listen_sock_add",
                extra_config=EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
            marks.Param(
                name="tfw_listen_sock_add_2",
                func_name="tfw_listen_sock_add",
                extra_config=EXTRA_SERVERS,
                space=2,
                retval=-12,
            ),
            marks.Param(
                name="ss_sock_create_1",
                func_name="ss_sock_create",
                extra_config=f"""
listen 800;
listen 4443 proto=https,h2;
"""
                + EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
            marks.Param(
                name="ss_sock_create_2",
                func_name="ss_sock_create",
                extra_config=f"""
listen 800;
listen 4443 proto=https,h2;
"""
                + EXTRA_SERVERS,
                space=2,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sg_new_1",
                func_name="tfw_sg_new",
                extra_config=EXTRA_SERVERS,
                space=1,
                retval=0,
            ),
            marks.Param(
                name="tfw_sg_new_2",
                func_name="tfw_sg_new",
                extra_config=EXTRA_SERVERS,
                space=2,
                retval=0,
            ),
            marks.Param(
                name="tfw_cfgop_sg_copy_sched_arg_1",
                func_name="tfw_cfgop_sg_copy_sched_arg",
                extra_config=f"""
sched ratio predict minimum past=5 ahead=2;
"""
                + EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
            marks.Param(
                name="tfw_cfgop_sg_copy_sched_arg_2",
                func_name="tfw_cfgop_sg_copy_sched_arg",
                extra_config=f"""
sched ratio predict minimum past=5 ahead=2;
"""
                + EXTRA_SERVERS,
                space=2,
                retval=-12,
            ),
            marks.Param(
                name="tfw_cfgop_sg_copy_sched_arg_4",
                func_name="tfw_cfgop_sg_copy_sched_arg",
                extra_config=f"""
sched ratio predict minimum past=5 ahead=2;
srv_group grp1 {{
    server {SERVER_IP}:8001;
    sched ratio predict minimum past=5 ahead=2;
}}
srv_group grp2 {{
    server {SERVER_IP}:8002;
    sched ratio predict minimum past=5 ahead=2;
}}
srv_group grp3 {{
    server {SERVER_IP}:8003;
    sched ratio predict minimum past=5 ahead=2;
}}
srv_group grp4 {{
    server {SERVER_IP}:8004;
    sched ratio predict minimum past=5 ahead=2;
}}
vhost vh1 {{
    proxy_pass grp1;
}}
vhost vh2 {{
    proxy_pass grp2;
}}
vhost vh3 {{
    proxy_pass grp3;
}}
http_chain {{
    hdr host == "testapp.com" -> vh1;
    hdr forwarded == "host=testshop.com" -> vh2;
    host == "badhost.com" -> vh3;
    -> block;
}}
""",
                space=4,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sched_hash_add_grp_0",
                func_name="tfw_sched_hash_add_grp",
                extra_config=f"""
sched hash;
"""
                + EXTRA_SERVERS,
                space=0,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sched_hash_add_grp_1",
                func_name="tfw_sched_hash_add_grp",
                extra_config=f"""
sched hash;
"""
                + EXTRA_SERVERS,
                space=1,
                retval=-12,
            ),
        ]
    )
    def test(self, name, func_name, extra_config, space, retval):
        self.get_tempesta().config.set_defconfig(self.base_tempesta_config)
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, -1, space, retval)

        self.oops_ignore = ["ERROR"]
        self.get_tempesta().config.set_defconfig(self.base_tempesta_config + extra_config)

        with self.assertRaises(error.ProcessBadExitStatusException):
            self.get_tempesta().reload()

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="crypto_alloc_aead",
                func_name="crypto_alloc_aead",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
""",
                module_path=None,
                module_name_preload=None,
                retval=-12,
            ),
            marks.Param(
                name="crypto_alloc_shash",
                func_name="crypto_alloc_shash",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
""",
                module_path=None,
                module_name_preload=None,
                retval=-12,
            ),
            marks.Param(
                name="kmem_cache_create",
                func_name="kmem_cache_create",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
cache 2;
cache_fulfill * *;
""",
                module_path=None,
                module_name_preload=None,
                retval=0,
            ),
            marks.Param(
                name="tfw_kmalloc",
                func_name="tfw_kmalloc",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
cache 2;
cache_fulfill * *;

srv_group test {{
    server {SERVER_IP}:8001 conns_n=10;
}}

srv_group test1 {{
    server {SERVER_IP}:8002 conns_n=10;
}}

vhost tests {{
    location prefix / {{
        proxy_pass test;
    }}
    proxy_pass test1;
}}

http_chain {{
    host == "tests.com" -> tests;
    ->block;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="tfw_kmalloc_node",
                func_name="tfw_kmalloc_node",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
cache 2;
cache_fulfill * *;

health_stat 3* 4* 5*;
health_stat_server 3* 4* 5*;

health_check h_monitor1 {{
    request "GET / HTTP/1.1\r\n\r\n";
    request_url "/";
    resp_code   200;
    resp_crc32  auto;
    timeout     1;
}}

srv_group test {{
    server {SERVER_IP}:8001 conns_n=10;

    health h_monitor1;
}}

srv_group test1 {{
    server {SERVER_IP}:8002 conns_n=10;
}}

vhost tests {{
    location prefix / {{
        proxy_pass test;
    }}
    proxy_pass test1;
}}

http_chain {{
    host == "tests.com" -> tests;
    ->block;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="tfw_kzalloc",
                func_name="tfw_kzalloc",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
cache 2;
cache_fulfill * *;

health_stat 3* 4* 5*;
health_stat_server 3* 4* 5*;

health_check h_monitor1 {{
    request "GET / HTTP/1.1\r\n\r\n";
    request_url "/";
    resp_code   200;
    resp_crc32  auto;
    timeout     1;
}}

srv_group test {{
    sched hash;
    server {SERVER_IP}:8001 conns_n=10;

    health h_monitor1;
}}

srv_group test1 {{
    server {SERVER_IP}:8002 conns_n=10;
}}

vhost tests {{
    location prefix / {{
        proxy_pass test;
    }}
    proxy_pass test1;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}

tft {{
    hash a7007c90000 5 5;
}}

tfh {{
    hash a7007c90000 5 5;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="tfw_kcalloc",
                func_name="tfw_kcalloc",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;

srv_group test {{
    sched hash;
    server {SERVER_IP}:8001 conns_n=10;
}}

vhost tests {{
    proxy_pass test;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="tfw_kvmalloc_node",
                func_name="tfw_kvmalloc_node",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;

srv_group test {{
    sched hash;
    server {SERVER_IP}:8001 conns_n=10;
}}

vhost tests {{
    proxy_pass test;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="tfw__alloc_percpu",
                func_name="tfw__alloc_percpu",
                config=f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;

srv_group test {{
    sched hash;
    server {SERVER_IP}:8001 conns_n=10;
}}

vhost tests {{
    proxy_pass test;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}

""",
                module_path="lib",
                module_name_preload="tempesta_lib",
                retval=0,
            ),
            marks.Param(
                name="proc_mkdir",
                func_name="proc_mkdir",
                config=f"""
listen 80;

srv_group test_1 {{
    server {SERVER_IP}:8001 conns_n=10;
}}

srv_group test_2 {{
    server {SERVER_IP}:8002 conns_n=10;
}}

srv_group test_3 {{
    server {SERVER_IP}:8003 conns_n=10;
}}

srv_group test_4 {{
    server {SERVER_IP}:8004 conns_n=10;
}}

vhost tests {{
    proxy_pass test_1;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}
""",
                module_path=None,
                module_name_preload=None,
                retval=0,
            ),
            marks.Param(
                name="proc_create_data",
                func_name="proc_create_data",
                config=f"""
listen 80;

srv_group test_1 {{
    server {SERVER_IP}:8001 conns_n=10;
}}

srv_group test_2 {{
    server {SERVER_IP}:8002 conns_n=10;
}}

srv_group test_3 {{
    server {SERVER_IP}:8003 conns_n=10;
}}

srv_group test_4 {{
    server {SERVER_IP}:8004 conns_n=10;
}}

vhost tests {{
    proxy_pass test_1;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}
""",
                module_path=None,
                module_name_preload=None,
                retval=0,
            ),
        ]
    )
    def test_init_modules(self, name, func_name, config, module_path, module_name_preload, retval):
        self.get_tempesta().config.set_defconfig(config)
        self.oops_ignore = ["ERROR"]
        space = 0
        need_stop = False
        while not need_stop:
            success = None
            if module_name_preload:
                self.assertIsNotNone(module_path)
                self.get_tempesta().load_module(module_path, module_name_preload)
            TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, -1, space, retval)
            try:
                self.get_tempesta().start()
            except error.ProcessBadExitStatusException:
                success = True
            except:
                success = False
            else:
                success = True
                need_stop = True

            self.assertTrue(success)
            self.get_tempesta().stop()
            """
            Because we setup fail function in the loop we should call teardown here
            at the end of the each loop iteration. If test fails teardown will be
            called from the cleanup procedure also.
            """
            TestFailFunctionBaseStress.teardown_fail_function_test()
            space = space + 1

    def test_abort_srv_connection_on_graceful_shutdown(self):
        """
        Tempesta FW try to stop server connections gracefully if
        grace_shutdown_time is not 0. If graceful shutdown fails
        Tempesta FW abort all servers connections. Internally
        Tempesta FW uses `__tfw_wq_push` function for these
        purposes. This test checks that all server connections
        will be aborted if `__tfw_wq_push` fails.
        """
        self.get_tempesta().config.set_defconfig(
            f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
grace_shutdown_time 1;

server {SERVER_IP}:8002 conns_n=10;

srv_group test {{
    server {SERVER_IP}:8003 conns_n=10;
}}

srv_group test1 {{
    server {SERVER_IP}:8004 conns_n=10;
}}

vhost tests {{
    proxy_pass test1;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}
"""
        )
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test("__tfw_wq_push", 100, -1, 0, -12)
        for server in self.get_servers():
            server.conns_n = 10
            server.set_response(
                deproxy.Response.create_simple_response(
                    status="200",
                    headers=[],
                    date=deproxy.HttpMessage.date_time_string(),
                )
            )

            server.start()

        self.deproxy_manager.start()
        for srv_name in ["deproxy_3", "deproxy_4", "deproxy_5"]:
            server = self.get_server(srv_name)
            self.assertTrue(server.wait_for_connections(timeout=5))

        self.get_tempesta().config.set_defconfig(
            f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
grace_shutdown_time 1;
"""
        )
        self.get_tempesta().reload()
        for srv_name in ["deproxy_3", "deproxy_4", "deproxy_5"]:
            server = self.get_server(srv_name)
            self.assertTrue(server.wait_for_connections_closed(timeout=5))
        server = self.get_server("deproxy_1")
        self.assertTrue(server.wait_for_connections(timeout=5))

    def test_failed_disconnect_srv_connection(self):
        """
        Tempesta FW try to stop and disconnect all server connections
        on Tempesta shutdown. If disconnec fails Tempesta FW abort all
        servers connections. Internally Tempesta FW uses `__tfw_wq_push`
        function for these purposes. This test checks that all server
        connections will be aborted if `__tfw_wq_push` fails.
        """
        self.get_tempesta().config.set_defconfig(
            f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;

server {SERVER_IP}:8002 conns_n=10;

srv_group test {{
    server {SERVER_IP}:8003 conns_n=10;
}}

srv_group test1 {{
    server {SERVER_IP}:8004 conns_n=10;
}}

vhost tests {{
    proxy_pass test1;
}}

http_chain {{
    uri == "/" -> 301 = https://static.request_uri;
    host == "tests.com" -> tests;
    ->block;
}}
"""
        )
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test("__tfw_wq_push", 100, -1, 0, -12)
        for server in self.get_servers():
            server.conns_n = 10
            server.set_response(
                deproxy.Response.create_simple_response(
                    status="200",
                    headers=[],
                    date=deproxy.HttpMessage.date_time_string(),
                )
            )

            server.start()

        self.deproxy_manager.start()
        for srv_name in ["deproxy_3", "deproxy_4", "deproxy_5"]:
            server = self.get_server(srv_name)
            self.assertTrue(server.wait_for_connections(timeout=5))
        self.get_tempesta().stop_tempesta()
        for srv_name in ["deproxy_3", "deproxy_4", "deproxy_5"]:
            server = self.get_server(srv_name)
            self.assertTrue(server.wait_for_connections_closed())

    def test_abort_client_connection(self):
        """
        This test checks that Tempesta FW correctly close
        client connections if `__tfw_wq_push` fails.
        """
        self.get_tempesta().config.set_defconfig(
            f"""
listen 80;
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
tls_match_any_server_name;

srv_group test {{
    server {SERVER_IP}:8000 conns_n=10;
}}

vhost test {{
    frang_limits {{
        http_strict_host_checking false;
    }}
    proxy_pass test;
}}

http_chain {{
   -> test;
}}
"""
        )
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test("__tfw_wq_push", 100, 50, 7, -12)
        server = self.get_server("deproxy_1")
        server.conns_n = 10
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        server.start()
        self.deproxy_manager.start()
        self.assertTrue(server.wait_for_connections(timeout=5))

        client = self.get_client("deproxy_h2")
        client.start()
        client.send_request(client.create_request(method="GET", headers=[]), "200")
        self.get_tempesta().stop()

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="ttls_md_hmac_starts",
                func_name="ttls_md_hmac_starts",
                base_config=f"""
listen 80;
""",
                new_config=f"""
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
""",
                space=0,
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_hmac_starts_2",
                func_name="ttls_md_hmac_starts",
                base_config=f"""
listen 80;
""",
                new_config=f"""
listen 443 proto=h2,https;
tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
server {SERVER_IP}:8000 conns_n=10;
""",
                space=2,
                retval=-12,
            ),
        ]
    )
    def test_tls(self, name, func_name, base_config, new_config, space, retval):
        self.get_tempesta().config.set_defconfig(base_config)
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, -1, space, retval)

        self.oops_ignore = ["ERROR"]
        self.get_tempesta().config.set_defconfig(new_config)

        with self.assertRaises(error.ProcessBadExitStatusException):
            self.get_tempesta().reload()

    def client_send_first_req(self, client):
        req = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        client.send_request(req, "200")
        response = client.last_response

        c_header = response.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        return cookie

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="tfw_sched_hash_add_srv",
                func_name="tfw_sched_hash_add_srv",
                extra_config_1=f"""
sticky {{
    learn name=client-id;
}}

sched hash;
                """,
                extra_config_2=f"""
grace_shutdown_time 5;
                """
                + EXTRA_SERVERS,
                space=0,
                retval=-12,
            ),
            marks.Param(
                name="tfw_sched_ratio_srvdesc_setup_srv",
                func_name="tfw_sched_ratio_srvdesc_setup_srv",
                extra_config_1=f"""
sticky {{
    learn name=client-id;
}}

sched ratio predict minimum past=5 ahead=2;
                """,
                extra_config_2=f"""
grace_shutdown_time 5;
                """
                + EXTRA_SERVERS,
                space=6,
                retval=-12,
            ),
        ]
    )
    def test_learn(self, name, func_name, extra_config_1, extra_config_2, space, retval):
        self.get_tempesta().config.set_defconfig(self.base_tempesta_config + extra_config_1)
        self.get_tempesta().start()
        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, -1, space, retval)

        server = self.get_server("deproxy_1")
        server.conns_n = 10
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[
                    ("content-length", "0"),
                    ("set-cookie", "client-id=jdsfhrkfj53542njfnjdmdnvjs45343n4nn4b54m"),
                ],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        server.start()
        self.deproxy_manager.start()
        self.assertTrue(server.wait_for_connections(timeout=5))

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[])
        client.start()

        cookie = self.client_send_first_req(client)
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (cookie[0], cookie[1])
        )
        client.send_request(request, "200")

        self.get_tempesta().config.set_defconfig(self.base_tempesta_config + extra_config_2)
        self.get_tempesta().reload()


class TestSched(TestFailFunctionBaseStress):
    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2,https;

            cache 2;
            cache_fulfill * *;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            server ${server_ip}:8000 conns_n=10;

            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="ss_sock_create",
                func_name="ss_sock_create",
                retval=-105,
            ),
            marks.Param(
                name="ss_connect",
                func_name="ss_connect",
                retval=-12,
            ),
        ]
    )
    def test_stress(self, name, func_name, retval):
        server = self.get_server("deproxy")
        server.conns_n = 10
        server.set_response(
            deproxy.Response.create_simple_response(
                status="200",
                headers=[("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        self.start_all_services(client=False)

        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 15, -1, 0, retval)
        self.get_tempesta().reload()

        client = self.get_client("h2load")

        self.oops_ignore = ["ERROR"]
        client.start()
        self.wait_while_busy(client)
        client.stop()


class TestFailFunction(TestFailFunctionBase, NetWorker):
    @marks.Parameterize.expand(
        [
            marks.Param(
                name="ss_active_guard_enter_0",
                func_name="ss_active_guard_enter",
                id="deproxy",
                msg=None,
                times=1,
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-4089,
            ),
            marks.Param(
                name="ss_active_guard_enter_1",
                func_name="ss_active_guard_enter",
                id="deproxy",
                msg=None,
                times=1,
                space=2,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-4089,
            ),
            marks.Param(
                name="tfw_cli_conn_alloc",
                func_name="tfw_cli_conn_alloc",
                id="deproxy",
                msg="can't allocate a new client connection",
                times=-1,
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=0,
            ),
            marks.Param(
                name="ttls_md_hmac_starts_1",
                func_name="ttls_md_hmac_starts",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=3,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_hmac_starts_2",
                func_name="ttls_md_hmac_starts",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=4,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_hmac_reset",
                func_name="ttls_md_hmac_reset",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_cipher_setup",
                func_name="ttls_cipher_setup",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_cipher_setup_2",
                func_name="ttls_cipher_setup",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=2,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_handshake_init_out_buffers",
                func_name="ttls_handshake_init_out_buffers",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_starts_1",
                func_name="ttls_md_starts",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_update_1",
                func_name="ttls_md_update",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ttls_md_finish_1",
                func_name="ttls_md_finish",
                id="deproxy_ssl",
                msg=None,
                times=-1,
                space=1,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="tfw_client_obtain",
                func_name="tfw_client_obtain",
                id="deproxy",
                msg="can't obtain a client for frang accounting",
                times=-1,
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
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
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("content-length", "0")],
                    date=deproxy.HttpMessage.date_time_string(),
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_1",
                func_name="ss_skb_realloc_headroom",
                id="deproxy",
                msg=None,
                times=1,
                space=4,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_2",
                func_name="ss_skb_realloc_headroom",
                id="deproxy",
                msg=None,
                times=1,
                space=7,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_ssl_1",
                func_name="ss_skb_realloc_headroom",
                id="deproxy_ssl",
                msg=None,
                times=1,
                space=4,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_ssl_2",
                func_name="ss_skb_realloc_headroom",
                id="deproxy_ssl",
                msg=None,
                times=1,
                space=7,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_h2_1",
                func_name="ss_skb_realloc_headroom",
                id="deproxy_h2",
                msg=None,
                times=1,
                space=4,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
            marks.Param(
                name="ss_skb_realloc_headroom_h2_2",
                func_name="ss_skb_realloc_headroom",
                id="deproxy_h2",
                msg=None,
                times=1,
                space=7,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "200000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 200000,
                ),
                retval=-12,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, func_name, id, msg, times, space, response, retval):
        self._test(name, func_name, id, msg, times, space, response, retval)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="ss_skb_to_sgvec_with_new_pages_long_resp",
                func_name="ss_skb_to_sgvec_with_new_pages",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                space=0,
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
                name="ss_skb_expand_head_tail_long_resp",
                func_name="ss_skb_to_sgvec_with_new_pages",
                id="deproxy_h2",
                msg="tfw_tls_encrypt: cannot encrypt data",
                times=1,
                space=0,
                response=deproxy.Response.create_simple_response(
                    status="200",
                    headers=[("qwerty", "x" * 50000), ("content-length", "100000")],
                    date=deproxy.HttpMessage.date_time_string(),
                    body="y" * 100000,
                ),
                mtu=100,
                retval=-12,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    @NetWorker.protect_ipv6_addr_on_dev
    def test_with_mtu(self, name, func_name, id, msg, times, space, response, mtu, retval):
        try:
            dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
            prev_mtu = sysnet.change_mtu(remote.client, dev, mtu)
            self._test(name, func_name, id, msg, times, space, response, retval)
        finally:
            sysnet.change_mtu(remote.client, dev, prev_mtu)

    def _test(self, name, func_name, id, msg, times, space, response, retval):
        """
        Basic test to check how Tempesta FW works when some internal
        function fails. Function should be marked as ALLOW_ERROR_INJECTION
        in Tempesta FW source code.
        """
        server = self.get_server("deproxy")
        server.conns_n = 1
        server.set_response(response)
        self.start_all_services(client=False)

        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, times, space, retval)
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
    @dmesg.unlimited_rate_on_tempesta_node
    @NetWorker.protect_ipv6_addr_on_dev
    def test_tfw_h2_prep_resp_for_error_response(self):
        """
        Basic test to check how Tempesta FW works when some internal
        function fails. Function should be marked as ALLOW_ERROR_INJECTION
        in Tempesta FW source code.
        """

        try:
            dev = sysnet.route_dst_ip(remote.client, tf_cfg.cfg.get("Tempesta", "ip"))
            prev_mtu = sysnet.change_mtu(remote.client, dev, 100)
            self._test_tfw_h2_prep_resp_for_error_response()
        finally:
            sysnet.change_mtu(remote.client, dev, prev_mtu)

    def _test_tfw_h2_prep_resp_for_error_response(self):
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

        TestFailFunctionBaseStress.setup_fail_function_test(
            "tfw_h2_append_predefined_body", 100, -1, 0, -12
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
        TestFailFunctionBaseStress.setup_fail_function_test(
            "tfw_h2_append_predefined_body", 100, 1, 0, -12
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
        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, times, 0, retval)

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

        TestFailFunctionBaseStress.setup_fail_function_test(func_name, 100, -1, 0, 0)

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
