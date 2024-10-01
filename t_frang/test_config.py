"""Tests for default frang config and overriding/inheritance."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from hyperframe.frame import DataFrame, HeadersFrame

from framework.parameterize import param, parameterize
from helpers.dmesg import (
    amount_positive,
    limited_rate_on_tempesta_node,
    unlimited_rate_on_tempesta_node,
)
from helpers.remote import CmdError
from test_suite import tester


class TestDefaultConfig(tester.TempestaTest):
    """
    This class contains tests for frang directives
    when `frang_limits` is not present in config.
    """

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy-2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "config": """
listen 80 proto=http;
listen 443 proto=h2;
server ${server_ip}:8000;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
block_action attack reply;
block_action error reply;
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    @unlimited_rate_on_tempesta_node
    def test_http_body_len(self):
        """
        Client send request with body > 1 GB and Tempest MUST return a 403 response
        because by default `http_body_len` is 1 GB.
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")

        client.start()
        client.make_request(client.create_request(method="POST", headers=[]), end_stream=False)

        default_size = 1073741824  # 1 GB
        frame_size = 16384  # max_frame_size for http2
        df = DataFrame(stream_id=client.stream_id, data=b"a" * frame_size)

        for _ in range(default_size // frame_size):
            client.send_bytes(df.serialize(), expect_response=False)

        df.flags.add("END_STREAM")
        client.send_bytes(df.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response(30))
        self.assertEqual(client.last_response.status, "403")
        self.assertTrue(self.oops.find("frang: HTTP body length exceeded for"))

    @unlimited_rate_on_tempesta_node
    def test_http_strict_host_checking(self):
        """
        Client send request with different host and authority headers. Tempesta MUST return a 403
        response because by default `http_strict_host_checking` is True
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")
        client.parsing = False

        client.start()
        client.send_request(
            request=client.create_request(
                method="GET", headers=[("host", "otherhost")], authority="localhost"
            ),
            expected_status_code="403",
        )
        self.assertTrue(self.oops.find("frang: Request :authority differs from Host for"))

    @unlimited_rate_on_tempesta_node
    def test_http_ct_required(self):
        """
        Client send request without Content-Type header. Tempesta MUST return a 200 response
        because by default `http_ct_required` is False and Content-Type is optional
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")

        client.start()
        client.send_request(
            request=client.create_request(method="POST", headers=[]),
            expected_status_code="200",
        )
        self.assertFalse(self.oops.find("frang: Content-Type header field for"))

    @unlimited_rate_on_tempesta_node
    def test_http_trailer_split_allowed(self):
        """
        Client send request with same header in headers and trailer. Tempesta MUST return a 403
        response because by default `http_trailer_split_allowed` is false.
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")

        client.start()
        client.make_request(
            request=client.create_request(
                method="POST", headers=[("trailer", "x-my-hdr"), ("x-my-hdr", "value")]
            ),
            end_stream=False,
        )

        tf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("x-my-hdr", "value")]),
            flags=["END_HEADERS", "END_STREAM"],
        )
        client.send_bytes(data=tf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "403")
        self.assertTrue(self.oops.find("frang: HTTP field appear in header and trailer"))

    @unlimited_rate_on_tempesta_node
    def test_http_methods(self):
        """
        Client send PUT request. Tempesta MUST return a 403 response because by default
        `http_methods` is get post head.
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")

        client.start()
        client.send_request(
            request=client.create_request(method="PUT", headers=[]),
            expected_status_code="403",
        )
        self.assertTrue(self.oops.find("frang: restricted HTTP method"))

    @limited_rate_on_tempesta_node
    def test_concurrent_tcp_connections(self):
        """
        Client create 1010 connections and Tempesta MUST accept 1000 connections because
        by default `concurrent_tcp_connections` is 1000.
        """
        self.start_all_services(client=False)
        client = self.get_client("wrk")
        client.connections = 1010
        client.options.append(f"--header 'Host: tempesta-tech.com'")

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertTrue(self.oops.find("frang: connections max num. exceeded for", amount_positive))
        self.assertGreater(client.statuses[200], 0)

    @unlimited_rate_on_tempesta_node
    def test_http_header_cnt(self):
        """
        Client send request with 60 headers. Tempesta MUST return a 403 response because
        by default `http_header_cnt` is 50.
        """
        self.start_all_services(client=False)
        client = self.get_client("deproxy-1")

        client.start()
        client.send_request(
            request=client.create_request(
                method="POST", headers=[("x-my-hdr", "value") for _ in range(60)]
            ),
            expected_status_code="403",
        )
        self.assertTrue(self.oops.find("frang: HTTP headers count exceeded for"))

    @unlimited_rate_on_tempesta_node
    def test_ip_block(self):
        """
        Client creates 2 connections and sends an invalid request in the first connection.
        Tempesta MUST block the first connection and accept the second connection because
        by default `ip_block` is off.
        """
        self.start_all_services(client=False)
        client_1 = self.get_client("deproxy-1")
        client_2 = self.get_client("deproxy-2")

        client_1.start()
        client_1.send_request(
            request=client_1.create_request(method="PUT", headers=[]),
            expected_status_code="403",
        )

        client_2.start()
        client_2.send_request(
            request=client_2.create_request(method="POST", headers=[]),
            expected_status_code="200",
        )

        self.assertTrue(self.oops.find("frang: "))


class TestOverridingInheritance(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_http",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta = {
        "config": """
cache 2;
listen 80;
listen 443 proto=h2;
server ${server_ip}:8000;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
block_action attack reply;
block_action error reply;
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    def __update_tempesta_config(self, frang_config: str):
        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = new_config + frang_config

    @unlimited_rate_on_tempesta_node
    def test_two_connection_frang_limits_in_global_config(self):
        """
        Tempesta config has two global `frang_limits` with `http_hdr_len` (connection limit)
        directive. Only the last will be used.
        """
        self.__update_tempesta_config(
            """
            frang_limits {http_hdr_len 500;}
            frang_limits {http_hdr_len 100;}
            """
        )
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            client.create_request(method="POST", headers=[("x-my-xdr", "a" * 150)]), "403"
        )
        self.assertTrue(self.oops.find("frang: HTTP header length exceeded for"))

    @parameterize.expand(
        [
            param(
                name="in_global_config",
                config="""
                    frang_limits {http_methods get post put;}
                    frang_limits {http_methods post put;}
                """,
            ),
            param(
                name="in_vhost",
                config="""
                    vhost vhost_1 {
                        frang_limits {http_methods get post put;}
                        frang_limits {http_methods post put;}
                        proxy_pass default;
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_two_message_frang_limits(self, name, config: str):
        """
        Tempesta config has two global/vhost `frang_limits` with `http_methods` (message limit)
        directive. `default` vhost/location will be used the last config.
        """
        self.__update_tempesta_config(config)
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(client.create_request(method="GET", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    @parameterize.expand(
        [
            param(
                name="two_frang_limits_in_location",
                config="""
                    vhost vhost_1 {
                        proxy_pass default;
                        location prefix "/vhost_1" {
                            frang_limits {http_methods get post put;}
                            frang_limits {http_methods post put;}
                            cache_fulfill * *; 
                            proxy_pass default;
                        }
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="connection_limit_in_vhost",
                config="""
                    vhost vhost_1 {frang_limits {http_hdr_len 100;} proxy_pass default;}
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="connection_limit_in_location",
                config="""
                        vhost vhost_1 {
                            proxy_pass default;
                            location prefix "/vhost_1" {
                                frang_limits {http_hdr_len 100;}
                                cache_fulfill * *;
                                proxy_pass default;
                            }
                        }
                        http_chain {-> vhost_1;}
                    """,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test(self, name, config):
        """
        Tempesta config has double frang_limits in location or connection frang limit in
        a vhost/location. It is incorrect. It must not work.
        """
        self.__update_tempesta_config(config)
        self.oops_ignore.append("ERROR")
        with self.assertRaises(CmdError):
            self.start_tempesta()

    @parameterize.expand(
        [
            param(
                name="global_to_vhost",
                config="""
                    frang_limits {http_methods post put;}
                    vhost vhost_1 {proxy_pass default;}
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="global_to_location_via_vhost",
                config="""
                    frang_limits {http_methods post put; http_strict_host_checking false;}
                    vhost vhost_1 {
                        proxy_pass default;
                        location prefix "/vhost_1" {cache_fulfill * *; proxy_pass default;}
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="vhost_to_location",
                config="""
                    vhost vhost_1 {
                        proxy_pass default;
                        frang_limits {http_methods post put; http_strict_host_checking false;}
                        location prefix "/vhost_1" {cache_fulfill * *; proxy_pass default;}
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_inheritance(self, name, config: str):
        """
        The vhost/location inherits the last `frang_limits` so Tempesta MUST block request with
        GET method. By default `http_methods` is get post head.
        """
        self.__update_tempesta_config(config)
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(client.create_request(method="GET", uri="/vhost_1", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    @unlimited_rate_on_tempesta_node
    def test_inheritance_global_to_location(self):
        """
        The global location inherit the last `frang_limits` so Tempesta MUST block
        request with GET method because `http_methods` in global config is post put.
        """
        self.__update_tempesta_config(
            """
            frang_limits {http_methods post put; http_strict_host_checking false;}
            location prefix "/vhost_1" {cache_fulfill * *;}
        """
        )
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(client.create_request(method="GET", uri="/vhost_1", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    @unlimited_rate_on_tempesta_node
    def test_inheritance_vhost_to_location_limits_after_location(self):
        """
        Tempesta config has a frang_limits in vhost after location and:
          - default location in vhost inherits this frang_limits;
          - location before frang_limits in vhost inherits a default (implicit) frang_limits;
        """
        self.__update_tempesta_config(
            """
            vhost vhost_1 {
                frang_limits {http_strict_host_checking false;}
                proxy_pass default;
                location prefix "/vhost_1" {cache_fulfill * *; proxy_pass default;}
                frang_limits {http_methods post put;}
            }
            http_chain {-> vhost_1;}
        """
        )
        self.start_all_services()
        client = self.get_client("deproxy")

        # request to location /vhost_1 with http_methods get post head (global limits)
        client.send_request(client.create_request(method="GET", uri="/vhost_1", headers=[]), "200")
        self.oops.update()
        self.assertEqual(0, len(self.oops.log_findall("frang: restricted HTTP method for")))

        # request to vhost vhost_1 with http_methods post put (vhost limits and default location)
        client.send_request(client.create_request(method="HEAD", uri="/", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    @parameterize.expand(
        [
            param(
                name="location_via_vhost",
                config="""
                    vhost vhost_1 {
                        frang_limits {http_strict_host_checking false;}
                        proxy_pass default;
                        location prefix "/vhost_1" {cache_fulfill * *; proxy_pass default;}
                        location prefix "/vhost_2" {cache_fulfill * *; proxy_pass default;}
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="vhost",
                config="""
                    frang_limits {http_strict_host_checking false;}
                    vhost vhost_1 {proxy_pass default;}
                    vhost vhost_2 {proxy_pass default;}
                    http_chain {uri == "/vhost_1" -> vhost_1; uri == "/vhost_2" -> vhost_2;}
                """,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_inheritance_default_to_several(self, name, config: str):
        """
        All vhost/location inherits the default `frang_limits` so Tempesta MUST NOT block same
        requests to different vhost/location because they have same frang_limits.
        """
        self.__update_tempesta_config(config)
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(client.create_request(method="GET", uri="/vhost_1", headers=[]), "200")
        client.send_request(client.create_request(method="GET", uri="/vhost_2", headers=[]), "200")
        self.oops.update()
        self.assertEqual(0, len(self.oops.log_findall("frang: ")))

    @parameterize.expand(
        [
            param(
                name="global_to_vhost",
                config="""
                    frang_limits {http_methods get post put;}
                    vhost vhost_1 {proxy_pass default; frang_limits {http_methods post put;}}
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="global_to_location",
                config="""
                    frang_limits {http_methods get post put;}
                    location prefix "/vhost_1" {
                        cache_fulfill * *; 
                        frang_limits {http_methods post put;}
                    }
                """,
            ),
            param(
                name="global_to_location_via_vhost",
                config="""
                    frang_limits {http_methods get post put;}
                    vhost vhost_1 {
                        proxy_pass default;
                        location prefix "/vhost_1" {
                            cache_fulfill * *; 
                            proxy_pass default;
                            frang_limits {http_methods post put;}
                        }
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
            param(
                name="vhost_to_location",
                config="""
                    vhost vhost_1 {
                        proxy_pass default;
                        frang_limits {http_methods get post put;}
                        location prefix "/vhost_1" {
                            cache_fulfill * *; 
                            proxy_pass default;
                            frang_limits {http_methods post put;}
                        }
                    }
                    http_chain {-> vhost_1;}
                """,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_overriding(self, name, config: str):
        """
        Tempesta has different frang limits in global/vhost/location.
        """
        self.__update_tempesta_config(config)
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(client.create_request(method="GET", uri="/vhost_1", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    def _test_not_override_http_methods(self):
        client = self.get_client("deproxy")
        client.start()
        client.send_request(client.create_request(method="GET", headers=[]), "403")
        self.assertTrue(self.oops.find("frang: restricted HTTP method for"))

    def _test_not_override_concurrent_tcp_connections(self):
        client = self.get_client("deproxy")
        client_1 = self.get_client("deproxy_1")
        client.start()
        client_1.start()

        client.make_request(client.create_request(method="GET", headers=[]))
        client_1.make_request(client.create_request(method="GET", headers=[]))

        client.wait_for_response(timeout=2)
        client_1.wait_for_response(timeout=2)

        self.assertTrue(self.oops.find("frang: connections max num. exceeded for"))
        self.assertEqual(1, len(client.responses) + len(client_1.responses))

    def _test_not_override_http_body_len_0(self):
        client = self.get_client("deproxy_http")
        client.start()
        request = (
            f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n{'x' * 1000}"
        )
        client.send_request(request, "200")
        self.assertFalse(self.oops.find("frang: HTTP body length exceeded for"))

    def _test_not_override_http_body_len_1(self):
        client = self.get_client("deproxy_http")
        client.start()
        request = f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{'x' * 2}"
        client.send_request(request, "403")
        self.assertTrue(self.oops.find("frang: HTTP body length exceeded for"))

    def _test_not_override_http_body_len_2(self):
        client = self.get_client("deproxy_http")
        client.start()
        request = f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{'x' * 2}"
        client.send_request(request, "200")
        self.assertFalse(self.oops.find("frang: HTTP body length exceeded for"))

    def _test_not_override_http_resp_code_block_1(self):
        client = self.get_client("deproxy")
        client.start()
        client.make_request(client.create_request(method="GET", headers=[]))
        client.make_request(client.create_request(method="GET", headers=[]))
        client.make_request(client.create_request(method="GET", headers=[]))
        client.wait_for_response(5)
        self.assertFalse(self.oops.find("frang: http_resp_code_block limit exceeded for"))

    def _test_not_override_http_resp_code_block_2(self):
        client = self.get_client("deproxy")
        client.start()
        client.make_request(client.create_request(method="GET", headers=[]))
        client.make_request(client.create_request(method="GET", headers=[]))
        client.wait_for_response(5)
        self.assertTrue(self.oops.find("frang: http_resp_code_block limit exceeded for"))
        self.assertEqual(len(client.responses), 2)

    @parameterize.expand(
        [
            param(
                name="http_methods",
                config="""
                    frang_limits {http_methods post put;}
                    frang_limits {}
                    """,
                test_function=_test_not_override_http_methods,
            ),
            param(
                name="concurrent_tcp_connections",
                config="""
                    frang_limits {concurrent_tcp_connections 1;}
                    frang_limits {}
                    """,
                test_function=_test_not_override_concurrent_tcp_connections,
            ),
            param(
                name="http_body_len_0",
                config="""
                    frang_limits {http_body_len 0;}
                    frang_limits {}
                    """,
                test_function=_test_not_override_http_body_len_0,
            ),
            param(
                name="http_body_len_1",
                config="""
                    frang_limits {http_body_len 1;}
                    frang_limits {}
                    """,
                test_function=_test_not_override_http_body_len_1,
            ),
            param(
                name="http_body_len_2",
                config="""
                    frang_limits {http_body_len 1;}
                    frang_limits {http_body_len 3;}
                    """,
                test_function=_test_not_override_http_body_len_2,
            ),
            param(
                name="http_body_len_3",
                config="""
                    frang_limits {http_body_len 1;}
                    vhost test {
                        frang_limits {http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_not_override_http_body_len_1,
            ),
            param(
                name="http_body_len_4",
                config="""
                    frang_limits {http_body_len 10;}
                    vhost test {
                        frang_limits {}
                        frang_limits {http_body_len 1; http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_not_override_http_body_len_1,
            ),
            param(
                name="http_body_len_5",
                config="""
                    vhost test {
                        frang_limits {http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_not_override_http_body_len_2,
            ),
            param(
                name="http_resp_code_block_1",
                config="""
                    frang_limits {http_resp_code_block 200 1 1;}
                    frang_limits {http_resp_code_block 201 1 1;}
                    """,
                test_function=_test_not_override_http_resp_code_block_1,
            ),
            param(
                name="http_resp_code_block_2",
                config="""
                    frang_limits {http_resp_code_block 201 1 1;}
                    frang_limits {http_resp_code_block 200 1 1;}
                    """,
                test_function=_test_not_override_http_resp_code_block_2,
            ),
            param(
                name="http_resp_code_block_3",
                config="""
                    vhost test {
                        frang_limits{}
                        frang_limits {http_resp_code_block 201 1 1;}
                        frang_limits {http_resp_code_block 200 1 1; http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_not_override_http_resp_code_block_2,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_default_not_override(self, name, config: str, test_function):
        """
        This test checks that default value from second frang config
        doesn't override previoulsy set value.
        This test also checks that not default value from second config
        override previoulsy set value.
        """
        self.__update_tempesta_config(config)
        self.start_all_services(client=False)
        test_function(self)

    def _test_override_http_methods_after_reload(self):
        client = self.get_client("deproxy")
        client.start()
        client.send_request(client.create_request(method="GET", headers=[]), "200")
        self.assertFalse(self.oops.find("frang: restricted HTTP method for"))

    @parameterize.expand(
        [
            param(
                name="http_methods",
                first_config="""
                    frang_limits {http_methods post put;}
                    frang_limits {}
                    """,
                second_config="""
                    frang_limits {}
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_default_override_after_reload(
        self, name, first_config: str, second_config: str, test_function
    ):
        """
        Same as previous, but checks it after Tempesta FW
        reload.
        """
        config = self.get_tempesta().config.defconfig
        self.__update_tempesta_config(first_config)
        self.start_all_services(client=False)
        self.get_tempesta().config.defconfig = config
        self.__update_tempesta_config(second_config)
        self.get_tempesta().reload()
        test_function(self)

    @parameterize.expand(
        [
            param(
                name="http_methods",
                first_config="""
                    frang_limits {http_methods post put;}
                    frang_limits {}
                    """,
                second_config="""
                    frang_limits {}
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
            param(
                name="http_methods_1",
                first_config="""
                    vhost test {
                        frang_limits {http_methods post put; http_strict_host_checking false;}
                        frang_limits {}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                second_config="""
                    vhost test {
                        frang_limits {http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
            param(
                name="http_body_len",
                first_config="""
                    frang_limits {http_body_len 1;}
                    frang_limits {}
                    """,
                second_config="""
                    frang_limits {}
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
            param(
                name="http_body_len_1",
                first_config="""
                    vhost test {
                        frang_limits {http_body_len 1;}
                        frang_limits {}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                second_config="""
                    vhost test {
                        frang_limits {http_strict_host_checking false;}
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
            param(
                name="http_body_len_3",
                first_config="""
                    vhost test {
                        location prefix / {
                            frang_limits {http_body_len 1;}
                            proxy_pass default;
                        }
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                second_config="""
                    vhost test {
                        location prefix / {
                            frang_limits {http_strict_host_checking false;}
                            proxy_pass default;
                        }
                        proxy_pass default;
                    }
                    http_chain {
                        ->test;
                    }
                    """,
                test_function=_test_override_http_methods_after_reload,
            ),
        ]
    )
    @unlimited_rate_on_tempesta_node
    def test_default_override_after_fail_reload(
        self, name, first_config: str, second_config: str, test_function
    ):
        """
        Same as previous, but checks it after Tempesta FW
        reload after fail reload.
        """
        config = self.get_tempesta().config.defconfig
        self.__update_tempesta_config(first_config)
        self.start_all_services(client=False)
        self.oops_ignore.append("ERROR")

        wrong_config = """
            frang_limits { "wrong_config" }
        """
        self.get_tempesta().config.defconfig = config
        self.__update_tempesta_config(wrong_config)

        with self.assertRaises(
            expected_exception=CmdError, msg="TempestaFW reloads with wrong config"
        ):
            self.oops_ignore = ["ERROR"]
            self.get_tempesta().reload()

        self.get_tempesta().config.defconfig = config
        self.__update_tempesta_config(second_config)
        self.get_tempesta().reload()
        test_function(self)
