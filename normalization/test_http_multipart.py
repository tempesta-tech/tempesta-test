"""
Checks whenever Content-Type header field value is being sanitized as expected.
"""

import itertools
import textwrap

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ContentTypeTestBase(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.0 200 OK\r\n" + "Content-Length: 0\r\n" + "\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def setUp(self):
        super(ContentTypeTestBase, self).setUp()
        self.deproxy_srv = self.get_server("deproxy")
        self.deproxy_srv.start()
        self.assertEqual(0, len(self.deproxy_srv.requests))

        self.start_tempesta()

        self.deproxy_cl = self.get_client("deproxy")
        self.deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(self.deproxy_srv.wait_for_connections(timeout=3))

    def do_test_replacement(self, content_type, expected_content_type):
        """Perform a parametrized test of Content-Type string.

        content_type may contain any number of placeholders ({}) which will be
        replaced by combinations of whitespace characters in cycle.
        """
        number_of_whitespace_places = content_type.count("{}")
        request_tmpl = (
            "POST / HTTP/1.1\r\n"
            + "Host: localhost\r\n"
            + "Content-Type:"
            + content_type
            + "\r\n"
            + "Content-Length: 0\r\n"
            + "\r\n"
        )

        for state in itertools.product(
            ["", " ", "\t", " \t", "\t "], repeat=number_of_whitespace_places
        ):
            request = request_tmpl.format(*state)
            self.deproxy_cl.make_request(request)
            resp = self.deproxy_cl.wait_for_response(timeout=5)
            self.assertTrue(resp, "Response not received")

        for server_req in self.deproxy_srv.requests:
            found_content_type_field = False
            val = server_req.headers["Content-Type"]
            self.assertIsNotNone(val)
            self.assertEqual(val, expected_content_type)

    def expect_content_type_rebuilt(self):
        self.do_test_replacement(
            " multipart/form-data; tmp=123; boundary=456", "multipart/form-data; boundary=456"
        )

    def expect_content_type_intact(self):
        self.do_test_replacement(
            " multipart/form-data; tmp=123; boundary=456",
            "multipart/form-data; tmp=123; boundary=456",
        )


class ContentTypeHeaderReconstructTest(ContentTypeTestBase):
    """Ensure Content-Type header field value is sanitized."""

    tempesta = {
        "config": textwrap.dedent(
            """\
            server ${server_ip}:8000;
            vhost default {
                location prefix / {
                    http_post_validate;
                    proxy_pass default;
                }
                proxy_pass default;
            }
            http_chain {
                -> default;
            }
            """
        ),
    }

    def test_replacement_unquoted_1(self):
        self.do_test_replacement(
            'multiPART/form-data;{}boundary=helloworld{};{}o_param="123" ',
            "multipart/form-data; boundary=helloworld",
        )

    def test_replacement_unquoted_2(self):
        self.do_test_replacement(
            'multiPART/form-data;{}o_param="123";{}boundary=helloworld{}',
            "multipart/form-data; boundary=helloworld",
        )

    def test_replacement_quoted(self):
        self.do_test_replacement(
            '{}multiPart/form-data{}; boundary="helloworld"{}',
            'multipart/form-data; boundary="helloworld"',
        )

    def test_replacement_escaped(self):
        self.do_test_replacement(
            ' multiPart/form-data; boundary="hello\\"world"',
            'multipart/form-data; boundary="hello\\"world"',
        )


class ConfigParameterAbsent(ContentTypeTestBase):
    """No changes should be made if sanitization wasn't enabled."""

    tempesta = {
        "config": textwrap.dedent(
            """\
            server ${server_ip}:8000;
            vhost default {
                location prefix / {
                    proxy_pass default;
                }
                proxy_pass default;
            }
            http_chain {
                -> default;
            }
            """
        ),
    }

    def test(self):
        self.expect_content_type_intact()


class ConfigParameterAtTopLevel(ContentTypeTestBase):
    """Test that 'http_post_validate' at top level of a config works."""

    tempesta = {
        "config": textwrap.dedent(
            """\
            http_post_validate;
            server ${server_ip}:8000;
            vhost default {
                location prefix / {
                    proxy_pass default;
                }
                proxy_pass default;
            }
            http_chain {
                -> default;
            }
            """
        ),
    }

    def test(self):
        self.expect_content_type_rebuilt()


class ConfigParameterAtVhost(ContentTypeTestBase):
    """Test that 'http_post_validate' at vhost level of a config works."""

    tempesta = {
        "config": textwrap.dedent(
            """\
            server ${server_ip}:8000;
            vhost default {
                http_post_validate;
                location prefix / {
                    proxy_pass default;
                }
                proxy_pass default;
            }
            http_chain {
                -> default;
            }
            """
        ),
    }

    def test(self):
        self.expect_content_type_rebuilt()


class ConfigParameterAtLocation(ContentTypeTestBase):
    """Test that 'http_post_validate' at location level of a config works."""

    tempesta = {
        "config": textwrap.dedent(
            """\
            server ${server_ip}:8000;
            vhost default {
                location prefix / {
                    http_post_validate;
                    proxy_pass default;
                }
                proxy_pass default;
            }
            http_chain {
                -> default;
            }
            """
        ),
    }

    def test(self):
        self.expect_content_type_rebuilt()
