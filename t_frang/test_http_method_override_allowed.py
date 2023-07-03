"""Tests for Frang directive `http_method_override_allowed`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase, H2Config

WARN = "frang: restricted HTTP method"
WARN_ERROR = "frang: restricted overridden HTTP method"
WARN_UNSAFE = "request dropped: unsafe method override:"

ACCEPTED_REQUESTS = [
    "POST / HTTP/1.1\r\n" + "Host: tempesta-tech.com\r\n" + "X-HTTP-Method-Override: PUT\r\n\r\n",
    "POST / HTTP/1.1\r\n" + "Host: tempesta-tech.com\r\n" + "X-Method-Override: PUT\r\n\r\n",
    "POST / HTTP/1.1\r\n" + "Host: tempesta-tech.com\r\n" + "X-HTTP-Method: PUT\r\n\r\n",
]

REQUEST_FALSE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: POST\r
X-Method-Override: POST\r
X-HTTP-Method: POST\r
\r
"""

DOUBLE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: PUT\r
Http-Method: GET\r
\r
"""

MULTIPLE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: GET\r
X-HTTP-Method-Override: PUT\r
X-HTTP-Method-Override: GET\r
X-HTTP-Method: GET\r
X-HTTP-Method-Override: PUT\r
X-Method-Override: GET\r
\r
"""


class FrangHttpMethodsOverrideTestCase(FrangTestCase):
    def test_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=ACCEPTED_REQUESTS
            + [
                REQUEST_FALSE_OVERRIDE,
                DOUBLE_OVERRIDE,
                MULTIPLE_OVERRIDE,
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg="frang: ")

    def test_not_accepted_request_x_http_method_override(self):
        """
        override methods not allowed by limit http_methods
        for X_HTTP_METHOD_OVERRIDE
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[
                "POST / HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method-Override: OPTIONS\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_not_accepted_request_x_method_override(self):
        """
        override methods not allowed by limit http_methods
        for X_METHOD_OVERRIDE
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\nX-Method-Override: OPTIONS\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_not_accepted_request_x_http_method(self):
        """
        override methods not allowed by limit http_methods
        for X_HTTP_METHOD
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[
                "POST / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-HTTP-Method: OPTIONS\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_unsafe_override_x_http_method_override(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-HTTP-Method-Override
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[
                "GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-HTTP-Method-Override: POST\r\n\r\n"
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_unsafe_override_x_http_method(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-HTTP-Method
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=["GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-HTTP-Method: POST\r\n\r\n"],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_unsafe_override_x_method_override(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-Method-Override
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[
                "GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-Method-Override: POST\r\n\r\n"
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_default_http_method_override_allowed(self):
        """Test default `http_method_override_allowed` value."""
        client = self.base_scenario(
            frang_config="http_methods post put get;",
            requests=[
                "POST / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-Method-Override: PUT\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)


class FrangHttpMethodsOverrideH2(H2Config, FrangHttpMethodsOverrideTestCase):
    def test_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[
                self.post_request + [("x-http-method-override", "PUT")],
                self.post_request + [("x-http-method-override", "PUT")],  # from dynamic table
                self.post_request + [("x-method-override", "PUT")],
                self.post_request + [("x-method-override", "PUT")],  # from dynamic table
                self.post_request + [("x-http-method", "PUT")],
                self.post_request + [("x-http-method", "PUT")],  # from dynamic table
                self.post_request
                + [
                    ("x-http-method-override", "POST"),
                    ("x-method-override", "POST"),
                    ("x-http-method", "POST"),
                ],
                self.post_request
                + [
                    ("x-http-method-override", "PUT"),
                    ("x-http-method", "GET"),
                ],
                self.post_request
                + [
                    ("x-http-method-override", "GET"),
                    ("x-http-method-override", "PUT"),
                    ("x-http-method-override", "GET"),
                    ("x-http-method", "GET"),
                    ("x-http-method-override", "PUT"),
                    ("x-method-override", "GET"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg="frang: ")

    def test_not_accepted_request_x_http_method_override(self):
        """
        override methods not allowed by limit http_methods
        for X_HTTP_METHOD_OVERRIDE
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.post_request + [("x-http-method-override", "OPTIONS")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_not_accepted_request_x_method_override(self):
        """
        override methods not allowed by limit http_methods
        for X_METHOD_OVERRIDE
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.post_request + [("x-method-override", "OPTIONS")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_not_accepted_request_x_http_method(self):
        """
        override methods not allowed by limit http_methods
        for X_HTTP_METHOD
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.post_request + [("x-http-method", "OPTIONS")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)

    def test_unsafe_override_x_http_method_override(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-HTTP-Method-Override
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.get_request + [("x-http-method-override", "POST")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_unsafe_override_x_http_method(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-HTTP-Method
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.get_request + [("x-http-method", "POST")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_unsafe_override_x_method_override(self):
        """
        should not be allowed to be overridden by unsafe methods
        for X-Method-Override
        """
        client = self.base_scenario(
            frang_config="http_method_override_allowed true;\n\thttp_methods post put get;",
            requests=[self.get_request + [("x-method-override", "POST")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="400", warning_msg=WARN_UNSAFE)

    def test_default_http_method_override_allowed(self):
        """Test default `http_method_override_allowed` value."""
        client = self.base_scenario(
            frang_config="http_methods post put get;",
            requests=[self.post_request + [("x-method-override", "PUT")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=WARN_ERROR)
