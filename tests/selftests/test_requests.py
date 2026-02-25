import unittest

from framework.deproxy import deproxy_message

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ParseRequest(unittest.TestCase):
    async def asyncSetUp(self):
        self.plain = deproxy_message.Request(PLAIN)
        self.reordered = deproxy_message.Request(REORDERED)
        self.duplicated = deproxy_message.Request(DUPLICATED)

    def test_equal(self):
        # Reordering of headers is allowed.
        self.plain.set_expected()
        self.assertEqual(self.plain, self.reordered)
        with self.assertRaises(AssertionError, msg="Requests are unexpectedly equal"):
            self.assertEqual(self.plain, self.duplicated)
        self.reordered.set_expected()
        with self.assertRaises(AssertionError, msg="Requests are unexpectedly equal"):
            self.assertEqual(self.reordered, self.duplicated)

    def test_parse(self):
        self.assertEqual(self.plain.method, "GET")
        self.assertEqual(self.plain.uri, "/foo")
        self.assertEqual(self.plain.version, "HTTP/1.1")

        headers = [
            ("User-Agent", "Wget/1.13.4 (linux-gnu)"),
            ("Accept", "*/*"),
            ("Host", "localhost"),
            ("Connection", "Keep-Alive"),
            ("X-Custom-Hdr", "custom header values"),
            ("X-Forwarded-For", "127.0.0.1, example.com"),
            ("Content-Type", "text/html; charset=iso-8859-1"),
            ("Cache-Control", "max-age=1, no-store, min-fresh=30"),
            ("Pragma", "no-cache, fooo"),
            ("Cookie", "session=42; theme=dark"),
            ("Authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ]
        for header, value in headers:
            self.assertEqual(self.plain.headers[header], value.strip())

        self.assertEqual(self.plain.body, "")


PLAIN = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

"""

# Reordered:
REORDERED = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Cache-Control: max-age=1, no-store, min-fresh=30
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Pragma: no-cache, fooo
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

"""

# With duplicated header:
DUPLICATED = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
X-Custom-Hdr: other custom header values

"""

if __name__ == "__main__":
    unittest.main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
