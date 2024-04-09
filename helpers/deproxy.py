"""
Main utils and API for deproxy.

Deproxy combines HTTP client and server, so that it can check data consistency
on both the parts, e.g. easily verify requests/response pairing in HTTP
pipeline scenario. It's intended to check HTTP functionality in various aspects.

Use implemented in C clients (e.g. wrk) and servers (e.g. nginx) if you need
a test with heavy load condition.

Our Request/Response implementation differs from http.lib. We use these classes
like a wrapper for http message and in some cases we can manually instantiate
objects of these classes to construct message.
"""

from __future__ import print_function

import abc
import asyncore
import calendar  # for calendar.timegm()
import copy
import errno
import re
import select
import socket
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler
from io import StringIO
from typing import List, Tuple

import run_config

from . import error, stateful, tempesta, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

# -------------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------------


def dbg(deproxy, level, message, *args, prefix="", use_getsockname=True, **kwargs):
    assert isinstance(deproxy, asyncore.dispatcher)
    sockname = f" {util.getsockname_safe(deproxy.socket)}" if use_getsockname else ""
    msg = f"{prefix}Deproxy: {deproxy.__class__.__name__}{sockname}: {message}"
    tf_cfg.dbg(level, msg, *args, **kwargs)


class ParseError(Exception):
    pass


class IncompleteMessage(ParseError):
    pass


class HeaderCollection(object):
    """
    A collection class for HTTP Headers. This class combines aspects of a list
    and a dict. Lookup is always case-insensitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self, mapping=None, **kwargs):
        self.headers = []
        self.is_expected = False
        self.expected_time_delta = 0
        if mapping is not None:
            for k, v in mapping.items():
                self.add(k, v)
        if kwargs is not None:
            for k, v in kwargs.items():
                self.add(k, v)

    def set_expected(self, expected_time_delta=0):
        self.is_expected = True
        self.expected_time_delta = expected_time_delta

    def __contains__(self, item):
        item = item.lower()
        for header in self.headers:
            if header[0].lower() == item:
                return True
        return False

    def __len__(self):
        return self.headers.__len__()

    def __getitem__(self, key):
        key = key.lower()
        for header in self.headers:
            if header[0].lower() == key:
                return header[1]

    def __setitem__(self, key, value):
        lower = key.lower()
        for i, header in enumerate(self.headers):
            if header[0].lower() == lower:
                self.headers[i] = (header[0], value)
                return
        self.add(key.lower(), value)

    def __delitem__(self, key):
        self.delete_all(name=key)

    def __iter__(self):
        return self.iterkeys()

    def add(self, name, value):
        self.headers.append(
            (
                name,
                value,
            )
        )

    def find_all(self, name):
        name = name.lower()
        for header in self.headers:
            if header[0].lower() == name:
                yield header[1]

    def delete_all(self, name):
        lower = name.lower()
        self.headers = [header for header in self.headers if header[0].lower() != lower]

    def iterkeys(self):
        for header in self.headers:
            yield header[0]

    def itervalues(self):
        for header in self.headers:
            yield header[1]

    def iteritems(self):
        for header in self.headers:
            yield header

    def keys(self):
        return [key.lower() for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    @staticmethod
    def from_stream(rfile, no_crlf=False, is_h2=False):
        headers = HeaderCollection()
        line = rfile.readline()
        while not (line == "\r\n" or line == "\n"):
            if no_crlf and not line:
                break
            if not line or (line[-1] != "\n"):
                raise IncompleteMessage("Incomplete headers field")
            line = line.rstrip("\r\n")
            try:
                # h2 pseuodo-header
                if is_h2 and line.startswith(":"):
                    split = line.split(":", 2)
                    name, value = ":" + "".join(split[:2]), "".join(split[2:])
                else:
                    name, value = line.split(":", 1)
            except:
                raise ParseError("Invalid header format: [%s]" % line)
            name = name.strip()
            value = value.strip()
            line = rfile.readline()
            if "\n" not in line[-2:]:
                raise IncompleteMessage("Incomplete headers")
            while line.startswith(" ") or line.startswith("\t"):
                # Continuation lines - see RFC 2616, section 4.2
                value += " " + line.strip()
                line = rfile.readline()
            headers.add(name, value)
        return headers

    def _as_dict_lower(self):
        ret = {}
        for hed, val in self.items():
            ret.setdefault(hed.lower(), []).append(val)
        return ret

    _disable_report_wrong_is_expected = False

    def _report_wrong_is_expected(self, other):
        if not HeaderCollection._disable_report_wrong_is_expected:
            error.bug(
                "HeaderCollection: comparing is_expected=(%s, %s)\n"
                % (self.is_expected, other.is_expected)
            )

    def __eq__(self, other: "HeaderCollection"):
        h_self = self._as_dict_lower()
        h_other = other._as_dict_lower()

        if self.is_expected == other.is_expected:
            self._report_wrong_is_expected(other)
        else:
            if self.is_expected:
                h_expected, h_received = h_self, h_other
                expected_time_delta = self.expected_time_delta
            else:
                h_expected, h_received = h_other, h_self
                expected_time_delta = other.expected_time_delta

            self.__check_date_header(h_expected, h_received, expected_time_delta)
            self.__check_age_header(h_expected, h_received)
            self.__check_connection_header(h_expected, h_received)
            self.__check_warning_header(h_expected, h_received)
            self.__check_other_headers(h_expected, h_received)
            return True

    @staticmethod
    def __check_date_header(h_expected: dict, h_received: dict, expected_time_delta: int) -> None:
        """
        Special-case "Date:" header if both headers have it and it looks OK (i. e. not duplicated)
        """
        if len(h_expected.get("date", [])) == 1 and len(h_received.get("date", [])) == 1:
            date_expected = h_expected.pop("date")[0]
            date_received = h_received.pop("date")[0]
            ts_expected = HttpMessage.parse_date_time_string(date_expected)
            ts_received = HttpMessage.parse_date_time_string(date_received)

            # Tempesta and general VMs (remote setup) may have different timestamp
            # and Tempesta may add a date less than expected
            half_time_delta = expected_time_delta / 2
            assert ts_expected - half_time_delta <= ts_received <= ts_expected + half_time_delta, (
                f"Header 'date' is invalid."
                f"\nReceived: {date_received}."
                f"\nExpected: {date_expected}."
            )

    @staticmethod
    def __check_age_header(h_expected: dict, h_received: dict) -> None:
        """
        Special-case "Age:". Expected message MAY not contain this header
            - compare values if 'age' header is present in expected message or;
            - check value in received message. Value MUST be integer and greater than 0.
        """
        r_age = h_received.pop("age", [])
        e_age = h_expected.pop("age", [])

        if len(r_age) == 1 and len(e_age) == 1:
            assert int(r_age[0]) >= int(
                e_age[0]
            ), f"Header 'Age' is invalid.\nReceived: {r_age}\nExpected: {e_age}"
        elif r_age:
            assert len(r_age) <= 1, "Tempesta forwarded a response with several 'age' headers."

            age = int(r_age[0])
            assert age >= 0, f"Header 'age' is invalid.\nReceived: {age}."

    @staticmethod
    def __check_connection_header(h_expected: dict, h_received: dict) -> None:
        """
        Special-case "Connection:" it is hop-by-hop header and Tempesta MAY remove it
            - compare values if 'connection' header is present in expected message or;
            - check value in received message. Value MUST be 'keep-alive' or 'close'.
        """
        r_connections = h_received.pop("connection", [])
        e_connections = h_expected.pop("connection", [])

        if r_connections and e_connections:
            assert r_connections == e_connections, "Invalid 'Connection' header."
        else:
            assert (
                len(r_connections) <= 1
            ), "Tempesta forwarded a response with several 'Connection' headers."
            if r_connections:
                assert r_connections[0] in ["close", "keep-alive"], (
                    "Tempesta forwarded a response with invalid"
                    f" 'Conneciton' header - {r_connections[0]}."
                )

    @staticmethod
    def __check_warning_header(h_expected: dict, h_received: dict) -> None:
        """Special-case "Warning:". Tempesta MAY add it in some cases."""
        r_warnings = h_received.pop("warning", [])
        e_warnings = h_expected.pop("warning", [])

        if r_warnings and e_warnings:
            assert (
                r_warnings == e_warnings
            ), f"Header 'Warning' is invalid.\nReceived: {r_warnings}\nExpected: {e_warnings}"
        elif r_warnings:
            for r_warning in r_warnings:
                assert r_warning in [
                    "110 - Response is stale",
                    "111 - Revalidation Failed",
                    "112 - Disconnected Operation",
                    "113 - Heuristic Expiration",
                    "199 - Miscellaneous Warning",
                    "214 - Transformation Applied",
                    "299 - Miscellaneous Persistent Warning",
                ], f"Tempesta add a invalid 'Warning' header - {r_warning}"

    @staticmethod
    def __check_other_headers(h_expected: dict, h_received: dict) -> None:
        headers = h_expected if len(h_expected) > len(h_received) else h_received
        for header_name in headers.keys():
            received_header_value = h_received.get(header_name, None)
            expected_header_value = h_expected.get(header_name, None)
            assert received_header_value == expected_header_value, (
                f'Invalid header in headers or trailers.\nHeader name: "{header_name}"'
                f"\nReceived: {received_header_value}\nExpected: {expected_header_value}"
            )

    def __ne__(self, other):
        return not HeaderCollection.__eq__(self, other)

    def __str__(self):
        return "".join(["%s: %s\r\n" % (hed, val) for hed, val in self.items()])

    def __repr__(self):
        return repr(self.headers)


# -------------------------------------------------------------------------------
# HTTP Messages
# -------------------------------------------------------------------------------


class HttpMessage(object, metaclass=abc.ABCMeta):
    def __init__(self, message_text=None, body_parsing=True, method="GET", keep_original_data=None):
        self.msg = ""
        self.original_length = 0
        self.method = method
        self.body_parsing = True
        self.headers = HeaderCollection()
        self.trailer = HeaderCollection()
        self.body = ""
        self.keep_original_data = keep_original_data
        self.original_data = ""
        self.version = "HTTP/0.9"  # default version.
        if message_text:
            self.parse_text(message_text, body_parsing)

    def parse_text(self, message_text, body_parsing=True):
        self.body_parsing = body_parsing
        stream = StringIO(message_text)
        self.__parse(stream)
        self.build_message()
        self.original_length = stream.tell()
        if self.keep_original_data:
            self.original_data = message_text[: self.original_length]

    def __parse(self, stream):
        self.parse_firstline(stream)
        self.parse_headers(stream)
        self.body = ""
        if self.body_parsing:
            self.parse_body(stream)
        else:
            self.body = stream.read()

    def build_message(self):
        self.msg = str(self)

    @abc.abstractmethod
    def parse_firstline(self, stream):
        pass

    @abc.abstractmethod
    def parse_body(self, stream):
        pass

    def get_firstline(self):
        return ""

    def parse_headers(self, stream):
        self.headers = HeaderCollection.from_stream(stream)

    def read_encoded_body(self, stream, is_req):
        """RFC 7230. 3.3.3 #3"""
        enc = self.headers["Transfer-Encoding"]
        option = enc.split(",")[-1]  # take the last option

        if option.strip().lower() == "chunked":
            self.read_chunked_body(stream)
        else:
            if is_req:
                raise ParseError("Unlimited body not allowed for requests")
            self.read_rest_body(stream)

    def read_rest_body(self, stream):
        """RFC 7230. 3.3.3 #7"""
        self.body = stream.read()

    def read_chunked_body(self, stream):
        while True:
            line = stream.readline()
            if not line:
                raise IncompleteMessage("Empty chunk in chunked body.")

            self.body += line
            try:
                size = int(line.rstrip("\r\n").split(";")[0], 16)  # parse for value "9;extensions"
                assert size >= 0
                if size == 0:
                    break
                chunk = stream.readline()
                self.body += chunk

                chunk_size = len(chunk.rstrip("\r\n"))
                if chunk_size < size or "\n" not in chunk[-2:]:
                    raise IncompleteMessage("Incomplete chunk in chunked body")
                assert chunk_size == size
            except IncompleteMessage:
                raise
            except:
                raise ParseError("Error in chunked body")

        """
        if trailer is not present don't pass the last CRLF to parse_trailer,
        we must append it to body
        """
        pos = stream.tell()
        end = stream.read(2)
        if end and end.rstrip("\r\n") == "":
            self.body += end
            if 2 != self.body[-3:].count("\n"):
                raise IncompleteMessage("Incomplete chunked body.")
            return
        elif end == "":
            raise IncompleteMessage("Incomplete last CRLF in chunked body.")

        stream.seek(pos)
        # Parsing trailer will eat last CRLF
        self.parse_trailer(stream)

    def convert_chunked_body(self):
        chunked_lines = self.body.split("\r\n")
        self.body = "".join(chunked_lines[1::2])

    def read_sized_body(self, stream):
        """RFC 7230. 3.3.3 #5"""
        size = int(self.headers["Content-Length"])

        self.body = stream.read(size)
        if len(self.body) > size:
            raise ParseError(("Wrong body size: expect %d but got %d!" % (size, len(self.body))))
        elif len(self.body) < size:
            tf_cfg.dbg(5, "Incomplete message received")
            raise IncompleteMessage()

    def parse_trailer(self, stream):
        self.trailer = HeaderCollection.from_stream(stream, no_crlf=True)

    @abc.abstractmethod
    def __eq__(self, other: "HttpMessage"):
        assert (
            self.body == other.body
        ), f"Invalid http body. \nReceived:\n{self.body}\nExpected:\n{other.body}"
        self.headers.__eq__(other.headers)
        self.trailer.__eq__(other.trailer)
        return True

    @abc.abstractmethod
    def __ne__(self, other):
        return not HttpMessage.__eq__(self, other)

    def __str__(self):
        return "".join(
            [self.get_firstline(), "\r\n", str(self.headers), "\r\n", self.body, str(self.trailer)]
        )

    def update(self):
        self.parse_text(str(self))

    def set_expected(self, *args, **kwargs):
        for obj in [self.headers, self.trailer]:
            obj.set_expected(*args, **kwargs)

    @staticmethod
    def date_time_string(timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        struct_time = time.gmtime(timestamp)
        s = time.strftime("%a, %02d %3b %4Y %02H:%02M:%02S GMT", struct_time)
        return s

    @staticmethod
    def parse_date_time_string(s):
        """Return a timestamp corresponding to the given Date: header."""
        struct_time = time.strptime(s, "%a, %d %b %Y %H:%M:%S GMT")
        timestamp = calendar.timegm(struct_time)
        return timestamp

    @staticmethod
    def create(first_line, headers, date=None, srv_version=None, body=""):
        headers = copy.deepcopy(headers)
        if headers and isinstance(headers[0], tuple):
            headers = [f"{header[0]}: {header[1]}" for header in headers]
        if date:
            date = "".join(["date: ", date])
            headers.append(date)
        if srv_version:
            version = "".join(["Server: ", srv_version])
            headers.append(version)
        end = ["", body] if body else ["\r\n"]
        return "\r\n".join([first_line] + headers + end)


class Request(HttpMessage):
    # All methods registered in IANA.
    # https://www.iana.org/assignments/http-methods/http-methods.xhtml
    methods = [
        "ACL",
        "BASELINE-CONTROL",
        "BIND",
        "CHECKIN",
        "CHECKOUT",
        "CONNECT",
        "COPY",
        "DELETE",
        "GET",
        "HEAD",
        "LABEL",
        "LINK",
        "LOCK",
        "MERGE",
        "MKACTIVITY",
        "MKCALENDAR",
        "MKCOL",
        "MKREDIRECTREF",
        "MKWORKSPACE",
        "MOVE",
        "OPTIONS",
        "ORDERPATCH",
        "PATCH",
        "POST",
        "PRI",
        "PROPFIND",
        "PROPPATCH",
        "PUT",
        "REBIND",
        "REPORT",
        "SEARCH",
        "TRACE",
        "UNBIND",
        "UNCHECKOUT",
        "UNLINK",
        "UNLOCK",
        "UPDATE",
        "UPDATEREDIRECTREF",
        "VERSION-CONTROL",
        # Not RFC methods:
        "PURGE",
        # To check appropriate frang directive
        "UNKNOWN",
    ]

    def __init__(self, *args, **kwargs):
        self.method = None
        self.uri = None
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        requestline = stream.readline()
        if requestline[-1] != "\n":
            raise IncompleteMessage(f"Incomplete request line!. First line - '{requestline}'.")

        # Skip optional empty lines
        while re.match("^[\r]?$", requestline) and len(requestline) > 0:
            requestline = stream.readline()

        words = requestline.rstrip("\r\n").split()
        if len(words) == 3:
            self.method, self.uri, self.version = words
        elif len(words) == 2:
            self.method, self.uri = words
        else:
            raise ParseError("Invalid request line!")
        if not self.method in self.methods:
            raise ParseError("Invalid request method!")

    def get_firstline(self):
        return " ".join([self.method, self.uri, self.version])

    def parse_body(self, stream):
        """RFC 7230 3.3.3"""
        # 3.3.3 3
        if "Transfer-Encoding" in self.headers:
            self.read_encoded_body(stream, True)
            return
        # 3.3.3 5
        if "Content-Length" in self.headers:
            self.read_sized_body(stream)
            return
        # 3.3.3 6
        self.body = ""

    def __eq__(self, other: "Request"):
        msg = "Invalid request {0}.\nReceived: {1}.\nExpected: {2}."
        assert self.method == other.method, msg.format("method", self.method, other.method)
        assert self.version == other.version, msg.format("version", self.version, other.version)
        assert self.uri == other.uri, msg.format("uri", self.uri, other.uri)
        super().__eq__(other)
        return True

    def __ne__(self, other):
        return not Request.__eq__(self, other)

    def add_tempesta_headers(self, x_forwarded_for: str | None = None):
        self.headers.add("Via", f"1.1 tempesta_fw (Tempesta FW {tempesta.version()})")
        self.headers.delete_all("X-Forwarded-For")
        x_forwarded_for = x_forwarded_for if x_forwarded_for else tf_cfg.cfg.get("Client", "ip")
        self.headers.add("X-Forwarded-For", x_forwarded_for)

    @staticmethod
    def create(
        method: str,
        headers: list,
        authority: str = tf_cfg.cfg.get("Client", "hostname"),
        uri="/",
        version="HTTP/1.1",
        date=None,
        body="",
    ):
        first_line = " ".join([method, uri, version])
        headers = copy.deepcopy(headers)
        if authority:
            headers.insert(0, ("Host", authority))

        msg = HttpMessage.create(first_line, headers, date=date, body=body)
        return Request(msg)


class H2Request(Request):
    def __str__(self):
        return "".join([str(self.headers), "\r\n", self.body, str(self.trailer)])

    def build_message(self) -> list or tuple:
        msg = (self.headers.headers, self.body) if self.body else self.headers.headers
        self.msg = msg

    def parse_firstline(self, stream):
        pass

    def get_firstline(self):
        pass

    def parse_headers(self, stream):
        self.headers = HeaderCollection.from_stream(stream, is_h2=True)
        self.uri = self.headers.get(":path")
        self.method = self.headers.get(":method")

    @staticmethod
    def create(
        method: str or None,
        headers: List[Tuple[str, str]],
        authority: str = tf_cfg.cfg.get("Client", "hostname"),
        uri="/",
        version="HTTP/2",
        date: str = None,
        body="",
    ):
        headers = copy.deepcopy(headers)
        pseudo_headers = [
            (":method", method) if method else (),
            (":path", uri) if uri else (),
            (":scheme", "https"),
            (":authority", authority) if authority else (),
        ]
        if date:
            headers.append(("date", date))

        request = H2Request()
        request.method = method
        request.uri = uri
        request.version = version
        request.headers = HeaderCollection(
            **{header[0]: header[1] for header in pseudo_headers + headers}
        )
        request.body = body
        request.build_message()

        return request


class Response(HttpMessage):
    def __init__(self, *args, **kwargs):
        self.status = None  # Status-Code
        self.reason = None  # Reason-Phrase
        HttpMessage.__init__(self, *args, **kwargs)
        self._via_header = f"1.1 tempesta_fw (Tempesta FW {tempesta.version()})"
        self._server_header = f"Tempesta FW/{tempesta.version()}"

    def parse_firstline(self, stream):
        statusline = stream.readline()
        if statusline[-1] != "\n":
            raise IncompleteMessage("Incomplete Status line!")

        words = statusline.rstrip("\r\n").split()
        if len(words) >= 3:
            self.version, self.status = words[0:2]
            self.reason = " ".join(words[2:])
        elif len(words) == 2:
            self.version, self.status = words
        else:
            raise ParseError("Invalid Status line!")
        try:
            status = int(self.status)
            assert status > 100 and status < 600
        except:
            raise ParseError("Invalid Status code!")

    def parse_body(self, stream):
        """RFC 7230 3.3.3"""
        # 3.3.3 1
        if self.method == "HEAD":
            return
        code = int(self.status)
        if code >= 100 and code <= 199 or code == 204 or code == 304:
            return
        # 3.3.3 2
        if self.method == "CONNECT" and code >= 200 and code <= 299:
            error.bug("Not implemented!")
            return
        # 3.3.3 3
        if "Transfer-Encoding" in self.headers:
            self.read_encoded_body(stream, False)
            return
        # TODO: check 3.3.3 4
        # 3.3.3 5
        if "Content-Length" in self.headers:
            self.read_sized_body(stream)
            return
        # 3.3.3 7
        self.read_rest_body(stream)

    def get_firstline(self):
        status = int(self.status)
        reason = BaseHTTPRequestHandler.responses[status][0]
        return " ".join([self.version, self.status, reason])

    def __eq__(self, other: "Response"):
        msg = "Invalid response {0}.\nReceived: {1}.\nExpected: {2}."
        assert self.status == other.status, msg.format("status", self.status, other.status)
        assert self.version == other.version, msg.format("version", self.version, other.version)
        assert self.reason == other.reason, msg.format("reason", self.reason, other.reason)
        super().__eq__(other)
        return True

    def __ne__(self, other):
        return not Response.__eq__(self, other)

    def add_tempesta_headers(self):
        self.headers.delete_all("via")
        self.headers.add("via", self._via_header)
        self.headers.delete_all("server")
        self.headers.add("server", self._server_header)
        if self.headers.get("date", None) is None:
            self.headers.add("date", self.date_time_string())

    @staticmethod
    def create(
        status,
        headers,
        version="HTTP/1.1",
        date=False,
        srv_version=None,
        body=None,
        method="GET",
        tempesta_headers=False,
        expected=False,
    ):
        reason = BaseHTTPRequestHandler.responses
        first_line = " ".join([version, str(status), reason[int(status)][0]])
        msg = HttpMessage.create(first_line, headers, date=date, srv_version=srv_version, body=body)

        response = Response(msg, method=method)
        if expected:
            response.set_expected()
        if tempesta_headers:
            response.add_tempesta_headers()
        return response


class H2Response(Response):
    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        self.version = "HTTP/2"
        self._via_header = f"2.0 tempesta_fw (Tempesta FW {tempesta.version()})"
        self._server_header = f"Tempesta FW/{tempesta.version()}"

    def parse_firstline(self, stream):
        pass

    def get_firstline(self):
        return ""

    def parse_headers(self, stream):
        self.headers = HeaderCollection.from_stream(stream, is_h2=True)
        self.status = self.headers.get(":status")

    @staticmethod
    def convert_http1_to_http2(response: Response) -> "H2Response":
        new_response = H2Response()
        new_response.method = response.method
        new_response.status = response.status

        new_response.headers = copy.deepcopy(response.headers)
        new_response.headers.add(name=":status", value=new_response.status)
        new_response.add_tempesta_headers()

        new_response.trailer = copy.deepcopy(response.trailer)
        new_response.body = response.body
        return new_response

    @staticmethod
    def create(
        status: str,
        headers: list,
        date: str = None,
        body="",
        tempesta_headers=False,
        expected=False,
        **kwargs,
    ):
        headers = copy.deepcopy(headers)
        if date:
            headers.append(("date", date))

        response = H2Response(method="")
        response.status = status
        response.headers = HeaderCollection(
            **{header[0]: header[1] for header in [(":status", f"{status}")] + headers}
        )
        if expected:
            response.set_expected()
        if tempesta_headers:
            response.add_tempesta_headers()
        response.body = body
        response.build_message()

        return response


# -------------------------------------------------------------------------------
# HTTP Client/Server
# -------------------------------------------------------------------------------
MAX_MESSAGE_SIZE = 65536


class TlsClient(asyncore.dispatcher):
    """
    A thin shim between async IO and an application logic class to establish
    TLS connection on handle_connect() and restore all the handlers necessary
    for application logic, such that the whole deproxy logic must not be aware
    about TLS and only need to set ssl constructor argument to employ TLS.
    """

    def __init__(self, is_ssl=False, proto="http/1.1"):
        asyncore.dispatcher.__init__(self)
        self.ssl = is_ssl
        self.want_read = False
        self.want_write = True  # TLS ClientHello is the first one
        self.server_hostname = None
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if run_config.SAVE_SECRETS:
            self.context.keylog_filename = "secrets.txt"
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.proto = proto
        self.apply_proto_settings()

    def set_server_hostname(self, server_hostname):
        self.server_hostname = server_hostname

    def save_handlers(self):
        """
        We need to store the handlers defined at any descendant layer to
        restore them when TLS handshake is done and we can do application
        logic.
        """
        assert hasattr(self, "handle_read"), "TLS: save null handlers"
        assert not hasattr(self, "__handle_read"), "TLS: double handlers save"
        self.__handle_read = self.handle_read
        self.__handle_write = self.handle_write
        self.__readable = self.readable
        self.__writable = self.writable

    def restore_handlers(self):
        """
        Since TLS operates with its own records:
        -- if a read event happened it doesn't imply that we have enough data
           for a complete TLS record and can return something to the application
           layer;
        -- SSLSocket.recv() seems to return a single TLS record payload, so if
           we received 2 or more records at once, there is no sense to report
           the socket readable() after the first record read.
        Generally speaking, handle_read() just must be aware about non-blocking
        IO, which SSL actually is. However, we should first try to read from the
        socket before go to polling, i.e. the only requirement to handle_read()
        is to call recv() multiple time until it doesn't return empty string.
        """
        self.readable = self.__readable
        self.handle_read = self.__handle_read
        self.writable = self.__writable
        self.handle_write = self.__handle_write

    def handle_connect(self):
        if not self.ssl:
            return
        # The TCP connection has been established and now we can
        # run TLS handshake on the socket.
        # Use default/mainstream TLS version - we have dedicated tests for
        # unusual TLS versions.
        self.save_handlers()
        self.handle_read = self.handle_write = self.tls_handshake
        self.writable = self.tls_handshake_writable
        self.readable = self.tls_handshake_readable
        try:
            self.socket = self.context.wrap_socket(
                self.socket, do_handshake_on_connect=False, server_hostname=self.server_hostname
            )

        except IOError as tls_e:
            dbg(self, 2, "Cannot establish TLS connection")
            raise tls_e

    def tls_handshake_readable(self):
        return self.want_read

    def tls_handshake_writable(self):
        return self.want_write

    def tls_handshake(self):
        try:
            self.socket.do_handshake()
        except ssl.SSLError as tls_e:
            self.want_read = self.want_write = False
            if tls_e.args[0] == ssl.SSL_ERROR_WANT_READ:
                self.want_read = True
            elif tls_e.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                self.want_write = True
            else:
                dbg(self, 2, "TLS handshake error,", tls_e)
                raise
        else:
            dbg(self, 4, "Finished TLS handshake", prefix="\t")
            # Handshake is done, set processing callbacks
            self.restore_handlers()

    def apply_proto_settings(self):
        if self.proto == "h2":
            self.context.set_alpn_protocols(["h2"])
            # Disable old proto
            self.context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            # RFC 9113 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
            # compression.
            self.context.options |= ssl.OP_NO_COMPRESSION


class Client(TlsClient, stateful.Stateful):
    def __init__(
        self,
        addr=None,
        host="Tempesta",
        port=80,
        ssl=False,
        bind_addr=None,
        proto="http/1.1",
        socket_family="ipv4",
    ):
        TlsClient.__init__(self, ssl, proto)
        self.request = None
        self.request_buffer = ""
        self.response_buffer = ""
        self.tester = None
        self.conn_addr = addr or tf_cfg.cfg.get(host, "ip")
        self.port = port
        self.stop_procedures = [self.__stop_client]
        self.conn_is_closed = True
        self.conn_was_opened = False
        self.bind_addr = bind_addr or tf_cfg.cfg.get("Client", "ip")
        self.error_codes = []
        self.socket_family = socket_family

    def __stop_client(self):
        dbg(self, 4, "Stop", prefix="\t")
        self.close()

    def run_start(self):
        dbg(self, 3, "Start", prefix="\t", use_getsockname=False)
        dbg(
            self,
            4,
            "Connect to %s:%d" % (self.conn_addr, self.port),
            prefix="\t",
            use_getsockname=False,
        )

        self.create_socket(
            socket.AF_INET if self.socket_family == "ipv4" else socket.AF_INET6, socket.SOCK_STREAM
        )
        if self.bind_addr:
            self.bind((self.bind_addr, 0))
        self.connect((self.conn_addr, self.port))

    def clear(self):
        self.request_buffer = ""

    def set_request(self, message_chain):
        if message_chain:
            self.request = message_chain.request
            self.request_buffer = message_chain.request.msg if message_chain.request else ""

    def set_tester(self, tester):
        self.tester = tester

    def connection_is_closed(self):
        return self.conn_is_closed

    @property
    def conn_is_active(self):
        return self.conn_was_opened and not self.conn_is_closed

    @property
    def socket_family(self) -> str:
        return self.__socket_family

    @socket_family.setter
    def socket_family(self, socket_family: str) -> None:
        if socket_family in ("ipv4", "ipv6"):
            self.__socket_family = socket_family
        else:
            raise Exception("Unexpected socket family.")

    def handle_connect(self):
        TlsClient.handle_connect(self)
        self.conn_was_opened = True
        self.conn_is_closed = False

    def handle_close(self):
        self.close()
        self.conn_is_closed = True
        self.state = stateful.STATE_STOPPED

    def handle_read(self):
        while True:  # TLS aware - read as many records as we can
            try:
                buf = self.recv(MAX_MESSAGE_SIZE).decode()
            except IOError as err:
                if err.errno == errno.EWOULDBLOCK:
                    break
            if not buf:
                break
            self.response_buffer += buf
        if not self.response_buffer:
            return
        dbg(self, 4, "Receive response from Tempesta:", prefix="\t")
        tf_cfg.dbg(5, self.response_buffer)
        try:
            response = Response(self.response_buffer, method=self.request.method)
            self.response_buffer = self.response_buffer[len(response.msg) :]
        except IncompleteMessage:
            return
        except ParseError:
            dbg(self, 4, ("Can't parse message\n" "<<<<<\n%s>>>>>" % self.response_buffer))
            raise
        if len(self.response_buffer) > 0:
            # TODO: take care about pipelined case
            raise ParseError("Garbage after response end:\n```\n%s\n```\n" % self.response_buffer)
        if self.tester:
            self.tester.received_response(response)
        self.response_buffer = ""

    def writable(self):
        if not self.tester:
            return False
        return self.tester.is_srvs_ready() and (len(self.request_buffer) > 0)

    def handle_write(self):
        dbg(self, 4, "Send request to Tempesta:", prefix="\t")
        tf_cfg.dbg(5, self.request_buffer)
        sent = self.send(self.request_buffer.encode())
        self.request_buffer = self.request_buffer[sent:]

    def handle_error(self):
        type_error, v, _ = sys.exc_info()
        self.error_codes.append(type_error)
        dbg(self, 2, f"Receive error - {type_error} with message - {v}", prefix="\t")

        if type_error == ParseError:
            self.handle_close()
            raise v
        elif type_error in (
            ssl.SSLWantReadError,
            ssl.SSLWantWriteError,
            ConnectionRefusedError,
            AssertionError,
        ):
            # SSLWantReadError and SSLWantWriteError - Need to receive more data before decryption
            # can start.
            # ConnectionRefusedError and AssertionError - RST is legitimate case
            pass
        elif type_error == ssl.SSLEOFError:
            # This may happen if a TCP socket is closed without sending TLS close alert. See #1778
            self.handle_close()
        else:
            self.handle_close()
            error.bug("\tDeproxy: Client: %s" % v)


class ServerConnection(asyncore.dispatcher_with_send):
    def __init__(self, tester, server, sock=None, keep_alive=None):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.tester = tester
        self.server = server
        self.keep_alive = keep_alive
        self.responses_done = 0
        self.request_buffer = ""
        self.tester.register_srv_connection(self)
        dbg(self, 6, "New server connection", prefix="\t")

    def handle_read(self):
        self.request_buffer += self.recv(MAX_MESSAGE_SIZE).decode()
        try:
            request = Request(self.request_buffer)
        except IncompleteMessage:
            return
        except ParseError:
            dbg(
                self,
                4,
                ("Can't parse message\n" "<<<<<\n%s>>>>>" % self.request_buffer),
            )
        # Handler will be called even if buffer is empty.
        if not self.request_buffer:
            return
        dbg(self, 4, "Receive request from Tempesta.", prefix="\t")
        tf_cfg.dbg(5, self.request_buffer)
        if not self.tester:
            return
        response = self.tester.received_forwarded_request(request, self)
        self.request_buffer = ""
        if not response:
            return
        self.send_response(response)

    def send_pending_and_close(self):
        while len(self.out_buffer):
            self.initiate_send()
        self.handle_close()

    def send_response(self, response):
        if response.msg:
            dbg(self, 4, "Send response to Tempesta:", prefix="\t")
            tf_cfg.dbg(5, response.msg)
            self.send(response.msg.encode())
        else:
            dbg(self, 4, "Try send invalid response", prefix="\t")
        if self.keep_alive:
            self.responses_done += 1
            if self.responses_done == self.keep_alive:
                self.send_pending_and_close()

    def handle_error(self):
        _, v, _ = sys.exc_info()
        error.bug("\tDeproxy: SrvConnection: %s" % v)

    def handle_close(self):
        dbg(self, 6, "Close connection", prefix="\t")
        self.close()
        if self.tester:
            self.tester.remove_srv_connection(self)
        if self.server:
            try:
                self.server.connections.remove(self)
            except ValueError:
                pass


class Server(asyncore.dispatcher, stateful.Stateful):
    def __init__(self, port, host=None, conns_n=None, keep_alive=None):
        asyncore.dispatcher.__init__(self)
        self.tester = None
        self.port = port
        self.connections = []
        if conns_n is None:
            conns_n = tempesta.server_conns_default()
        self.conns_n = conns_n
        self.keep_alive = keep_alive
        self.ip = tf_cfg.cfg.get("Server", "ip")
        self.stop_procedures = [self.__stop_server]

    def run_start(self):
        dbg(self, 3, "Start on %s:%d" % (self.ip, self.port), prefix="\t")
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.ip, self.port))
        self.listen(socket.SOMAXCONN)

    def __stop_server(self):
        dbg(self, 3, "Stop", prefix="\t")
        self.close()
        connections = [conn for conn in self.connections]
        for conn in connections:
            conn.handle_close()
        if self.tester:
            self.tester.servers.remove(self)

    def set_tester(self, tester):
        self.tester = tester

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            handler = ServerConnection(
                self.tester, server=self, sock=sock, keep_alive=self.keep_alive
            )
            self.connections.append(handler)
            # ATTENTION
            # Due to the polling cycle, creating new connection can be
            # performed before removing old connection.
            # So we can have case with >expected amount of connections
            # It's not a error case, it's a problem of polling

    def handle_read_event(self):
        asyncore.dispatcher.handle_read_event(self)

    def active_conns_n(self):
        return len(self.connections)

    def handle_error(self):
        _, v, _ = sys.exc_info()
        if type(v) == AssertionError:
            raise v
        else:
            raise Exception("\tDeproxy: Server %s:%d: %s" % (self.ip, self.port, str(v)))

    def handle_close(self):
        self.close()
        self.state = stateful.STATE_STOPPED


# -------------------------------------------------------------------------------
# Message Chain
# -------------------------------------------------------------------------------
TEST_CHAIN_TIMEOUT = 5


class MessageChain(object):
    def __init__(self, request, expected_response, forwarded_request=None, server_response=None):
        # Request to be sent from Client.
        self.request = request
        # Response received on the client.
        self.response = expected_response
        # Expected request forwarded by Tempesta to the server.
        self.fwd_request = forwarded_request
        # Server response in reply to the forwarded request.
        self.server_response = server_response

    @staticmethod
    def empty():
        return MessageChain(None, None)


class Deproxy(stateful.Stateful):
    def __init__(self, client, servers, register=True, message_chains=None):
        self.message_chains = message_chains
        self.client = client
        self.servers = servers
        # Current chain of expected messages.
        self.current_chain = None
        # Current chain of received messages.
        self.received_chain = None
        # Default per-message-chain loop timeout.
        self.timeout = TEST_CHAIN_TIMEOUT
        # Registered connections.
        self.srv_connections = []
        if register:
            self.register_tester()
        self.stop_procedures = [self.__stop_deproxy]

    def __stop_deproxy(self):
        tf_cfg.dbg(3, "\tStopping deproxy tester")

    def run_start(self):
        tf_cfg.dbg(3, "\tStarting deproxy tester")

    def register_tester(self):
        self.client.set_tester(self)
        for server in self.servers:
            server.set_tester(self)

    def loop(self, timeout=None):
        """Poll for socket events no more than `self.timeout` or `timeout` seconds."""
        if timeout is not None:
            timeout = min(timeout, self.timeout)
        else:
            timeout = self.timeout

        try:
            eta = time.time() + timeout
            s_map = asyncore.socket_map

            if hasattr(select, "poll"):
                poll_fun = asyncore.poll2
            else:
                poll_fun = asyncore.poll

            while (eta > time.time()) and s_map:
                poll_fun(eta - time.time(), s_map)
        except asyncore.ExitNow:
            pass

    def run(self):
        if self.message_chains is None:
            return
        for self.current_chain in self.message_chains:
            self.received_chain = MessageChain.empty()
            self.client.clear()
            self.client.set_request(self.current_chain)
            self.loop()
            self.check_expectations()

    def check_expectations(self):
        for message in ["response", "fwd_request"]:
            expected = getattr(self.current_chain, message)
            received = getattr(self.received_chain, message)
            if expected:
                expected.set_expected(expected_time_delta=self.timeout)
            assert expected == received, (
                "Received message (%s) does not suit expected one!\n\n"
                "\tReceieved:\n<<<<<|\n%s|>>>>>\n"
                "\tExpected:\n<<<<<|\n%s|>>>>>\n"
                % (message, received.msg if received else "", expected.msg if expected else "")
            )

    def received_response(self, response):
        """Client received response for its request."""
        self.received_chain.response = response
        raise asyncore.ExitNow

    def received_forwarded_request(self, request, connection=None):
        self.received_chain.fwd_request = request
        return self.current_chain.server_response

    def register_srv_connection(self, connection):
        assert (
            connection.server in self.servers
        ), "Register connection, which comes from not registered server!"
        self.srv_connections.append(connection)

    def remove_srv_connection(self, connection):
        # Normally we have the connection in the list, but do not crash test
        # framework if that is not true.
        try:
            self.srv_connections.remove(connection)
        except ValueError:
            pass

    def is_srvs_ready(self):
        expected_conns_n = sum([s.conns_n for s in self.servers])
        assert (
            len(self.srv_connections) <= expected_conns_n
        ), "Registered more connections that must be!."
        return expected_conns_n == len(self.srv_connections)


def finish_all_deproxy():
    asyncore.close_all()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
