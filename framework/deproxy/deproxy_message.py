"""
Our Request/Response implementation differs from http.lib. We use these classes
like a wrapper for http message and in some cases we can manually instantiate
objects of these classes to construct message.
"""

import abc
import calendar  # for calendar.timegm()
import copy
import re
import time
from http.server import BaseHTTPRequestHandler
from io import StringIO
from typing import List, Tuple

from framework.helpers import error, tf_cfg
from framework.services import tempesta

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

# -------------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------------


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
    def __is_header_expect(header: str) -> bool:
        return header.lower() == "expect"

    def __check_other_headers(self, h_expected: dict, h_received: dict) -> None:
        headers = h_expected if len(h_expected) > len(h_received) else h_received
        for header_name in headers.keys():
            if self.__is_header_expect(header_name):
                continue

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

    @property
    def msg(self) -> str:
        return self.__str__()

    def parse_text(self, message_text, body_parsing=True):
        self.body_parsing = body_parsing
        stream = StringIO(message_text)
        self.__parse(stream)
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
        If trailer is not present don't pass the last CRLF to parse_trailer.
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

    def convert_chunked_body(self, http2, method_is_head):
        chunked_lines = self.body.split("\r\n")
        self.body = "".join(chunked_lines[1::2])
        # Tempesta FW encode body in single chunk
        # For example 3 abc 2 be 0 will be converted to 5 abcbe 0
        if not http2 and not method_is_head:
            if self.body != "":
                result = f"{hex(len(self.body))[2:]}\r\n"
                result += f"{self.body}\r\n"
            else:
                result = ""
            self.body = result + "0\r\n"

    def read_sized_body(self, stream):
        """RFC 7230. 3.3.3 #5"""
        size = int(self.headers["Content-Length"])

        self.body = stream.read(size)
        if len(self.body) > size:
            raise ParseError(("Wrong body size: expect %d but got %d!" % (size, len(self.body))))
        elif len(self.body) < size and self.headers.get("expect") == "100-continue":
            return
        elif len(self.body) < size:
            raise IncompleteMessage()

    def parse_trailer(self, stream):
        self.trailer = HeaderCollection.from_stream(stream, no_crlf=True)

    @abc.abstractmethod
    def __eq__(self, other: "HttpMessage"):
        assert (
            self.body == other.body
        ), f"Invalid http body. \nReceived:\n{self.body.encode()}\nExpected:\n{other.body.encode()}"
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
        "POT",
        "GFT",
        "PUTA",
        "GETA",
        "OPTIONA",
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

    @property
    def msg(self) -> list | tuple:
        return (self.headers.headers, self.body) if self.body else self.headers.headers

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
        request.headers = HeaderCollection()
        for header in pseudo_headers + headers:
            request.headers.add(name=header[0], value=header[1])
        request.body = body

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
            assert status > 99 and status < 600
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
        self.trailer.delete_all("server")
        self.trailer.delete_all("via")
        if self.headers.get("date", None) is None:
            self.headers.add("date", self.date_time_string())

    @staticmethod
    def create_simple_response(
        status,
        headers,
        version="HTTP/1.1",
        date=False,
        srv_version=None,
        body=None,
    ):
        reason = BaseHTTPRequestHandler.responses
        first_line = " ".join([version, str(status), reason[int(status)][0]])
        return HttpMessage.create(
            first_line, headers, date=date, srv_version=srv_version, body=body
        )

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
        msg = Response.create_simple_response(status, headers, version, date, srv_version, body)

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

        return response


MAX_MESSAGE_SIZE = 65536
