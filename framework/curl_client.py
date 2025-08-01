"""cURL utility wrapper."""

import email
import io
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Any, Dict, List, Optional

from helpers import error, tf_cfg
from helpers.tf_cfg import test_logger

from . import client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


# Expected `curl --version`.
# This value could be overriden by the 'Client.curl_version' config variable.
# When updating, version in `setup.sh` should also be updated.
CURL_BINARY_VERSION = "7.85.0"


@dataclass
class CurlResponse:
    """Parsed cURL response.

    Args:
      headers_dump (bytes): status line + headers
      stdout_raw (bytes): stdout bytes
      stderr_raw (bytes): stderr bytes
      status (int): parsed HTTP status code
      proto (str): parsed HTTP potocol version, "1.1" or "2"
      headers (dict): parsed headers with lowercase names
    """

    headers_dump: bytes = field(repr=False)
    stdout_raw: bytes = field(repr=False)
    stderr_raw: bytes = field(repr=False)
    status: int = None
    proto: str = None
    headers: Dict[str, str] = None

    @property
    def stdout(self) -> str:
        """Decoded stdout."""
        return self.stdout_raw.decode()

    @property
    def stderr(self) -> str:
        """Decoded stderr."""
        return self.stderr_raw.decode()

    @property
    def multi_headers(self) -> Dict[str, List[str]]:
        """Parsed headers with lowercase names and list of values, like:
        {'set-cookie': ['name1=xxx', 'name2=yyy'], 'content-length': ['4']}
        """
        return dict(self._multi_headers)

    def __post_init__(self):
        try:
            response_line, headers = self.headers_dump.decode().split("\r\n", 1)
        except ValueError:
            test_logger.error(f"Unexpected headers dump: {self.headers_dump}", exc_info=True)
        else:
            message = email.message_from_file(io.StringIO(headers))
            match = re.match(r"HTTP/([.012]+) (\d+)", response_line)
            self.proto = match.group(1)
            self.status = int(match.group(2))

            self._multi_headers = defaultdict(list)
            for k, v in ((k.lower(), v) for k, v in message.items()):
                self._multi_headers[k].append(v)
            self.headers = {k: v[-1] for k, v in self.multi_headers.items()}


@dataclass
class CurlArguments:
    """Interface class for cURL client.
    Contains all accepted arguments (fields) supported by `CurlClient`.
    """

    id: str
    addr: str
    uri: str = "/"
    cmd_args: str = ""
    data: str = ""
    headers: dict = field(default_factory=dict)
    dump_headers: int = True
    disable_output: bool = False
    save_cookies: bool = False
    load_cookies: bool = False
    ssl: bool = False
    http2: bool = False
    curl_iface: str = None
    insecure: bool = True
    parallel: int = None
    method: str = ""

    @classmethod
    def get_arg_names(cls) -> List[str]:
        """Returns list of `CurlClient` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class CurlClient(CurlArguments, client.Client):
    """
    Wrapper to manage cURL.
    See `selftests/test_curl_client.py` and #332 PR for usage examples.

    Args:
      addr (str): Host (IP address) to connect to
      uri (str): URI to access
      cmd_args (str): additional curl options
      data (str): data to POST
      headers (dict[str, str]): headers to include in the request
      dump_headers (bool): dump headers to the workdir, and enable response parsing
                           Enabled by default. In combination with parallel
                           can provide inaccurate results #488.
      disable_output (bool): do not output results but only errors
      save_cookies (bool): Save cookies to the workdir.
                           Be aware: cookies are shared among all clients.
      load_cookies (bool): load and send cookies from the workdir
      ssl (bool): use SSL/TLS for the connection
      http2 (bool): use HTTP version 2
      curl_iface (str): Interface name, IP address or host name using for performing request.
                        Don't mess with "interface" argument, used by framework
                        for creating alias interfaces.
      insecure (bool): Ignore SSL certificate errors. Enabled by default.
      parallel (int): Enable parallel mode, with maximum <int> simultaneous transfers.
                      In combination with dump_headers can provide inaccurate results #488.
      method (str): Specify HTTP method for request.
    """

    def __init__(self, **kwargs):
        # Initialize the `CurlArguments` interface first
        super().__init__(**kwargs)
        # Initialize the base `Client`
        client.Client.__init__(
            self,
            id_=self.id,
            binary="curl",
            server_addr=self.addr,
            uri=self.uri,
            ssl=self.ssl or self.http2,
        )
        self.options = [self.cmd_args] if self.cmd_args else []
        self._output_delimeter = "-===curl-transfer===-"

    @property
    def requests(self) -> int:
        """Number of perfomed requests."""
        return max(len(self._stats), len(self._responses))

    @requests.setter
    def requests(self, value):
        # ignore attribute initialization by `Client`
        pass

    @property
    def responses(self) -> List[CurlResponse]:
        """List of all received responses.
        Can provide inaccurate results in some cases, (see dump_headers comment).
        If dump_headers disabled, will be empty.
        """
        return list(self._responses)

    @property
    def last_response(self) -> Optional[CurlResponse]:
        """Last parsed response if any.
        Can provide inaccurate results in some cases, (see dump_headers comment).
        If dump_headers disabled, will be empty.
        """
        return (self.responses or [None])[-1]

    @property
    def statuses(self) -> Dict[int, int]:
        """Received statuses counters from headers, like:
        {200: 1, 400: 2}
        Can provide inaccurate results in some cases, (see dump_headers comment).
        If dump_headers disabled, will be empty.
        """
        return dict(self._statuses)

    @statuses.setter
    def statuses(self, value):
        self._statuses = defaultdict(lambda: 0, value)

    def statuses_from_stats(self) -> Dict[int, int]:
        """Received statuses counters from curl output, like:
        {200: 1, 400: 2}
        statuses property can provide inaccurate results in some cases,
        (see dump_headers comment) - the function will be useful so.
        """
        r = defaultdict(lambda: 0)
        for s in self.stats:
            r[int(s["response_code"])] += 1
        return dict(r)

    @property
    def last_stats(self) -> Dict[str, Any]:
        """Information about last completed transfer.
        See https://curl.se/docs/manpage.html#-w
        for the list of available variables.
        If disable_output enabled, will be empty.
        """
        return (self._stats or [None])[-1]

    @property
    def stats(self) -> List[Dict[str, Any]]:
        """List of stats of all transfers.
        See https://curl.se/docs/manpage.html#-w
        for the list of available variables.
        If disable_output enabled, will be empty.
        """
        return list(self._stats)

    @property
    def reset_conn_n(self) -> int:
        """
        Amount of connections reseted by server (by RST).
        """
        return sum(
            "Connection reset by peer" in (s["errormsg"] or "") and s["response_code"] == 0
            for s in self.stats
        )

    @property
    def binary_version(self) -> Optional[str]:
        """curl binary version, parsed from the latest transfer."""
        if self.last_stats:
            return self._parse_binary_version(self.last_stats["curl_version"])

    @property
    def cookie_jar_path(self):
        """Path to save/load cookies."""
        return Path(self.workdir) / "curl-default.jar"

    @property
    def output_path(self):
        """Path to write stdout (response)."""
        # id(self) for the case of several client instances
        return Path(self.workdir) / f"curl-output-{id(self)}"

    @property
    def headers_dump_path(self):
        """Path do dump received headers."""
        # id(self) for the case of several client instances
        return Path(self.workdir) / f"curl-{id(self)}.hdr"

    @property
    def cookie_string(self) -> str:
        """Saved cookies name-value pairs: 'name1=value; name2=value'."""
        jar = MozillaCookieJar()
        jar.load(self.cookie_jar_path, ignore_discard=True, ignore_expires=True)
        return "; ".join([f"{cookie.name}={cookie.value}" for cookie in jar])

    def clear_cookies(self):
        """Delete cookies from previous runs."""
        self.cookie_jar_path.unlink(missing_ok=True)

    def clear_stats(self):
        super().clear_stats()
        self._responses = []
        self._stats = []

    def form_command(self):
        options = ["--no-progress-meter", "--create-dirs"]

        if self.dump_headers:
            options.append(f"--dump-header '{self.headers_dump_path}'")

        if self.disable_output:
            options.append("--silent --show-error --output /dev/null")
        else:
            options.append(f"--write-out '%{{json}}{self._output_delimeter}'")
            options.append(f"--output '{self.output_path}'")

        if self.save_cookies:
            options.append(f"--cookie-jar '{self.cookie_jar_path}'")
        if self.load_cookies:
            options.append(f"--cookie '{self.cookie_jar_path}'")

        for header, value in (self.headers or {}).items():
            options.append(f"--header '{header}: {value}'")

        if self.data:
            options.append(f"--data '{self.data}'")

        if self.http2:
            options.append("--http2-prior-knowledge")
        else:
            options.append("--http1.1")

        if self.curl_iface:
            options.append(f"--interface {self.curl_iface}")

        if self.ssl and self.insecure:
            options.append("--insecure")

        if self.parallel:
            options.append("--parallel")
            options.append("--parallel-immediate")
            options.append(f"--parallel-max {self.parallel}")

        if self.method:
            options.append(f"--request {self.method}")

        cmd = " ".join([self.bin] + options + self.options + [f"'{self.uri}'"])
        self._logger.info(f"Curl command formatted: {cmd}")
        return cmd

    def parse_out(self, stdout, stderr):
        if self.dump_headers:
            for dump in filter(None, self._read_headers_dump().split(b"\r\n\r\n")):
                try:
                    stdout_raw = self._read_output() if not self.disable_output else b""
                except FileNotFoundError:
                    stdout_raw = b""
                    self._logger.critical(
                        f"The {self.output_path} file was not created for 'dump_headers'",
                        exc_info=True,
                    )
                response = CurlResponse(headers_dump=dump, stdout_raw=stdout_raw, stderr_raw=stderr)
                expected_proto = ("2",) if self.http2 else ("1.0", "1.1")
                if response.proto and response.proto not in expected_proto:
                    raise Exception(f"Unexpected HTTP version response: {response.proto}")
                self._responses.append(response)
                self._statuses[response.status] += 1
        if not self.disable_output and stdout:
            try:
                self._stats = self._parse_stats(stdout)
                if not self.dump_headers:
                    for response in self._stats:
                        expected_proto = ("2") if self.http2 else ("1.0", "1.1")
                        if (
                            response["http_version"]
                            and response["http_version"] not in expected_proto
                        ):
                            raise Exception(f"Unexpected HTTP version response: {response.proto}")
                        self._statuses[response["response_code"]] += 1
            except json.JSONDecodeError:
                self._logger.error("Error: can't decode cURL JSON stats.")
            else:
                if self.last_stats or (
                    stderr and b"unknown --write-out variable: 'json'" in stderr
                ):
                    self._check_binary_version()
        return True

    def _parse_stats(self, stdout: bytes):
        return [
            json.loads(stats) for stats in stdout.decode().split(self._output_delimeter) if stats
        ]

    def _read_headers_dump(self) -> bytes:
        with self.headers_dump_path.open("rb") as f:
            return f.read()

    def _read_output(self):
        with self.output_path.open("rb") as f:
            return f.read()

    def _check_binary_version(self):
        # Check for badly outdated or too new version, than could not be parsed
        error.assertTrue(
            self.binary_version,
            f"Can't detect `curl` version. `curl --version` should be {CURL_BINARY_VERSION}",
        )
        error.assertTrue(
            self.binary_version == CURL_BINARY_VERSION,
            (
                f"Expected curl binary version: {CURL_BINARY_VERSION}\n"
                f"Detected curl binary version: {self.binary_version}\n"
                f"Set 'Client.curl_version' config variable to override expected value."
            ),
        )

    def _parse_binary_version(self, version: str) -> str:
        # Version string examples:
        # "libcurl/7.85.0 OpenSSL/3.0.2 zlib/1.2.11 nghttp2/1.43.0"
        # "libcurl/7.85.0-DEV OpenSSL/1.1.1f zlib/1.2.11"
        return version.split()[0].split("/")[1].split("-")[0]
