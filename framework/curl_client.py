"""cURL utility wrapper."""
import email
import io
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from helpers import tf_cfg
from . import client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


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
            tf_cfg.dbg(1, f"Unexpected headers dump: {self.headers_dump}")
        else:
            message = email.message_from_file(io.StringIO(headers))
            match = re.match(r"HTTP/([.12]+) (\d+)", response_line)
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

    addr: str
    uri: str = "/"
    cmd_args: str = ""
    data: str = ""
    headers: dict = None
    dump_headers: int = True
    disable_output: bool = False
    save_cookies: bool = False
    load_cookies: bool = False
    ssl: bool = False
    http2: bool = False
    insecure: bool = True

    @classmethod
    def get_kwargs(cls) -> list[str]:
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
      dump_headers (bool): dump headers to the workdir, and enable response parsing.
                           Enabled by default.
      disable_output (bool): do not output results but only errors
      save_cookies (bool): save cookies to the workdir
      load_cookies (bool): load and send cookies from the workdir
      ssl (bool): use SSL/TLS for the connection
      http2 (bool): use HTTP version 2
      insecure (bool): Ignore SSL certificate errors. Enabled by default.
    """

    def __init__(self, **kwargs):
        # Initialize the `CurlArguments` interface first
        super().__init__(**kwargs)
        # Initialize the base `Client`
        client.Client.__init__(
            self,
            binary="curl",
            server_addr=self.addr,
            uri=self.uri,
            ssl=self.ssl or self.http2,
        )
        self.options = [self.cmd_args] if self.cmd_args else []
        self._responses = []
        self._statuses = defaultdict(lambda: 0)

    @property
    def responses(self) -> List[CurlResponse]:
        """List of all received responses."""
        return list(self._responses)

    @property
    def last_response(self) -> Optional[CurlResponse]:
        """Last parsed response if any."""
        return (self.responses or [None])[-1]

    @property
    def statuses(self) -> Dict[int, int]:
        """Received statuses counters, like:
        {200: 1, 400: 2}
        """
        return dict(self._statuses)

    @statuses.setter
    def statuses(self, value):
        # ignore attribute initialization by `Client`
        pass

    @property
    def cookie_jar_path(self):
        """Path to save/load cookies."""
        return Path(self.workdir) / "curl-default.jar"

    @property
    def output_path(self):
        """Path to write stdout (response)."""
        return Path(self.workdir) / "curl-output"

    @property
    def headers_dump_path(self):
        """Path do dump received headers."""
        return Path(self.workdir) / "curl-default.hdr"

    def clear_cookies(self):
        """Delete cookies from previous runs."""
        self.cookie_jar_path.unlink(missing_ok=True)

    def form_command(self):
        options = ["--no-progress-meter", "--create-dirs"]

        if self.dump_headers:
            options.append(f"--dump-header '{self.headers_dump_path}'")

        if self.disable_output:
            options.append("--silent --show-error --output /dev/null")
        else:
            options.append("--write-out '%{json}'")
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

        if self.ssl and self.insecure:
            options.append("--insecure")

        cmd = " ".join([self.bin] + options + self.options + [f"'{self.uri}'"])
        tf_cfg.dbg(3, f"Curl command formatted: {cmd}")
        return cmd

    def parse_out(self, stdout, stderr):
        self.requests += 1
        if self.dump_headers:
            for dump in filter(None, self._read_headers_dump().split(b"\r\n\r\n")):

                response = CurlResponse(
                    headers_dump=dump,
                    stdout_raw=self._read_output(),
                    stderr_raw=stderr,
                )
                if response.proto and response.proto != ("2" if self.http2 else "1.1"):
                    raise Exception(
                        f"Unexpected HTTP version response: {response.proto}"
                    )
                self._responses.append(response)
                self._statuses[response.status] += 1
        return True

    def _read_headers_dump(self) -> bytes:
        with self.headers_dump_path.open("rb") as f:
            return f.read()

    def _read_output(self):
        with self.output_path.open("rb") as f:
            return f.read()
