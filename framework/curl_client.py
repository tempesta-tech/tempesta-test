import email
import io
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from helpers import tf_cfg
from . import client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class CurlResponse:
    """Parsed cURL response."""

    headers_dump: bytes  # status line + headers
    stdout_raw: bytes  # stdout bytes
    stderr_raw: bytes  # stderr bytes
    status: int = None  # parsed HTTP status code
    proto: str = None  # parsed HTTP potocol version
    headers: dict = None  # parsed headers with lowercase names

    @property
    def stdout(self) -> str:
        """Decoded stdout."""
        return self.stdout_raw.decode()

    @property
    def stderr(self) -> str:
        """Decoded stderr."""
        return self.stderr_raw.decode()

    @property
    def multi_headers(self):
        """Parsed headers with lowercase names and list of values."""
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
    """cURL client accepted arguments (fields)."""

    server_addr: str
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


class CurlClient(CurlArguments, client.Client):
    """Wrapper to manage cURL."""

    def __init__(self, **kwargs):
        super().__init__(
            **{k: v for k, v in kwargs.items() if k in CurlArguments.__match_args__}
        )
        client.Client.__init__(
            self,
            binary="curl",
            server_addr=kwargs["server_addr"],
            uri=self.uri,
            ssl=self.ssl or self.http2,
        )
        self.options = [self.cmd_args] if self.cmd_args else []
        self.responses = []
        self.statuses = defaultdict(lambda: 0)

    @property
    def cookie_jar_path(self):
        return Path(self.workdir) / "curl-default.jar"

    @property
    def output_path(self):
        return Path(self.workdir) / "curl-output"

    @property
    def headers_dump_path(self):
        return Path(self.workdir) / "curl-default.hdr"

    @property
    def last_response(self) -> CurlResponse:
        return (self.responses or [None])[-1]

    def clear_cookies(self):
        """Remove the cookies jar of previous runs."""
        self.cookie_jar_path.unlink(missing_ok=True)

    def form_command(self):
        options = ["--no-progress-meter", '--write-out "%{json}"']

        if self.dump_headers:
            options.append(f"--dump-header '{self.headers_dump_path}'")

        if self.disable_output:
            options.append(f"--silent --show-error --output /dev/null")
        else:
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
                self.responses.append(response)
                self.statuses[response.status] += 1
        return True

    def _read_headers_dump(self) -> bytes:
        with self.headers_dump_path.open("rb") as f:
            return f.read()

    def _read_output(self):
        with self.output_path.open("rb") as f:
            return f.read()
