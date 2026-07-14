"""Wrapper for the RUDY (R-U-Dead-Yet?) slow HTTP attack tool.

RUDY opens concurrent POST (or other method) connections and sends the request
body one byte at a time with a long interval between bytes. It is used to
exercise Tempesta FW protection against slow HTTP / low-and-slow DoS attacks
(for example ``client_body_timeout`` and connection limits).

Supports HTTP/1.1 (chunked), HTTP/2 over TLS, and h2c via ``--protocol``.

Fork with HTTP/2 support:
https://github.com/symstu-tempesta/rudy/tree/symstu/added-http2-support
"""

from typing import List, Optional, Union

from framework.services import base_client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

# Protocols accepted by the rudy binary (--protocol).
RUDY_PROTOCOLS = ("http1", "http2", "h2c")


class Rudy(base_client.BaseClient):
    """Manage the ``rudy`` binary: start, stop, and collect basic stats.

    Client definition fields (``tester.TempestaTest.clients`` entry)::

        {
            "id": "rudy",
            "type": "rudy",
            "addr": "${tempesta_ip}:80",
            "uri": "/",
            "ssl": False,
            "protocol": "http1",  # http1 | http2 | h2c
            "insecure": False,    # -k skip TLS verify (http2 lab / self-signed)
            "concurrents": 50,
            "interval": "5s",
            "payload_size": "100KB",
            "method": "POST",
            "headers": ["Host: example.com", "Content-Type: text/plain"],
            "duration": 30,  # optional process timeout override (seconds)
        }
    """

    def __init__(
        self,
        id_: str,
        concurrents: Optional[int] = None,
        interval: str = "10s",
        payload_size: str = "1MB",
        method: str = "POST",
        headers: Optional[List[str]] = None,
        protocol: str = "http1",
        insecure: bool = False,
        duration: Optional[int] = None,
        **kwargs,
    ):
        base_client.BaseClient.__init__(self, id_, "rudy", **kwargs)
        # Default concurrent workers to framework concurrent_connections.
        self.concurrents = concurrents if concurrents is not None else self.connections
        self.interval = interval
        self.payload_size = payload_size
        self.method = method
        self.headers = list(headers) if headers else []
        if protocol not in RUDY_PROTOCOLS:
            raise ValueError(
                f"Unsupported rudy protocol {protocol!r}; want one of {RUDY_PROTOCOLS}"
            )
        self.protocol = protocol
        self.insecure = insecure
        if duration is not None:
            self.duration = duration

    def form_command(self):
        """Build ``rudy run ...`` command line for the remote client node."""
        opts = [
            "run",
            f"-u '{self.uri}'",
            f"-c {self.concurrents}",
            f"-i {self.interval}",
            f"-p {self.payload_size}",
            f"-m {self.method}",
            f"--protocol {self.protocol}",
        ]
        if self.insecure:
            opts.append("-k")
        for header in self.headers:
            # Quote so values with spaces (e.g. Host headers) survive the shell.
            opts.append(f"--header '{header}'")
        cmd = " ".join([self.bin] + opts + self.options)
        return cmd

    def parse_out(self, stdout: Union[str, bytes, None], stderr: Union[str, bytes, None]):
        """Parse rudy logs into ``requests`` / ``errors`` counters."""
        parts = []
        for stream in (stdout, stderr):
            if stream is None:
                continue
            if isinstance(stream, bytes):
                parts.append(stream.decode(errors="replace"))
            else:
                parts.append(stream)
        out = "".join(parts)

        # Successful full body send (rare under frang timeout).
        self.requests = out.count("Request successfully sent")
        # Failures when the peer closes / times out the slow connection.
        self.errors = out.count("an error occurred")
        # Bytes that were actually pushed before close (best-effort progress).
        self.statuses["bytes_sent"] = out.count("Sent 1 byte")
        return True
