"""Wrapper for the RUDY (R-U-Dead-Yet?) slow HTTP attack tool.

RUDY opens concurrent POST (or other method) connections and sends the request
body one byte at a time with a long interval between bytes. It is used to
exercise Tempesta FW protection against slow HTTP / low-and-slow DoS attacks
(for example ``client_body_timeout`` and connection limits).

Upstream project: https://github.com/darkweak/rudy
"""

from typing import List, Optional, Union

from framework.services import base_client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Rudy(base_client.BaseClient):
    """Manage the ``rudy`` binary: start, stop, and collect basic stats.

    Client definition fields (``tester.TempestaTest.clients`` entry)::

        {
            "id": "rudy",
            "type": "rudy",
            "addr": "${tempesta_ip}:80",
            "uri": "/",
            "ssl": False,
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
        ]
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
