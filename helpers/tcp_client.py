import abc
import contextlib
import subprocess
from typing import Optional, Type

from scapy.all import L3RawSocket, conf, sr, sr1
from scapy.layers.inet import IP, TCP

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ScapyFix:
    @classmethod
    @abc.abstractmethod
    def apply(cls):
        """
        Do some changes to fix something
        """

    @classmethod
    @abc.abstractmethod
    def rollback(cls):
        """
        Rollback made changes in apply method
        """


class ScapyLocalhostRequestFix(ScapyFix):
    """
    This fix allows to send requests to localhost using lo interface

    https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-or-1-scapy-does-not-work-with-127-0-0-1-or-1-on-the-loopback-interface
    """

    @classmethod
    def apply(cls) -> None:
        conf.L3socket = L3RawSocket

    @classmethod
    def rollback(cls) -> None:
        conf.L3socket = None


class ScapyTCPHandshakeResetFix(ScapyFix):
    """
    This fix creates rules in iptables to ignore kernel RESET answer
    because of scapy uses user space to send packages.

    https://scapy.readthedocs.io/en/latest/troubleshooting.html#my-tcp-connections-are-reset-by-scapy-or-by-my-kernel
    """

    @classmethod
    def apply(cls) -> None:
        cmd = [
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            "55555",
            "-j",
            "DROP",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.stderr == ""

    @classmethod
    def rollback(cls) -> None:
        cmd = [
            "iptables",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            "55555",
            "-j",
            "DROP",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.stderr == ""


class SimpleTCPClient:
    def __init__(
        self,
        destination_host: str,
        destination_port: int,
        source_host: str = "127.0.0.1",
        source_port: int = 55555,
        timeout: int = 5,
    ):
        self.source_host = source_host
        self.source_port = source_port
        self.destination_host = destination_host
        self.destination_port = destination_port
        self.timeout = timeout

        self.last_response: Optional[IP] = None
        self.last_request: Optional[IP] = None

        self.fixes = []

    def fixes_install(self, *args: Type[ScapyFix]) -> None:
        """
        Apply some fixes for scapy
        """
        self.fixes = args
        list(map(lambda item: item.apply(), self.fixes))

    def fixes_rollback(self) -> None:
        """
        Rollback all installed fixes
        """
        list(map(lambda item: item.rollback(), self.fixes))

    @contextlib.contextmanager
    def fixes_context(self, *args: Type[ScapyFix]):
        """
        Apply scapy fixes and auto rollback
        """
        self.fixes_install(*args)
        yield
        self.fixes_rollback()

    @staticmethod
    def __build_packet(
        flags: str,
        src_host: str,
        src_port: int,
        dst_host: str,
        dst_port: int,
        seq: int = 0,
        ack: int = 0,
        data: bytes = None,
    ) -> IP:
        """
        TCP request builder
        """
        req = IP(src=src_host, dst=dst_host) / TCP(
            seq=seq,
            ack=ack,
            sport=src_port,
            dport=dst_port,
            window=65495,
            flags=flags,
        )

        if data:
            req = req / data

        return req

    def request(
        self, flags: str, data: bytes = None, seq: int = 0, ack: int = None, timeout: int = 1
    ) -> tuple[IP, IP]:
        """
        Made a request and return first server answer
        limited by timeout
        """
        self.last_request = self.__build_packet(
            flags=flags,
            src_host=self.source_host,
            src_port=self.source_port,
            dst_host=self.destination_host,
            dst_port=self.destination_port,
            seq=seq,
            ack=ack,
            data=data,
        )
        self.last_response = sr1(self.last_request, timeout=self.timeout or timeout)

        return self.last_request, self.last_response

    def request_last_answer(
        self, flags: str, data: bytes = None, seq: int = 0, ack: int = None, timeout: int = 1
    ) -> tuple[IP, IP]:
        """
        Make a request, collect all server answers
        limited by period and return last one.

        Warning: it could skip some ACK but for
        simplicity it's ignoring
        """
        self.last_request = self.__build_packet(
            flags=flags,
            src_host=self.source_host,
            src_port=self.source_port,
            dst_host=self.destination_host,
            dst_port=self.destination_port,
            seq=seq,
            ack=ack,
            data=data,
        )
        answered, _ = sr(self.last_request, timeout=self.timeout or timeout, multi=True)

        if answered:
            _, self.last_response = answered[-1]

        return self.last_request, self.last_response
