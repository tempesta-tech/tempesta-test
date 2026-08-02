__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc
import asyncio
import logging
import socket
import ssl
import struct
from ipaddress import AddressValueError, IPv4Address, IPv6Address, NetmaskValueError
from typing import Awaitable, Callable, Optional

import run_config


def safe_readwrite(func: Callable):
    """
    Decorator for the read/write loop coroutines: turns a broken/reset
    connection into a clean `close()` instead of an unhandled task
    exception. Shared by server and client connections.
    """

    async def wrapper(self: "DeproxyConnection"):
        try:
            await func(self)
        except BrokenPipeError:
            self.is_rst_received = False
            self._tcp_logger.info("Close TCP connection from the remote side.")
            await self.close()
        except ConnectionResetError:
            self.is_rst_received = True
            self._tcp_logger.info("Close TCP connection by RST from the remote side.")
            await self.close()

    return wrapper


class DeproxyConnection(abc.ABC):
    """
    Common asyncio-socket behaviour shared between the deproxy server and client

    Both sides need:
      * TCP segmentation on write (segment_size / segment_gap),
      * a cancellable/restartable read task,
      * a write loop that pulls items from a queue and survives a dead peer,
      * an idempotent `close()`.
    """

    def __init__(
        self, deproxy: "DeproxyBase", reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # objects
        self._deproxy: "DeproxyBase" = deproxy
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        # asyncio part
        self._readwrite = asyncio.Event()
        self._queue: asyncio.Queue[tuple[bytes, int] | None] = asyncio.Queue()
        self._write_func: Callable[[bytes], Awaitable[None]] = None
        self._read_task: asyncio.Task | None = None
        self._write_task: asyncio.Task | None = None
        # connection flags
        self.is_rst_received: Optional[bool] = None
        # loggers
        addr = writer.get_extra_info("peername")
        _id = f"{self.__class__.__name__}({addr[0]}:{addr[1]})"
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{_id}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{_id}"}
        )
        # initialize
        self._set_recv_buffer_size()
        self._tcp_logger.debug("New connection")

    def set_rst_tcp_to_closing_connection(self) -> None:
        """Set socket options to close the TCP connection with RST."""
        sock = self._writer.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

    def update_segment_size(self) -> None:
        """
        Set the data sending function according to the segment_size
        """
        self._write_func = (
            self._send_bytes_with_tcp_segmentation
            if self._deproxy.segment_size
            else self._send_bytes
        )
        self._tcp_logger.debug(f"Updated write method - {self._write_func}")

    @property
    def ssl_object(self) -> Optional[ssl.SSLObject]:
        return self._writer.get_extra_info("ssl_object")

    async def close(self) -> None:
        """
        Stop the connection and wait for it to stop.
        """
        self._tcp_logger.debug("Closing connection")
        if not self._readwrite.is_set():
            return
        self._readwrite.clear()

        self._queue.put_nowait(None)
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self._after_close()
            self._tcp_logger.debug("Closed")

    async def disable_readable(self) -> None:
        """Stop the reading task. The connection stops reading data from the socket"""
        if not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                ...

    def enable_readable(self) -> None:
        """Create a new reading task."""
        if not self._read_task.cancelled():
            raise Exception("Call disable_readable first")
        self._read_task = asyncio.create_task(self._read_loop())

    def _start_readwrite(self) -> None:
        """Create read and write tasks."""
        self._readwrite.set()
        self.update_segment_size()
        self._read_task = asyncio.create_task(self._read_loop())
        self._write_task = asyncio.create_task(self._write_loop())

    def _set_recv_buffer_size(self) -> None:
        if self._deproxy.rcv_buf_size >= 0:
            # don't expect that buffer will have exactly the same size as passed to
            # `setsockopt()`, the kernel may increase this size.
            sock = self._writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self._deproxy.rcv_buf_size)

    async def _send_bytes_with_tcp_segmentation(self, data: bytes) -> None:
        initial_len = len(data)
        seg_size = self._deproxy.segment_size
        self._tcp_logger.debug(
            f"Sending data with len={initial_len} and TCP segment_size={seg_size}"
        )
        if initial_len == 0:
            return

        view = memoryview(data)
        offset = 0

        while offset < initial_len:
            data_to_send = view[offset : offset + seg_size]
            self._writer.write(data_to_send)
            await self._writer.drain()

            offset += seg_size

            if self._deproxy.segment_gap:
                await asyncio.sleep(self._deproxy.segment_gap)

        self._tcp_logger.info(f"Segmented transfer finished. Total size: {initial_len} bytes")

    async def _send_bytes(self, data: bytes) -> None:
        self._tcp_logger.debug(f"Sending data with len={len(data)}")
        if len(data) == 0:
            return
        self._writer.write(data)
        await self._writer.drain()
        self._http_logger.info(f"A message was sent")

    @abc.abstractmethod
    async def _read_loop(self) -> None: ...

    @abc.abstractmethod
    async def _write_loop(self) -> None: ...

    @abc.abstractmethod
    def _after_close(self) -> None: ...


class DeproxyBase(abc.ABC):
    """
    A basic abstract class for managing deproxy connections.

    Provides a common logic for initializing network parameters, logging,
    and data segmentation for client and server deproxy connections.
    """

    def __init__(
        self,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
        rcv_buf_size: int,
    ):
        self._connections: list[DeproxyConnection] = list()
        self._message_event = asyncio.Event()
        self._connection_event = asyncio.Event()
        self.is_ipv6 = is_ipv6
        self.port = port
        self.bind_addr = bind_addr
        self._deproxy_auto_parser = deproxy_auto_parser
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{self}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{self}"}
        )
        self.segment_size = segment_size or run_config.TCP_SEGMENTATION or 0
        self.segment_gap = segment_gap
        self.rcv_buf_size = rcv_buf_size

    def __str__(self):
        return f"{self.__class__.__name__}({self.bind_addr}:{self.port})"

    @property
    def connections(self) -> list[DeproxyConnection]:
        return self._connections

    def remove_connection(self, connection: DeproxyConnection) -> None:
        self._connections.remove(connection)
        self._connection_event.set()

    @property
    def segment_size(self) -> int:
        return self._segment_size

    @segment_size.setter
    def segment_size(self, segment_size: int) -> None:
        """Set the segment_size and update all connections."""
        if segment_size < 0:
            raise ValueError("`segment_size` MUST be greater than or equal to 0.")
        self._segment_size = segment_size
        for conn in self.connections:
            conn.update_segment_size()

    @property
    def bind_addr(self) -> str:
        return str(self._bind_addr)

    @bind_addr.setter
    def bind_addr(self, bind_addr: str) -> None:
        self._bind_addr = self._set_and_check_ip_addr(bind_addr)

    def set_rst_tcp_to_closing_connection(self) -> None:
        """Set socket options to close the TCP connection with RST."""
        for con in self._connections:
            con.set_rst_tcp_to_closing_connection()

    def _set_and_check_ip_addr(self, addr: str) -> IPv6Address | IPv4Address:
        try:
            return IPv6Address(addr) if self.is_ipv6 else IPv4Address(addr)
        except (AddressValueError, NetmaskValueError):
            version = "IPv6" if self.is_ipv6 else "IPv4"
            raise ValueError(f"{addr} does not appear to be an {version} address") from None

    def _stop_procedures(self) -> list[Callable]:
        return [self._stop_deproxy]

    @abc.abstractmethod
    async def _stop_deproxy(self): ...
