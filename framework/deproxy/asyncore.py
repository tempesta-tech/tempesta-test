"""An analog of asyncore from python3.10 version."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


import abc
import errno
import select
import socket
import ssl

socket_map: dict[str, "DeproxyAsyncore"] = dict()


disconnected = frozenset(
    {
        errno.ECONNRESET,
        errno.ENOTCONN,
        errno.ESHUTDOWN,
        errno.ECONNABORTED,
        errno.EPIPE,
        errno.EBADF,
    }
)


class DeproxyAsyncore(abc.ABC):
    def __init__(self, is_ipv6: bool):
        self.is_ipv6: bool = is_ipv6

        self.connected: bool = False
        self.connecting: bool = False
        self.accepting: bool = False

        self.addr: tuple[str, int] = None
        self._fileno: int = None
        self._socket: socket.socket | ssl.SSLSocket = None

    def _create_socket(self):
        sock = socket.socket(
            socket.AF_INET6 if self.is_ipv6 else socket.AF_INET, socket.SOCK_STREAM
        )
        self._set_socket(sock)

    def _set_socket(self, sock: socket.socket):
        self._socket = sock
        self._socket.setblocking(False)
        self._fileno = sock.fileno()
        self._add_channel()

    def _add_channel(self) -> None:
        socket_map[self._fileno] = self

    def _del_channel(self) -> None:
        if self._fileno in socket_map:
            del socket_map[self._fileno]
        self._fileno = None

    def _set_reuse_addr(self) -> None:
        """try to re-use a server port if possible."""
        try:
            self._socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1,
            )
        except OSError:
            pass

    # socket methods

    def _listen(self) -> None:
        self.accepting = True
        self._socket.listen(socket.SOMAXCONN)

    def _connect(self, address) -> None:
        self.connected = False
        self.connecting = True
        err = self._socket.connect_ex(address)
        if err in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
            self.addr = address
            return
        if err in (0, errno.EISCONN):
            self.addr = address
            self._handle_connect_event()
        else:
            raise OSError(err, errno.errorcode[err])

    def _accept(self):
        try:
            conn, addr = self._socket.accept()
        except TypeError:
            return None
        except OSError as why:
            if why.errno in (errno.EWOULDBLOCK, errno.ECONNABORTED, errno.EAGAIN):
                return None
            else:
                raise
        else:
            return conn, addr

    def _send(self, data: bytes) -> int:
        try:
            result = self._socket.send(data)
            return result
        except OSError as why:
            if why.errno == errno.EWOULDBLOCK:
                return 0
            elif why.errno in disconnected:
                self._handle_close()
                return 0
            else:
                raise

    def _recv(self, buffer_size: int) -> bytes:
        try:
            data = self._socket.recv(buffer_size)
            if not data:
                # a closed connection is indicated by signaling
                # a read condition, and having recv() return 0.
                self._handle_close()
                return b""
            else:
                return data
        except OSError as why:
            # winsock sometimes raises ENOTCONN
            if why.errno in disconnected:
                self._handle_close()
                return b""
            else:
                raise

    # deproxy methods

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def _handle_connect_event(self):
        err = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err, errno.errorcode[err])
        self._handle_connect()
        self.connected = True
        self.connecting = False

    def _handle_read_event(self):
        if self.accepting:
            self._handle_accept()
        elif not self.connected:
            if self.connecting:
                self._handle_connect_event()
            self._handle_read()
        else:
            self._handle_read()

    def _handle_write_event(self) -> None:
        if self.accepting:
            return

        if not self.connected:
            if self.connecting:
                self._handle_connect_event()
        self._handle_write()

    def _handle_error(self) -> None:
        """Proces exceptions."""

    def _handle_read(self) -> None:
        """Read data from socket and parse it."""

    def _handle_write(self) -> None:
        """Write data to socket and send them."""

    def _handle_connect(self) -> None:
        """Connect to remote socket."""

    def _handle_accept(self) -> None:
        """Accept a new connection."""
        pair = self._accept()
        if pair is not None:
            sock, _ = pair
            sock.close()

    def _handle_close(self) -> None:
        """Close socket and remove it from socket map."""
        self.connected = False
        self.accepting = False
        self.connecting = False
        self._del_channel()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError as why:
                if why.errno not in (errno.ENOTCONN, errno.EBADF):
                    raise

    def _readwrite(self, flags) -> None:
        try:
            if flags & select.POLLIN:
                self._handle_read_event()
            if flags & select.POLLOUT:
                self._handle_write_event()
            if flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                self._handle_close()
        except OSError as e:
            if e.errno not in disconnected:
                self._handle_error()
            else:
                self._handle_close()
        except:
            self._handle_error()
