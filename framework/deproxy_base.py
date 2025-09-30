__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc
import asyncore
import logging
import threading
from abc import ABC
from ipaddress import AddressValueError, IPv4Address, IPv6Address, NetmaskValueError
from typing import Optional

import run_config
from framework.stateful import Stateful


class BaseDeproxy(asyncore.dispatcher, Stateful, ABC):
    def __init__(
        self,
        *,
        id_: str,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
    ):
        # Initialize the base `dispatcher`
        asyncore.dispatcher.__init__(self)

        self._deproxy_auto_parser = deproxy_auto_parser
        self.is_ipv6 = is_ipv6
        self.port = port
        self.bind_addr = bind_addr
        self.segment_size = segment_size or run_config.TCP_SEGMENTATION or 0
        self.segment_gap = segment_gap
        self.__polling_lock: Optional[threading.Lock] = None

        Stateful.__init__(self, id_=id_)

        self.stop_procedures: list[callable] = [self.__stop]

        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{self._service_id}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{self._service_id}"}
        )

    def _generate_service_id(self, id_: str) -> None:
        self._service_id = f"{self.__class__.__name__}({self.bind_addr}:{self.port})"

    def set_lock(self, polling_lock: threading.Lock) -> None:
        self.__polling_lock = polling_lock

    def bind(self, address: tuple) -> None:
        """
        Wrapper for `bind` method to add some log details.

        `bind` is originally `asyncore.dispatcher` method and declared in there.

        Args:
            address (tuple): address to bind
        """
        self._tcp_logger.info(f"Trying to bind {str(address)} for {self.__class__.__name__}")
        try:
            super().bind(address)
        # When we cannot bind an address, adding more details
        except OSError as os_exc:
            os_err_msg = (
                f"Cannot assign an address `{str(address)}` for `{self.__class__.__name__}`"
            )
            self._tcp_logger.error(os_err_msg, exc_info=True)
            raise OSError(os_err_msg) from os_exc

    def run_start(self):
        self.__acquire()

        try:
            self._run_deproxy()
        except Exception as e:
            self._tcp_logger.error(
                f"Error while creating socket {self.bind_addr}:{self.port}: {str(e)}"
            )
            raise e
        finally:
            self.__release()

    def __stop(self) -> None:
        self.__acquire()
        try:
            self._stop_deproxy()
            self.clear_stats()
        except Exception as e:
            self._tcp_logger.error("Exception while stop", exc_info=True)
            raise e
        finally:
            self.__release()

    def __acquire(self) -> None:
        self._tcp_logger.debug("Try to capture the thread Lock")
        self.__polling_lock.acquire()
        self._tcp_logger.debug("Thread Lock was successfully captured")

    def __release(self) -> None:
        self._tcp_logger.debug("Try to release the thread Lock")
        self.__polling_lock.release()
        self._tcp_logger.debug("Thread Lock has been successfully released")

    @abc.abstractmethod
    def _stop_deproxy(self) -> None: ...

    @abc.abstractmethod
    def _run_deproxy(self) -> None: ...

    @property
    def bind_addr(self) -> str:
        return str(self._bind_addr)

    @bind_addr.setter
    def bind_addr(self, bind_addr: str) -> None:
        self._bind_addr = self._set_and_check_ip_addr(bind_addr)

    def _set_and_check_ip_addr(self, addr: str) -> IPv6Address | IPv4Address:
        try:
            return IPv6Address(addr) if self.is_ipv6 else IPv4Address(addr)
        except (AddressValueError, NetmaskValueError):
            version = "IPv6" if self.is_ipv6 else "IPv4"
            raise ValueError(f"{addr} does not appear to be an {version} address") from None

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, port: int) -> None:
        if port <= 0:
            raise ValueError("The server port MUST be greater than 0.")
        self._port = port

    @property
    def segment_size(self) -> int:
        return self._segment_size

    @segment_size.setter
    def segment_size(self, segment_size: int) -> None:
        if segment_size < 0:
            raise ValueError("`segment_size` MUST be greater than or equal to 0.")
        self._segment_size = segment_size

    @property
    def segment_gap(self) -> int:
        return self._segment_gap

    @segment_gap.setter
    def segment_gap(self, segment_gap: int) -> None:
        if segment_gap < 0:
            raise ValueError("`segment_gap` MUST be greater than or equal to 0.")
        self._segment_gap = segment_gap
