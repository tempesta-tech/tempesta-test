__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc

from framework.helpers import port_checks, remote, tf_cfg, util
from framework.services import stateful, tempesta


class BaseServer(stateful.Stateful, abc.ABC):
    """
    Base class for managing backends.
    """

    def __init__(self, id_: str):
        super().__init__(id_=id_)
        self._workdir = tf_cfg.cfg.get("Server", "workdir")
        self.port_checker = port_checks.FreePortsChecker()
        self.conns_n = tempesta.server_conns_default()
        self.node = remote.server

    @property
    def conns_n(self) -> int:
        return self._conns_n

    @conns_n.setter
    def conns_n(self, conns_n: int) -> None:
        if conns_n < 0:
            raise ValueError("`conns_n` MUST be greater than or equal to 0.")
        self._conns_n = conns_n

    async def wait_for_connections(
        self, timeout: float = 1.0, strict: bool = False, msg: str = None
    ) -> bool | None:
        """
        Wait until the container becomes healthy
        and Tempesta establishes connections to the server ports.
        """
        if self.state != stateful.STATE_STARTED:
            return False

        result = await util.wait_until(
            self._wait_for_connections,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
            timeout=timeout,
        )

        if strict:
            assert result, msg or f"Tempesta FW don't create connection to {self}."
        return result

    @abc.abstractmethod
    def _wait_for_connections(self) -> bool: ...
