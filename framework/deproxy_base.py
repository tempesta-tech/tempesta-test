__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc
import threading

from framework.stateful import Stateful
from helpers import tf_cfg


class DeproxyBaseClass(Stateful, abc.ABC):
    """
    Class with a common logic for the deproxy client\server.
    """

    def __init__(self):
        super().__init__()
        self._polling_lock: threading.Lock | None = None

    def set_events(self, polling_lock: threading.Lock) -> None:
        self._polling_lock = polling_lock

    def _lock_acquire(self) -> None:
        tf_cfg.dbg(5, "Try to capture the thread Lock")
        self._polling_lock.acquire()
        tf_cfg.dbg(5, "Thread Lock was successfully captured")

    def _lock_release(self) -> None:
        tf_cfg.dbg(5, "Try to release the thread Lock")
        self._polling_lock.release()
        tf_cfg.dbg(5, "Thread Lock has been successfully released")
