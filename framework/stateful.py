import abc
import traceback
import typing

from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

STATE_BEGIN_START = "begin_start"
STATE_STARTED = "started"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"


class Stateful(abc.ABC):
    """
    Class for stateful items, who have states
    stopped -> started -> stopped
    """

    def __init__(self):
        self._state = STATE_STOPPED
        self.stop_procedures = []
        self._exceptions = []

    def __str__(self):
        return f"{self.__class__.__name__}"

    @property
    def state(self) -> str:
        return self._state

    @state.setter
    def state(self, new_state: str) -> None:
        if new_state not in [STATE_BEGIN_START, STATE_STARTED, STATE_STOPPED, STATE_ERROR]:
            raise ValueError('Please use valid values for "Stateful".')
        self._state = new_state

    @property
    def exceptions(self) -> typing.List[str]:
        return self._exceptions

    def append_exception(self, exception: str) -> None:
        self._exceptions.append(exception)
        self.state = STATE_ERROR

    @abc.abstractmethod
    def run_start(self): ...

    def _reinit_variables(self) -> None:
        """
        The optional method. It MUST be called only inside the `start` and `init` methods.
        All counters or dynamic variables for the service should be reset here.
        """

    def restart(self):
        self.stop()
        self.start()

    def start(self, obj=""):
        """Try to start object"""
        if self.state != STATE_STOPPED:
            tf_cfg.dbg(3, f"{obj or self} not stopped")
            return
        self.state = STATE_BEGIN_START
        self._reinit_variables()
        self.run_start()
        self.state = STATE_STARTED

    def force_stop(self):
        """Stop object"""
        for stop_proc in self.stop_procedures:
            try:
                stop_proc()
                self.state = STATE_STOPPED
            except Exception as exc:
                tb_msg = traceback.format_exc()
                tf_cfg.dbg(
                    1,
                    f"Exception in stopping process: {exc}, type: {type(exc)}, traceback:\n{tb_msg}",
                )
                self.append_exception(tb_msg)

    def stop(self, obj=""):
        """Try to stop object"""
        if self.state != STATE_STARTED and self.state != STATE_BEGIN_START:
            tf_cfg.dbg(3, f"{obj or self} not started")
            return
        self.force_stop()

    def is_running(self):
        return self.state == STATE_STARTED
