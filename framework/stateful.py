import abc
import typing

from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

STATE_BEGIN_START = "begin_start"
STATE_STARTED = "started"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"


class Stateful(abc.ABCMeta):
    """Class for stateful items, who have states
    stopped -> started -> stopped"""

    _state = STATE_STOPPED
    stop_procedures = []

    @property
    def state(self) -> str:
        return self._state

    @state.setter
    def state(self, new_state: str) -> None:
        if new_state not in [STATE_BEGIN_START, STATE_STARTED, STATE_STOPPED, STATE_ERROR]:
            raise ValueError('Please use valid values for "Stateful".')
        self._state = new_state

    @property
    def exceptions(self) -> typing.List[Exception]:
        # TODO it should be change after #534 issue
        return self._exceptions

    def append_exception(self, exception: Exception) -> None:
        # TODO it should be change after #534 issue
        self._exceptions.append(exception)
        self.state = STATE_ERROR

    def run_start(self):
        """Should be overridden"""
        pass

    def restart(self):
        self.stop()
        self.start()

    def start(self, obj=""):
        """Try to start object"""
        if self.state != STATE_STOPPED:
            if obj == "":
                tf_cfg.dbg(3, "Not stopped")
            else:
                tf_cfg.dbg(3, "%s not stopped" % obj)
            return
        self.state = STATE_BEGIN_START
        self._exceptions = list()
        self.run_start()
        self.state = STATE_STARTED

    def force_stop(self):
        """Stop object"""
        for stop_proc in self.stop_procedures:
            try:
                stop_proc()
            except Exception as exc:
                tf_cfg.dbg(1, f"Exception in stopping process: {exc}, type: {type(exc)}")
                self.append_exception(exc)

        if self.state != STATE_ERROR:
            self.state = STATE_STOPPED

    def stop(self, obj=""):
        """Try to stop object"""
        if self.state != STATE_STARTED and self.state != STATE_BEGIN_START:
            if obj == "":
                tf_cfg.dbg(3, "Not started")
            else:
                tf_cfg.dbg(3, "%s not started" % obj)
            return
        self.force_stop()

    def is_running(self):
        return self.state == STATE_STARTED

    def check_exceptions(self):
        """Raise exception if error was received."""
        # TODO it should be change after #534 issue
        if self.state == STATE_ERROR:
            raise self.exceptions[0]
