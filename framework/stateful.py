import abc
import logging
import traceback
import typing

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

    def __init__(self, *, id_: str):
        self._state = STATE_STOPPED
        self.stop_procedures = []
        self.id_ = id_
        self._exceptions = []
        self._generate_service_id(id_)
        self._logger = logging.LoggerAdapter(
            logging.getLogger("service"), extra={"service": f"{self._service_id}"}
        )

    def _generate_service_id(self, id_: str) -> None:
        self._service_id = f"{self.__class__.__name__}({id_})"

    def __str__(self):
        return f"{self.__class__.__name__}"

    def get_name(self):
        return self.id_

    def get_id(self):
        return self.id_

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

    def start(self):
        """Try to start object"""
        self._logger.info("Starting...")
        if self.state != STATE_STOPPED:
            self._logger.warning(f"Not stopped")
            return
        self.state = STATE_BEGIN_START
        self._reinit_variables()
        self.run_start()
        self.state = STATE_STARTED
        self._logger.info("Start completed")

    def force_stop(self):
        """Stop object"""
        procedures_names = [procedure.__name__ for procedure in self.stop_procedures]
        self._logger.info(f"Stop procedures list: {procedures_names}")
        for stop_proc in self.stop_procedures:
            try:
                stop_proc()
                self.state = STATE_STOPPED
            except Exception as exc:
                tb_msg = traceback.format_exc()
                self._logger.error("Exception in stopping process: %s", exc, exc_info=True)
                self.append_exception(tb_msg)

    def stop(self, obj=""):
        """Try to stop object"""
        self._logger.info("Stopping...")
        if self.state != STATE_STARTED and self.state != STATE_BEGIN_START:
            self._logger.warning(f"Not started")
            return
        self.force_stop()
        self._logger.info("Stop completed")

    def is_running(self):
        return self.state == STATE_STARTED
