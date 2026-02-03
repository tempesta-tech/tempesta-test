import asyncore
import select
import threading
import time
import traceback

from framework.services import stateful

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def finish_all_deproxy():
    asyncore.close_all()


class DeproxyManager(stateful.Stateful):
    """Class for running and managing
    deproxy servers and clients. polling cycle is also here.
    Tests don't need to manually use this class."""

    def __init__(self):
        super().__init__(id_="")
        self._exit_event = threading.Event()

        self._lock = threading.Lock()

        self.stop_procedures = [self.__stop]

    def clear_stats(self) -> None:
        self.servers = []
        self.clients = []
        self._proc = None

    def add_server(self, server):
        server.set_lock(self._lock)
        self.servers.append(server)

    def add_client(self, client):
        client.set_lock(self._lock)
        self.clients.append(client)

    def run_start(self):
        self._exit_event.clear()
        self._proc = threading.Thread(
            target=self.__run_deproxy_manager,
            args=(self._exit_event, self._lock),
        )
        self._proc.start()

    @stateful.Stateful.state.setter
    def state(self, new_state: str) -> None:
        """
        Set state for deproxy manager.
        Also set states for clients and servers if state is STATE_ERROR.
        """
        self._state = new_state
        if new_state != stateful.STATE_ERROR:
            return None

        for client in self.clients:
            client.state = new_state
        for server in self.servers:
            server.state = new_state
        return None

    def __stop(self):
        self._exit_event.set()
        self._proc.join()

    def __run_deproxy_manager(
        self,
        exit_event: threading.Event,
        polling_lock: threading.Lock,
    ):
        try:
            poll_fun = asyncore.poll2 if hasattr(select, "poll") else asyncore.poll
            while not exit_event.is_set():
                polling_lock.acquire()
                t1 = time.monotonic()
                poll_fun()
                d_t = time.monotonic() - t1
                if d_t > 1:
                    self._logger.warning(f"freeze while polling - {d_t}")
                polling_lock.release()
                # some system has freeze without timeout when try to acquire the Lock in other threads
                time.sleep(0.000001)
        except Exception as e:
            polling_lock.release()
            self._logger.critical("Error while polling: %s", e, exc_info=True)
            self.append_exception(traceback.format_exc())
