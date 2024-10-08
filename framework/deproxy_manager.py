import asyncore
import queue
import select
import threading
import traceback

from framework import stateful
from helpers import tf_cfg


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"


def finish_all_deproxy():
    asyncore.close_all()


def run_deproxy_server(
    deproxy: "DeproxyManager",
    exit_event: threading.Event,
    polling_lock: threading.Lock,
):
    tf_cfg.dbg(3, "Running deproxy server manager")

    try:
        if hasattr(select, "poll"):
            poll_fun = asyncore.poll2
        else:
            poll_fun = asyncore.poll
        while not exit_event.is_set():
            polling_lock.acquire()
            poll_fun()
            polling_lock.release()
    except Exception as e:
        tf_cfg.dbg(1, "Error while polling: %s" % str(e))
        polling_lock.release()
        deproxy.append_exception(traceback.format_exc())
    tf_cfg.dbg(3, "Finished deproxy manager")


class DeproxyManager(stateful.Stateful):
    """Class for running and managing
    deproxy servers and clients. polling cycle is also here.
    Tests don't need to manually use this class."""

    def __init__(self):
        super().__init__()
        self.thread_expts = queue.Queue()
        self.servers = []
        self.clients = []
        self.exit_event = threading.Event()

        self.polling_lock = threading.Lock()

        self.stop_procedures = [self.__stop]
        self.proc = None

    def add_server(self, server):
        server.set_events(self.polling_lock)
        self.servers.append(server)

    def add_client(self, client):
        client.set_events(self.polling_lock)
        self.clients.append(client)

    # run section
    def run_start(self):
        tf_cfg.dbg(3, "Running deproxy")
        self.exit_event.clear()
        self.proc = threading.Thread(
            target=run_deproxy_server,
            args=(self, self.exit_event, self.polling_lock),
        )
        self.proc.start()

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

    def __stop(self):
        tf_cfg.dbg(3, "Stopping deproxy")
        self.exit_event.set()
        self.proc.join()
