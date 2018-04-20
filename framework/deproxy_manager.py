import Queue
import threading
import asyncore
import select
import time

from helpers import stateful, tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def finish_all_deproxy():
    asyncore.close_all()

def run_deproxy_server(deproxy, exit_event, is_polling, sockets_changing):
    tf_cfg.dbg(3, "Running deproxy server manager")

    if hasattr(select, 'poll'):
        poll_fun = asyncore.poll2
    else:
        poll_fun = asyncore.poll
    while not exit_event.is_set():
        while sockets_changing.is_set() and not exit_event.is_set():
            pass
        if exit_event.is_set():
            break
        is_polling.set()
        poll_fun()
        is_polling.clear()
        # servers need some time for locking
        time.sleep(0.0001)

    tf_cfg.dbg(3, "Stopped deproxy manager")

class DeproxyManager(stateful.Stateful):

    def __init__(self):
        self.servers = []
        self.clients = []
        self.exit_event = threading.Event()
        # event is set, when polling
        self.is_polling = threading.Event()
        # event is set, when server changes sockets
        self.sockets_changing = threading.Event()
        self.stop_procedures = [self.__stop]
        self.proc = None

    def add_server(self, server):
        server.set_events(self.is_polling, self.sockets_changing)
        self.servers.append(server)

    def add_clients(self, client):
        self.clients.append(client)

    # run section
    def run_start(self):
        tf_cfg.dbg(3, "Running deproxy")
        self.exit_event.clear()
        self.proc = threading.Thread(target = run_deproxy_server,
                                    args=(self, self.exit_event,
                                          self.is_polling,
                                          self.sockets_changing))
        self.proc.start()

    def __stop(self):
        tf_cfg.dbg(3, "Stopping deproxy")
        self.exit_event.set()
        self.proc.join()
