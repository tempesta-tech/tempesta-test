import Queue
import threading
import asyncore
import select

from helpers import stateful, tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def finish_all_deproxy():
    asyncore.close_all()

def run_deproxy_server(deproxy, exit_event, queue):
    tf_cfg.dbg(3, "Running deproxy server manager")
    s_map = asyncore.socket_map

    if hasattr(select, 'poll'):
        poll_fun = asyncore.poll2
    else:
        poll_fun = asyncore.poll
    while not exit_event.is_set():
        s_map = asyncore.socket_map
        if s_map:
            poll_fun(map=s_map)

    tf_cfg.dbg(3, "Stopped deproxy manager")

class DeproxyManager(stateful.Stateful):

    def __init__(self):
        self.servers = []
        self.clients = []
        self.exit_event = threading.Event()
        self.resq = Queue.Queue()
        self.stop_procedures = [self.__stop]
        self.proc = None

    def add_server(self, server):
        self.servers.append(server)

    def add_clients(self, client):
        self.clients.append(client)

    # run section
    def run_start(self):
        tf_cfg.dbg(3, "Running deproxy")
        self.exit_event.clear()
        self.proc = threading.Thread(target = run_deproxy_server,
                                    args=(self, self.exit_event, self.resq))
        self.proc.start()

    def __stop(self):
        tf_cfg.dbg(3, "Stopping deproxy")
        self.exit_event.set()
        self.proc.join()
