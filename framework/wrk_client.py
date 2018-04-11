import multiprocessing

from helpers import control, stateful, tf_cfg, remote
from templates import fill_template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def run_wrk(wrk, exit_event, resq):
    res = remote.client.run_cmd(wrk.cmd, timeout=(wrk.duration + 5))
    tf_cfg.dbg(3, "Wrk exit")
    resq.put(res)
    exit_event.set()

class Wrk(control.Wrk, stateful.Stateful):
    def __init__(self, *args, **kwargs):
        self.server_addr = fill_template(kwargs['addr'])
        kwargs.pop('addr', None)
        control.Wrk.__init__(self, *args, **kwargs)
        self.stop_procedures = [self.__on_finish]
        self.proc = None
        self.returncode = 0
        self.exit_event = multiprocessing.Event()
        self.exit_event.clear()
        self.resq = multiprocessing.Queue()
        self.results = None

    def set_uri(self, uri):
        """ For some clients uri is an optional parameter, e.g. for Siege.
        They use file with list of uris instead. Don't force clients to use
        uri field.
        """
        if uri:
            proto = 'https://' if self.ssl else 'http://'
            self.uri = ''.join([proto, self.server_addr, uri])
        else:
            self.uri = ''

    def is_busy(self):
        busy = not self.exit_event.is_set()
        if busy:
            tf_cfg.dbg(4, "Wrk is running")
        else:
            tf_cfg.dbg(4, "Wrk is not running")
        return busy

    def __on_finish(self):
        if self.proc != None:
            self.proc.terminate()
            self.proc.join()
            self.returncode = self.proc.exitcode
            self.results = self.resq.get()
            self.proc = None
            tf_cfg.dbg(3, 'wrk stdout:\n%s' % self.results[0])
            if len(self.results[1]) > 0:
                tf_cfg.dbg(2, 'wrk stderr:\n%s' % self.results[1])
            if self.results != None:
                self.parse_out(self.results[0], self.results[1])

    def run_start(self):
        """ Run wrk """
        tf_cfg.dbg(3, "Running wrk")
        self.exit_event.clear()
        self.prepare()
        self.proc = multiprocessing.Process(target = run_wrk,
                                    args=(self, self.exit_event, self.resq))
        self.proc.start()
