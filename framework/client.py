import abc
import multiprocessing
import os

from framework import stateful
from helpers import remote, tf_cfg, util


def _run_client(client, resq: multiprocessing.Queue):
    try:
        res = remote.client.run_cmd(client.cmd, timeout=(client.duration + 5))
    except remote.CmdError as e:
        res = (e.stdout, e.stderr)
        client.returncode = e.returncode
    resq.put(res)
    tf_cfg.dbg(3, "\tClient exit")


class Client(stateful.Stateful, metaclass=abc.ABCMeta):
    """Base class for managing HTTP benchmark utilities.

    Command-line options can be added by appending `Client.options` list.
    Also see comment in `Client.add_option_file()` function.
    """

    def __init__(self, binary, server_addr, uri="/", ssl=False):
        """`uri` must be relative to server root.

        DO NOT format command line options in constructor! Instead format them
        in `form_command()` function. This would allow to update options until
        client will be started. See `Wrk` class for example
        """
        super().__init__()
        self.node = remote.client
        self.connections = int(tf_cfg.cfg.get("General", "concurrent_connections"))
        self.duration = int(tf_cfg.cfg.get("General", "Duration"))
        self.workdir = tf_cfg.cfg.get("Client", "workdir")
        self.ssl = ssl
        self.server_addr = server_addr
        self.set_uri(uri)
        self.bin = tf_cfg.cfg.get_binary("Client", binary)
        self.cmd = ""
        self.clear_stats()
        # List of command-line options.
        self.options = []
        # List tuples (filename, content) to create corresponding files on
        # remote node.
        self.files = []
        # Process
        self.proc = None
        self.returncode = 0
        self.resq = multiprocessing.Queue()
        self.proc_results = None
        # List of files to be removed from remote node after client finish.
        self.cleanup_files = []
        self.requests = 0
        self.rate = -1
        self.errors = 0
        self.statuses = {}
        # Stateful
        self.stop_procedures = [self.__on_finish]

    def __str__(self):
        return self.bin

    def set_uri(self, uri):
        """For some clients uri is an optional parameter, e.g. for Siege.
        They use file with list of uris instead. Don't force clients to use
        uri field.
        """
        if not uri:
            self.uri = ""
            return
        proto = "https://" if self.ssl else "http://"
        self.uri = "".join([proto, self.server_addr, uri])

    def clear_stats(self):
        self.requests = 0
        self.rate = -1
        self.errors = 0
        self.statuses = {}

    def cleanup(self):
        for f in self.cleanup_files:
            self.node.remove_file(f)

    def copy_files(self):
        for name, content in self.files:
            self.node.copy_file(name, content)

    def is_busy(self, verbose=True):
        busy = self.resq.empty()
        if verbose:
            if busy:
                tf_cfg.dbg(4, "\tClient is running")
            else:
                tf_cfg.dbg(4, "\tClient is not running")
        return busy

    def __on_finish(self):
        if not hasattr(self.proc, "terminate"):
            return
        tf_cfg.dbg(3, "Stopping client")

        self.proc_results = self.resq.get(timeout=self.duration)

        self.proc.join()
        self.proc = None

        if self.proc_results:
            tf_cfg.dbg(3, "\tclient stdout:\n%s" % self.proc_results[0].decode())

            if len(self.proc_results[1]) > 0:
                tf_cfg.dbg(2, "\tclient stderr:\n%s" % self.proc_results[1].decode())

            self.parse_out(self.proc_results[0], self.proc_results[1])
        else:
            tf_cfg.dbg(
                2,
                f'\tCmd command "{self.cmd}" has not received data from queue. '
                + "Queue is empty and timeout is over.",
            )

        tf_cfg.dbg(3, "Client is stopped")

    def run_start(self):
        """Run client"""
        tf_cfg.dbg(3, "Running client")
        self.prepare()
        self.proc = multiprocessing.Process(target=_run_client, args=(self, self.resq))
        self.proc.start()

    @abc.abstractmethod
    def parse_out(self, stdout, stderr):
        """Parse framework results."""
        print(stdout.decode("ascii"), stderr.decode("ascii"))
        return True

    def form_command(self):
        """Prepare run command for benchmark to run on remote node."""
        cmd = " ".join([self.bin] + self.options + [self.uri])
        return cmd

    def prepare(self):
        self.cmd = self.form_command()
        self.clear_stats()
        self.copy_files()
        return True

    def results(self):
        if self.rate == -1:
            self.rate = self.requests / self.duration
        return self.requests, self.errors, self.rate, self.statuses

    def add_option_file(self, option, filename, content):
        """Helper for using files as client options: normally file must be
        copied to remote node, present in command line as parameter and
        removed after client finish.
        """
        full_name = os.path.join(self.workdir, filename)
        self.files.append((filename, content))
        self.options.append("%s %s" % (option, full_name))
        self.cleanup_files.append(full_name)

    def set_user_agent(self, ua):
        self.options.append("-H 'User-Agent: %s'" % ua)

    def wait_for_finish(self, timeout=5):
        return util.wait_until(lambda: self.is_busy(verbose=False), timeout)
