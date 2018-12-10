""" Controls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import re
import os
import abc
import errno
import shutil
import time
import subprocess32 as subprocess
import paramiko
from . import tf_cfg, error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Don't remove files from remote node. Helpful for tests development.
DEBUG_FILES = False
# Default timeout for SSH sessions and command processing.
DEFAULT_TIMEOUT = 5

class Node(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, remote_type, hostname, workdir):
        self.host = hostname
        self.workdir = workdir
        self.type = remote_type

    def is_remote(self):
        return self.host != 'localhost'

    @abc.abstractmethod
    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False,
                err_msg='', env=None):
        pass

    @abc.abstractmethod
    def mkdir(self, path):
        pass

    @abc.abstractmethod
    def copy_file(self, filename, content):
        pass

    @abc.abstractmethod
    def copy_file_to_node(self, file_name, dest_dir):
        pass

    @abc.abstractmethod
    def remove_file(self, filename):
        pass

    @abc.abstractmethod
    def wait_available(self):
        pass

class LocalNode(Node):
    def __init__(self, remote_type, hostname, workdir):
        Node.__init__(self, remote_type, hostname, workdir)

    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False,
                err_msg='', env=None):
        tf_cfg.dbg(4, "\tRun command '%s' on host %s with environment %s" % (cmd, self.host, env))
        stdout = ''
        stderr = ''
        stderr_pipe = (open(os.devnull, 'w') if ignore_stderr
                       else subprocess.PIPE)
        # Popen() expects full environment
        env_full = {}
        env_full.update(os.environ)
        if env:
            env_full.update(env)
        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=stderr_pipe, env=env_full) as proc:
            try:
                stdout, stderr = proc.communicate(timeout)
                assert proc.returncode == 0, "Return code is not 0."
            except Exception:
                if not err_msg:
                    err_msg = ("Error running command '%s' on %s" %
                               (cmd, self.host))
                raise Exception("Remote error: %s, stdout = %s, stderr = %s" %
                                (err_msg, stdout, stderr))
        return stdout, stderr

    def mkdir(self, path):
        try:
            os.makedirs(path)
        except OSError:
            if not os.path.isdir(path):
                raise

    def copy_file(self, filename, content):
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        with open(filename, 'w') as new_file:
            new_file.write(content)

    def copy_file_to_node(self, file_name, dest_dir):
        shutil.copy(file_name, dest_dir)

    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        if os.path.isfile(filename):
            os.remove(filename)

    def wait_available(self):
        return True


class RemoteNode(Node):
    def __init__(self, remote_type, hostname, workdir, user, port=22):
        Node.__init__(self, remote_type, hostname, workdir)
        self.user = user
        self.port = port
        self.connect()

    def connect(self):
        """ Open SSH connection to node if remote. Returns False on SSH errors.
        """
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.load_system_host_keys()
            # Workaround: paramiko prefer RSA keys to ECDSA, so add RSA
            # key to known_hosts.
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname=self.host, username=self.user,
                             port=self.port, timeout=DEFAULT_TIMEOUT)
        except Exception:
            error.bug("Error connecting %s" % self.host)

    def close(self):
        """ Release SSH connection without waiting for GC. """
        self.ssh.close()

    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False,
                err_msg='', env=None):
        tf_cfg.dbg(4, "\tRun command '%s' on host %s with environment %s" %
                   (cmd, self.host, env))
        stderr = ''
        stdout = ''
        # we could simply pass environment to exec_command(), but openssh' default
        # is to reject such environment variables, so pass them via env(1)
        if env:
            cmd = ' '.join([
                'env',
                ' '.join(["%s='%s'" % (k, v) for k, v in env.items()]),
                cmd
            ])
            tf_cfg.dbg(4, "\tEffective command '%s' after injecting environment" % cmd)
        try:
            _, out_f, err_f = self.ssh.exec_command(cmd, timeout=timeout)
            stdout = out_f.read()
            if not ignore_stderr:
                stderr = err_f.read()
            assert out_f.channel.recv_exit_status() == 0, "Return code is not 0."
        except Exception:
            if not err_msg:
                err_msg = ("Error running command '%s' on %s" %
                           (cmd, self.host))
            error.bug(err_msg, stdout=stdout, stderr=stderr)
        return stdout, stderr

    def mkdir(self, path):
        self.run_cmd('mkdir -p %s' % path)

    def copy_file(self, filename, content):
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        try:
            sftp = self.ssh.open_sftp()
            sfile = sftp.file(filename, 'w', -1)
            sfile.write(content)
            sfile.flush()
            sftp.close()
        except Exception:
            error.bug(("Error copying file %s to %s" %
                       (filename, self.host)))

    def copy_file_to_node(self, file_name, dest_dir):
        try:
            sftp = self.ssh.open_sftp()
            sftp.put(file_name, dest_dir)
            sftp.close()
        except Exception:
            error.bug(("Error copying file %s to %s" %
                       (file_name, self.host)))

    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        try:
            sftp = self.ssh.open_sftp()
            try:
                sftp.unlink(filename)
            except IOError as exc:
                if exc.errno != errno.ENOENT:
                    raise
            sftp.close()
        except Exception:
            error.bug(("Error removing file %s on %s" %
                       (filename, self.host)))

    def wait_available(self):
        tf_cfg.dbg(3, '\tWaiting for %s node' % self.type)
        timeout = float(tf_cfg.cfg.get(self.type, 'unavaliable_timeout'))
        t_start = time.time()
        while True:
            t_curr = time.time()
            delta = t_curr - t_start
            tf_cfg.dbg(3, "\tAttempt to access node")
            if delta > timeout:
                tf_cfg.dbg(2, "Node %s is not available" % self.type)
                return False
            try:
                res, _ = self.run_cmd("echo -n check", timeout=1)
                tf_cfg.dbg(4, "Result = [%s]" % res)
                if res == "check":
                    tf_cfg.dbg(2, "Node %s is available" % self.type)
                    return True
            except Exception:
                try:
                    self.connect()
                except:
                    pass

            time.sleep(1)

def create_host_node():
    workdir = tf_cfg.cfg.get('General', 'workdir')
    return LocalNode('General', 'localhost', workdir)

def create_node(host):
    hostname = tf_cfg.cfg.get(host, 'hostname')
    workdir = tf_cfg.cfg.get(host, 'workdir')

    if hostname != 'localhost':
        port = int(tf_cfg.cfg.get(host, 'port'))
        username = tf_cfg.cfg.get(host, 'user')
        return RemoteNode(host, hostname, workdir, username, port)
    return LocalNode(host, hostname, workdir)


#-------------------------------------------------------------------------------
# Helper functions.
#-------------------------------------------------------------------------------

def get_max_thread_count(node):
    out, _ = node.run_cmd('grep -c processor /proc/cpuinfo')
    matches = re.match(r'^(\d+)$', out)
    if not matches:
        return 1
    return int(matches.group(1).decode('ascii'))

#-------------------------------------------------------------------------------
# Global accessible SSH/Local connections
#-------------------------------------------------------------------------------

client = None
tempesta = None
server = None
host = None

def connect():
    global client
    client = create_node('Client')

    global tempesta
    tempesta = create_node('Tempesta')

    global server
    server = create_node('Server')

    global host
    host = create_host_node()

    for node in [client, server, tempesta, host]:
        node.mkdir(node.workdir)

def wait_available():
    global client
    global server
    global tempesta

    for node in [client, server, tempesta]:
        if not node.wait_available():
            return False
    return True

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
