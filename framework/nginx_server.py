from helpers import control, tf_cfg, remote, tempesta
from templates import fill_template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Nginx(control.Nginx):
    """ Nginx class """

    class Config(object):

        def __init__(self, template, name):
            self.workdir = tf_cfg.cfg.kvs['server_workdir']
            pidname = self.workdir + "/nginx_" + name + ".pid"
            self.config = fill_template(template, {'backend_pid' : pidname})
            self.config_name = 'nginx_%s.cfg' % name
            self.pidfile_name = pidname

    def __init__(self, config, name):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        self.config = self.Config(config, name)
        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.err_msg = "Can't %s Nginx on %s"
        self.active_conns = 0
        self.requests = 0
        self.name = name
        self.stop_procedures = [self.stop_nginx, self.remove_config]

    def get_name(self):
        return self.name
