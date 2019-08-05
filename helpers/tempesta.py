import re
from . import error, remote, tf_cfg
from framework.x509 import CertGenerator

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Tempesta capabilities:
def servers_in_group():
    """ Max servers in server group. """
    return 32

def server_conns_default():
    """ Default connections to single upstream server. """
    return 32

def server_conns_max():
    """ Maximum connections to single upstream server used in the tests.
    Tempesta has no maximum limit for the value.
    """
    return 32

def upstream_port_start_from():
    """ Start value for upstream servers listen port. Just for convenience. """
    return 8000

# Version_info_cache
tfw_version = ''

def version():
    """TempestaFW current version. Defined in tempesta_fw.h:
    #define TFW_VERSION		"0.5.0-pre6"
    """
    global tfw_version
    if tfw_version:
        return tfw_version
    srcdir = tf_cfg.cfg.get('Tempesta', 'srcdir')
    hdr_filename = srcdir + "/tempesta_fw/tempesta_fw.h"
    parse_cmd = r"grep TFW_VERSION | awk -F '[\" ]' '{printf $3}'"
    cmd = "cat %s | %s" % (hdr_filename, parse_cmd)
    version, _ = remote.tempesta.run_cmd(cmd=cmd)
    tfw_version = version
    error.assertTrue(tfw_version)
    return version

class Stats(object):
    """ Parser for TempestaFW performance statistics (/proc/tempesta/perfstat).
    """

    def __init__(self):
        self.clear()

    def clear(self):
        self.ss_pfl_hits = 0
        self.ss_pfl_misses = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cl_msg_received = 0
        self.cl_msg_forwarded = 0
        self.cl_msg_served_from_cache = 0
        self.cl_msg_parsing_errors = 0
        self.cl_msg_filtered_out = 0
        self.cl_msg_other_errors = 0
        self.cl_conn_attempts = 0
        self.cl_established_connections = 0
        self.cl_conns_active = 0
        self.cl_rx_bytes = 0
        self.srv_msg_received = 0
        self.srv_msg_forwarded = 0
        self.srv_msg_parsing_errors = 0
        self.srv_msg_filtered_out = 0
        self.srv_msg_other_errors = 0
        self.srv_conn_attempts = 0
        self.srv_established_connections = 0
        self.srv_conns_active = 0
        self.srv_rx_bytes = 0

    def parse(self, stats):
        self.ss_pfl_hits = self.parse_option(stats, 'SS pfl hits')
        self.ss_pfl_misses = self.parse_option(stats, 'SS pfl misses')

        self.cache_hits = self.parse_option(stats, 'Cache hits')
        self.cache_misses = self.parse_option(stats, 'Cache misses')

        self.cl_msg_received = self.parse_option(
            stats, 'Client messages received')
        self.cl_msg_forwarded = self.parse_option(
            stats, 'Client messages forwarded')
        self.cl_msg_served_from_cache = self.parse_option(
            stats, 'Client messages served from cache')
        self.cl_msg_parsing_errors = self.parse_option(
            stats, 'Client messages parsing errors')
        self.cl_msg_filtered_out = self.parse_option(
            stats, 'Client messages filtered out')
        self.cl_msg_other_errors = self.parse_option(
            stats, 'Client messages other errors')
        self.cl_conn_attempts = self.parse_option(
            stats, 'Client connection attempts')
        self.cl_established_connections = self.parse_option(
            stats, 'Client established connections')
        self.cl_conns_active = self.parse_option(
            stats, 'Client connections active')
        self.cl_rx_bytes = self.parse_option(
            stats, 'Client RX bytes')

        self.srv_msg_received = self.parse_option(
            stats, 'Server messages received')
        self.srv_msg_forwarded = self.parse_option(
            stats, 'Server messages forwarded')
        self.srv_msg_parsing_errors = self.parse_option(
            stats, 'Server messages parsing errors')
        self.srv_msg_filtered_out = self.parse_option(
            stats, 'Server messages filtered out')
        self.srv_msg_other_errors = self.parse_option(
            stats, 'Server messages other errors')
        self.srv_conn_attempts = self.parse_option(
            stats, 'Server connection attempts')
        self.srv_established_connections = self.parse_option(
            stats, 'Server established connections')
        self.srv_conns_active = self.parse_option(
            stats, 'Server connections active')
        self.srv_rx_bytes = self.parse_option(
            stats, 'Server RX bytes')

    @staticmethod
    def parse_option(stats, name):
        s = r'%s\s+: (\d+)' % name
        m = re.search(s.encode('ascii'), stats)
        if m:
            return int(m.group(1))
        return -1

class ServerStats(object):

    def __init__(self, tempesta, sg_name, srv_ip, srv_port):
        self.tempesta = tempesta
        self.path = '%s/%s:%s' % (sg_name, srv_ip, srv_port)

    def get_server_health(self):
        stats, _ = self.tempesta.get_server_stats(self.path)
        name = 'HTTP availability'
        health = Stats.parse_option(stats, name)
        assert health >= 0, \
            ('Cannot find "%s" in server stats: %s\n' % (name, stats))
        return health


#-------------------------------------------------------------------------------
# Config Helpers
#-------------------------------------------------------------------------------

class ServerGroup(object):

    def __init__(self, name='default', sched='ratio', hm=None):
        self.name = name
        self.hm = hm
        self.implicit = (name == 'default')
        self.sched = sched
        self.servers = []
        # Server group options, inserted after servers.
        self.options = ''

    def add_server(self, ip, port, conns=server_conns_default()):
        error.assertTrue(conns <= server_conns_max())
        error.assertTrue(len(self.servers) < servers_in_group())
        conns_str = (' conns_n=%d' % conns if (conns != server_conns_default())
                     else '')
        self.servers.append('server %s:%d%s;' % (ip, port, conns_str))

    def get_config(self):
        sg = ''
        if self.hm:
            self.options += (' health %s;' % self.hm)
        if (self.name == 'default') and self.implicit:
            sg = '\n'.join(['sched %s;' % self.sched] + self.servers
                           + [self.options])
        else:
            sg = '\n'.join(
                ['srv_group %s {' % self.name] +
                ['sched %s;' % self.sched] +
                self.servers + [self.options] + ['}'])
        return sg

class Config(object):
    """ Creates Tempesta config file. """
    def __init__(self, vhost_auto=True):
        self.server_groups = []
        self.defconfig = ''
        self.vhost_auto_mode = vhost_auto

    def find_sg(self, sg_name):
        for sg in self.server_groups:
            if sg.name == sg_name:
                return sg
        return None

    def remove_sg(self, name):
        sg = self.find_sg(name)
        error.assertFalse(sg is None)
        self.server_groups.remove(sg)

    def add_sg(self, new_sg):
        error.assertTrue(self.find_sg(new_sg.name) is None)
        self.server_groups.append(new_sg)

    def vhosts_auto_config(self):
        vhosts = []
        if self.vhost_auto_mode:
            for sg in self.server_groups:
                if len(sg.servers) > 0:
                    vhosts.append('\n'.join(
                        ['vhost %s {' % sg.name] +
                        ['proxy_pass %s;' % sg.name] +
                        ['}']))

        return vhosts

    def get_config(self):
        cfg = '\n'.join([sg.get_config() for sg in self.server_groups] +
                        self.vhosts_auto_config() +
                        [self.defconfig])
        return cfg

    def __handle_tls(self, custom_cert):
        """
        Parse the config string and generate x509 certificates if there are
        appropriate options in the config. The default cert generator creates
        only one certificate for the simplest Tempesta configuration - if you
        need per vhost certificates, multiple cerificates and/or custom
        certificate options, generate the certs on your own.
        """
        if custom_cert:
            return # nothing to do for us, a caller takes care about certs
        cfg = {}
        for l in self.defconfig.splitlines():
            l = l.strip(' \t;')
            if not l or l.startswith('#'):
                continue
            try:
                k, v = l.split(' ', 1)
            except ValueError:
                continue # just ignore lines like '}' or '"'
            assert not k.startswith('tls_certificate') or not cfg.has_key(k), \
                "Two or more certificates configured, please use custom_cert" \
                " option in Tempesta configuration"
            cfg[k] = v
        if not cfg.has_key('listen') or not 'https' in cfg['listen']:
            return
        cert_path, key_path = cfg['tls_certificate'], cfg['tls_certificate_key']
        cgen = CertGenerator(cert_path, key_path, True)
        remote.tempesta.copy_file(cert_path, cgen.serialize_cert())
        remote.tempesta.copy_file(key_path, cgen.serialize_priv_key())

    def set_defconfig(self, config, custom_cert=False):
        self.defconfig = config
        self.__handle_tls(custom_cert)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
