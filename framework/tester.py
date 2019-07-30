from __future__ import print_function
import unittest
import time

from helpers import control, tf_cfg, dmesg, remote

import framework.wrk_client as wrk_client
import framework.deproxy_client as deproxy_client
import framework.deproxy_manager as deproxy_manager
from framework.templates import fill_template, populate_properties

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

backend_defs = {}
tempesta_defs = {}

def register_backend(type_name, factory):
    global backend_defs
    """ Register backend type """
    tf_cfg.dbg(3, "Registering backend %s" % type_name)
    backend_defs[type_name] = factory

def register_tempesta(type_name, factory):
    """ Register tempesta type """
    global tempesta_defs
    tf_cfg.dbg(3, "Registering tempesta %s" % type_name)
    tempesta_defs[type_name] = factory

def default_tempesta_factory(tempesta):
    return control.Tempesta()

register_tempesta("tempesta", default_tempesta_factory)

class TempestaTest(unittest.TestCase):
    """ Basic tempesta test class.
    Tempesta tests should have:
    1) backends: [...]
    2) clients: [...]
    3) several test functions.
    function name should start with 'test'

    Verbose documentation is placed in README.md
    """

    backends = []

    clients = []

    tempesta = {
        'listen_ip' : 'default',
        'listen_port' : 80,
        'backends' : [],
    }

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.__servers = {}
        self.__clients = {}
        self.__tempesta = None
        self.deproxy_manager = deproxy_manager.DeproxyManager()

    def __create_client_deproxy(self, client, ssl):
        addr = fill_template(client['addr'], client)
        port = int(fill_template(client['port'], client))
        clt = deproxy_client.DeproxyClient(addr=addr, port=port, ssl=ssl)
        if ssl:
            server_hostname = fill_template(client['ssl_hostname'], client)
            clt.set_server_hostname(server_hostname)
        return clt

    def __create_client_wrk(self, client, ssl):
        addr = fill_template(client['addr'], client)
        wrk = wrk_client.Wrk(server_addr=addr, ssl=ssl)
        wrk.set_script(client['id']+"_script", content="")
        return wrk

    def __create_client(self, client):
        populate_properties(client)
        ssl = client.setdefault('ssl', False)
        cid = client['id']
        if client['type'] == 'deproxy':
            self.__clients[cid] = self.__create_client_deproxy(client, ssl)
        elif client['type'] == 'wrk':
            self.__clients[cid] = self.__create_client_wrk(client, ssl)

    def __create_backend(self, server):
        srv = None
        checks = []
        sid = server['id']
        populate_properties(server)
        if server.has_key('check_ports'):
            for check in server['check_ports']:
                ip = fill_template(check['ip'], server)
                port = fill_template(check['port'], server)
                checks.append((ip, port))

        stype = server['type']
        try:
            factory = backend_defs[stype]
        except Exception as e:
            tf_cfg.dbg(1, "Unsupported backend %s" % stype)
            tf_cfg.dbg(1, "Supported backends: %s" % backend_defs)
            raise e
        srv = factory(server, sid, self)
        srv.port_checks = checks
        self.__servers[sid] = srv

    def __create_servers(self):
        for server in self.backends:
            # Copy description to keep it clean between several tests.
            self.__create_backend(server.copy())

    def get_server(self, sid):
        """ Return client with specified id """
        if not self.__servers.has_key(sid):
            return None
        return self.__servers[sid]

    def get_servers(self):
        return self.__servers.values()

    def get_servers_id(self):
        """ Return list of registered servers id """
        return self.__servers.keys()

    def __create_clients(self):
        for client in self.clients:
            # Copy description to keep it clean between several tests.
            self.__create_client(client.copy())

    def get_client(self, cid):
        """ Return client with specified id """
        if not self.__clients.has_key(cid):
            return None
        return self.__clients[cid]

    def get_clients_id(self):
        """ Return list of registered clients id """
        return self.__clients.keys()

    def get_tempesta(self):
        """ Return Tempesta instance """
        return self.__tempesta

    def __create_tempesta(self):
        desc = self.tempesta.copy()
        populate_properties(desc)
        custom_cert = False
        if 'custom_cert' in desc:
            custom_cert = self.tempesta['custom_cert']
        config = ""
        if 'config' in desc:
            config = desc['config']
        if 'type' in desc:
            factory = tempesta_defs[desc['type']]
            self.__tempesta = factory(desc)
        else:
            self.__tempesta = default_tempesta_factory(desc)
        self.__tempesta.config.set_defconfig(fill_template(config, desc),
                                             custom_cert)

    def start_all_servers(self):
        for sid in self.__servers:
            srv = self.__servers[sid]
            srv.start()
            if not srv.is_running():
                raise Exception("Can not start server %s" % sid)

    def start_tempesta(self):
        """ Start Tempesta and wait until the initialization process finish. """
        with dmesg.wait_for_msg('[tempesta fw] modules are started', 1, True):
            self.__tempesta.start()
            if not self.__tempesta.is_running():
                raise Exception("Can not start Tempesta")

    def start_all_clients(self):
        for cid in self.__clients:
            client = self.__clients[cid]
            client.start()
            if not client.is_running():
                raise Exception("Can not start client %s" % cid)

    def setUp(self):
        tf_cfg.dbg(3, '\tInit test case...')
        if not remote.wait_available():
            raise Exception("Tempesta node is unavaliable")
        self.oops = dmesg.DmesgOopsFinder()
        self.__create_servers()
        self.__create_tempesta()
        self.__create_clients()
        self.deproxy_manager.start()
        # preventing race between manager start and servers start
        time.sleep(0.2)

    def tearDown(self):
        tf_cfg.dbg(3, "\tTeardown")
        for cid in self.__clients:
            client = self.__clients[cid]
            client.stop()
        self.__tempesta.stop()
        for sid in self.__servers:
            server = self.__servers[sid]
            server.stop()
        self.deproxy_manager.stop()
        try:
            deproxy_manager.finish_all_deproxy()
        except:
            print('Unknown exception in stopping deproxy')

        self.oops.update()
        if self.oops.warn_count("Oops") > 0:
            raise Exception("Oopses happened during test on Tempesta")
        if self.oops.warn_count("WARNING") > 0:
            raise Exception("Warnings happened during test on Tempesta")
        if self.oops.warn_count("ERROR") > 0:
            raise Exception("Errors happened during test on Tempesta")

    def wait_while_busy(self, *items):
        if items is None:
            return

        for item in items:
            if item.is_running():
                item.wait_for_finish()
