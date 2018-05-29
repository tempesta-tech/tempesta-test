import unittest
import time

from helpers import tempesta, control, stateful, tf_cfg

from . import wrk_client, nginx_server
from . import deproxy_client, deproxy_server, deproxy_manager
from templates import fill_template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

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

    __servers = {}
    __clients = {}
    __tempesta = None
    __deproxy_manager = deproxy_manager.DeproxyManager()

    def __create_client_deproxy(self, client):
        addr = fill_template(client['addr'])
        port = int(fill_template(client['port']))
        clt = deproxy_client.DeproxyClient(addr=addr, port=port)
        return clt

    def __create_client_wrk(self, client):
        addr = client['addr']
        wrk = wrk_client.Wrk(server_addr=addr)
        wrk.set_script(client['id']+"_script", content="")
        return wrk

    def __create_client(self, client):
        cid = client['id']
        if client['type'] == 'deproxy':
            self.__clients[cid] = self.__create_client_deproxy(client)
        elif client['type'] == 'wrk':
            self.__clients[cid] = self.__create_client_wrk(client)

    def __create_srv_nginx(self, server, name):
        if not 'config' in server.keys():
            return None
        srv = nginx_server.Nginx(server['config'], name, server['status_uri'])
        return srv

    def __create_srv_deproxy(self, server):
        port = server['port']
        if port == 'default':
            port = tempesta.upstream_port_start_from()
        else:
            port = int(port)
        srv = None
        rtype = server['response']
        if rtype == 'static':
            content = fill_template(server['response_content'])
            srv = deproxy_server.StaticDeproxyServer(port=port,
                                                     response=content)
        else:
            raise Exception("Invalid response type: %s" % str(rtype))

        self.__deproxy_manager.add_server(srv)
        return srv

    def __create_backend(self, server):
        srv = None
        checks = []
        sid = server['id']
        if server.has_key('check_ports'):
            for check in server['check_ports']:
                ip = fill_template(check['ip'])
                port = fill_template(check['port'])
                checks.append((ip, port))
        
        if server['type'] == 'nginx':
            srv = self.__create_srv_nginx(server, sid)
        elif server['type'] == 'deproxy':
            srv = self.__create_srv_deproxy(server)
        
        srv.port_checks = checks
        self.__servers[sid] = srv

    def __create_servers(self):
        for server in self.backends:
            self.__create_backend(server)

    def get_server(self, sid):
        """ Return client with specified id """
        if not self.__servers.has_key(sid):
            return None
        return self.__servers[sid]

    def get_servers_id(self):
        """ Return list of registered servers id """
        return self.__servers.keys()

    def __create_clients(self):
        for client in self.clients:
            self.__create_client(client)

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
        config = ""
        if self.tempesta.has_key('config'):
            config = self.tempesta['config']
        self.__tempesta = control.Tempesta()
        self.__tempesta.config.set_defconfig(fill_template(config))

    def start_all_servers(self):
        for id in self.__servers:
            srv = self.__servers[id]
            srv.start()
            if not srv.is_running():
                raise Exception("Can not start server %s" % id)

    def start_tempesta(self):
        self.__tempesta.start()
        if not self.__tempesta.is_running():
            raise Exception("Can not start Tempesta")

    def start_all_clients(self):
        for id in self.__clients:
            client = self.__clients[id]
            client.start()
            if not client.is_running():
                raise Exception("Can not start client %s" % id)

    def setUp(self):
        tf_cfg.dbg(3, '\tInit test case...')
        self.__create_servers()
        self.__create_tempesta()
        self.__create_clients()
        self.__deproxy_manager.start()
        # preventing race between manager start and servers start
        time.sleep(0.2)

    def tearDown(self):
        for id in self.__clients:
            client = self.__clients[id]
            client.stop()
        self.__tempesta.stop()
        for id in self.__servers:
            server = self.__servers[id]
            server.stop()
        self.__deproxy_manager.stop()
        try:
            deproxy_manager.finish_all_deproxy()
        except:
            print ('Unknown exception in stopping deproxy')

    def wait_while_busy(self, *items):
        if items is None:
            return

        for item in items:
            if item.is_running():
                item.wait_for_finish()
