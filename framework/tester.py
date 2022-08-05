from __future__ import print_function
import unittest
import time

from helpers import control, tf_cfg, dmesg, remote

import framework.wrk_client as wrk_client
import framework.deproxy_client as deproxy_client
import framework.deproxy_manager as deproxy_manager
import framework.external_client as external_client

from framework.templates import fill_template, populate_properties

import socket
import struct

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2022 Tempesta Technologies, Inc.'
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

def ip_str_to_number(ip_addr):
    """ Convert ip to number """
    packed = socket.inet_aton(ip_addr)
    return struct.unpack("!L", packed)[0]

def ip_number_to_str(ip_addr):
    """ Convert ip in numeric form to string """
    packed = struct.pack("!L", ip_addr)
    return socket.inet_ntoa(packed)

def create_interface(iface_id, base_iface_name, base_ip):
    """ Create interface alias  """
    base_ip_addr = ip_str_to_number(base_ip)
    iface_ip_addr = base_ip_addr + iface_id
    iface_ip = ip_number_to_str(iface_ip_addr)

    iface = "%s:%i" % (base_iface_name, iface_id)

    command = "LANG=C ip address add %s dev %s label %s" % \
        (iface_ip, base_iface_name, iface)
    try:
        tf_cfg.dbg(3, "Adding ip %s" % iface_ip)
        remote.client.run_cmd(command)
    except:
        tf_cfg.dbg(3, "Interface alias already added")

    return (iface, iface_ip)

def remove_interface(interface_name, iface_ip):
    """ Remove interface """
    template = "LANG=C ip address del %s dev %s"
    try:
        tf_cfg.dbg(3, "Removing ip %s" % iface_ip)
        remote.client.run_cmd(template % (iface_ip, interface_name))
    except:
        tf_cfg.dbg(3, "Interface alias already removed")

def remove_interfaces(base_interface_name, ips):
    """ Remove previously created interfaces """
    for ip in ips:
        remove_interface(base_interface_name, ip)

def create_route(base_iface_name, ip, gateway_ip):
    """ Create route """
    command = "LANG=C ip route add %s via %s dev %s" % \
        (ip, gateway_ip, base_iface_name)
    try:
        tf_cfg.dbg(3, "Adding route for %s" % ip)
        remote.tempesta.run_cmd(command)
    except:
        tf_cfg.dbg(3, "Route already added")

    return

def remove_route(interface_name, ip):
    """ Remove route """
    template = "LANG=C ip route del %s dev %s"
    try:
        tf_cfg.dbg(3, "Removing route for %s" % ip)
        remote.tempesta.run_cmd(template % (ip, interface_name))
    except:
        tf_cfg.dbg(3, "Route already removed")

def remove_routes(base_interface_name, ips):
    """ Remove previously created routes """
    for ip in ips:
        remove_route(base_interface_name, ip)

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

    def __init_subclass__(cls, base=False, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._base = base

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.__servers = {}
        self.__clients = {}
        self.__ips = []
        self.__tempesta = None
        self.deproxy_manager = deproxy_manager.DeproxyManager()

    def __create_client_deproxy(self, client, ssl, bind_addr):
        addr = fill_template(client['addr'], client)
        port = int(fill_template(client['port'], client))
        if client['type'] == 'deproxy_h2':
            clt = deproxy_client.DeproxyClientH2(addr=addr, port=port, ssl=ssl,
                                                 bind_addr=bind_addr, proto='h2')
        else:
            clt = deproxy_client.DeproxyClient(addr=addr, port=port, ssl=ssl,
                                               bind_addr=bind_addr)
        if ssl and 'ssl_hostname' in client:
            # Don't set SNI by default, do this only if it was specified in
            # the client configuration.
            server_hostname = fill_template(client['ssl_hostname'], client)
            clt.set_server_hostname(server_hostname)
        clt.segment_size = int(client.get('segment_size', 0))
        clt.segment_gap = int(client.get('segment_gap', 0))
        clt.keep_original_data = bool(client.get('keep_original_data', None))
        return clt

    def __create_client_wrk(self, client, ssl):
        addr = fill_template(client['addr'], client)
        wrk = wrk_client.Wrk(server_addr=addr, ssl=ssl)
        wrk.set_script(client['id']+"_script", content="")
        return wrk

    def __create_client_external(self, client_descr):
        cmd_args = fill_template(client_descr['cmd_args'], client_descr)
        ext_client = external_client.ExternalTester(binary=client_descr['binary'],
                                                    cmd_args=cmd_args,
                                                    server_addr=None,
                                                    uri=None)
        return ext_client

    def __create_client(self, client):
        populate_properties(client)
        ssl = client.setdefault('ssl', False)
        cid = client['id']
        if client['type'] in ['deproxy', 'deproxy_h2']:
            ip = None
            if client.get('interface', False):
                interface = tf_cfg.cfg.get('Server', 'aliases_interface')
                base_ip = tf_cfg.cfg.get('Server',   'aliases_base_ip')
                client_ip = tf_cfg.cfg.get('Client',   'ip')
                (_, ip) = create_interface(len(self.__ips), interface, base_ip)
                create_route(interface, ip, client_ip)
                self.__ips.append(ip)
            self.__clients[cid] = self.__create_client_deproxy(client, ssl, ip)
            self.__clients[cid].set_rps(client.get('rps', 0))
        elif client['type'] == 'wrk':
            self.__clients[cid] = self.__create_client_wrk(client, ssl)
        elif client['type'] == 'external':
            self.__clients[cid] = self.__create_client_external(client)

    def __create_backend(self, server):
        srv = None
        checks = []
        sid = server['id']
        populate_properties(server)
        if 'check_ports' in server:
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
        if sid not in self.__servers:
            return None
        return self.__servers[sid]

    def get_servers(self):
        return self.__servers.values()

    def get_servers_id(self):
        """ Return list of registered servers id """
        return self.__servers.keys()

    def __create_clients(self):
        if not remote.wait_available():
            raise Exception("Client node is unavaliable")
        for client in self.clients:
            # Copy description to keep it clean between several tests.
            self.__create_client(client.copy())

    def get_client(self, cid):
        """ Return client with specified id """
        if cid not in self.__clients:
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
        # "modules are started" string is only logged in debug builds while 
        # "Tempesta FW is ready" is logged at all levels.
        with dmesg.wait_for_msg('[tempesta fw] Tempesta FW is ready', 1, True):
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
        # `unittest.TestLoader.discover` returns initialized objects, we can't
        # raise `SkipTest` inside of `TempestaTest.__init__` because we are unable
        # to interfere `unittest` code and catch that exception inside of it.
        # Please, make sure to put the following check in your code if you override `setUp`.
        if self._base:
            self.skipTest("This is an abstract class")

        tf_cfg.dbg(3, '\tInit test case...')
        if not remote.wait_available():
            raise Exception("Tempesta node is unavaliable")
        self.oops = dmesg.DmesgFinder()
        self.oops_ignore = []
        self.__create_servers()
        self.__create_tempesta()
        self.__create_clients()

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

        tf_cfg.dbg(3, "Removing interfaces")
        interface = tf_cfg.cfg.get('Server', 'aliases_interface')
        remove_routes(interface, self.__ips)
        remove_interfaces(interface, self.__ips)
        self.__ips = []

        self.oops.update()
        for err in ["Oops", "WARNING", "ERROR"]:
            if err in self.oops_ignore:
                continue
            if self.oops._warn_count(err) > 0:
                self.oops_ignore = []
                raise Exception("%s happened during test on Tempesta" % err)
        # Drop the list of ignored errors to allow set different errors masks
        # for different tests.
        self.oops_ignore = []

    def wait_while_busy(self, *items):
        if items is None:
            return

        for item in items:
            if item.is_running():
                item.wait_for_finish()

    # Should replace all duplicated instances of wait_all_connections
    def wait_all_connections(self, tmt=1):
        for sid in self.__servers:
            srv = self.__servers[sid]
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True
