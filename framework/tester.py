from __future__ import print_function

import datetime
import os
import signal
import socket
import struct
import subprocess
import unittest

import framework.curl_client as curl_client
import framework.deproxy_client as deproxy_client
import framework.deproxy_manager as deproxy_manager
import framework.external_client as external_client
import framework.wrk_client as wrk_client
import run_config
from framework.templates import fill_template, populate_properties
from helpers import control, dmesg, remote, stateful, sysnet, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

backend_defs = {}
tempesta_defs = {}
save_tcpdump = False
last_test_id = ""
build_path = f"/var/tcpdump/{datetime.date.today()}/{datetime.datetime.now().strftime('%H:%M:%S')}"


def dns_entry_decorator(ip_address, dns_name):
    
    def add_dns_entry(ip_address, dns_name):
        try:
            with open('/etc/hosts', 'a') as hosts_file:
                entry = f"{ip_address} {dns_name}\n"
                hosts_file.write(entry)
            tf_cfg.dbg(3, f"DNS Record added: {entry}")
        except IOError as e:
            tf_cfg.dbg(3, f"Error during add DNS record: {str(e)}")

    def remove_dns_entry(ip_address, dns_name):
        try:
            with open('/etc/hosts', 'r') as hosts_file:
                lines = hosts_file.readlines()
            filtered_lines = [line for line in lines if f"{ip_address} {dns_name}" not in line]
            with open('/etc/hosts', 'w') as hosts_file:
                hosts_file.writelines(filtered_lines)
            tf_cfg.dbg(3, f"DNS record removed: {ip_address} {dns_name}")
        except IOError as e:
            tf_cfg.dbg(3, f"Error during remove DNS record: {str(e)}")
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            add_dns_entry(ip_address, dns_name)
            try:
                result = func(*args, **kwargs)
            finally:
                remove_dns_entry(ip_address, dns_name)
                return result
        return wrapper
    return decorator


def register_backend(type_name, factory):
    global backend_defs
    """ Register backend type """
    tf_cfg.dbg(3, "Registering backend %s" % type_name)
    backend_defs[type_name] = factory


def register_tempesta(type_name, factory):
    """Register tempesta type"""
    global tempesta_defs
    tf_cfg.dbg(3, "Registering tempesta %s" % type_name)
    tempesta_defs[type_name] = factory


def default_tempesta_factory(tempesta):
    return control.Tempesta()


register_tempesta("tempesta", default_tempesta_factory)


class TempestaTest(unittest.TestCase):
    """Basic tempesta test class.
    Tempesta tests should have:
    1) backends: [...]
    2) clients: [...]
    3) several test functions.
    function name should start with 'test'

    no_reload - Tempesta and backends run once for test class.

    Verbose documentation is placed in README.md
    """

    backends = []

    clients = []

    tempesta = {
        "listen_ip": "default",
        "listen_port": 80,
        "backends": [],
    }

    def __init_subclass__(cls, base=False, no_reload=False, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._base = base
        cls._no_reload = no_reload
        cls.deproxy_manager = deproxy_manager.DeproxyManager()

        if cls._no_reload or run_config.NO_RELOAD:
            cls.__servers = {}
            cls.__tempesta = None

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.__clients = {}
        self.__tcpdump: subprocess.Popen = None
        self.__ips = []

        if not self._no_reload or not run_config.NO_RELOAD:
            self.__servers = {}
            self.__tempesta = None

    def __create_client_deproxy(self, client, ssl, bind_addr):
        addr = fill_template(client["addr"], client)
        port = int(fill_template(client["port"], client))
        socket_family = client.get("socket_family", "ipv4")
        if client["type"] == "deproxy_h2":
            clt = deproxy_client.DeproxyClientH2(
                addr=addr,
                port=port,
                ssl=ssl,
                bind_addr=bind_addr,
                proto="h2",
                socket_family=socket_family,
            )
        else:
            clt = deproxy_client.DeproxyClient(
                addr=addr, port=port, ssl=ssl, bind_addr=bind_addr, socket_family=socket_family
            )
        if ssl and "ssl_hostname" in client:
            # Don't set SNI by default, do this only if it was specified in
            # the client configuration.
            server_hostname = fill_template(client["ssl_hostname"], client)
            clt.set_server_hostname(server_hostname)
        clt.segment_size = int(client.get("segment_size", 0))
        clt.segment_gap = int(client.get("segment_gap", 0))
        clt.keep_original_data = bool(client.get("keep_original_data", None))
        return clt

    def __create_client_wrk(self, client, ssl):
        addr = fill_template(client["addr"], client)
        wrk = wrk_client.Wrk(server_addr=addr, ssl=ssl)
        wrk.set_script(client["id"] + "_script", content="")
        return wrk

    def __create_client_external(self, client_descr):
        cmd_args = fill_template(client_descr["cmd_args"], client_descr)
        ext_client = external_client.ExternalTester(
            binary=client_descr["binary"], cmd_args=cmd_args, server_addr=None, uri=None
        )
        return ext_client

    def __create_client_curl(self, client):
        # extract arguments that are supported by cURL client
        kwargs = {k: client[k] for k in curl_client.CurlArguments.get_kwargs() if k in client}
        kwargs["addr"] = fill_template(
            client.get("addr", "${tempesta_ip}"), client  # Address is Tempesta IP by default
        )
        kwargs["cmd_args"] = fill_template(client.get("cmd_args", ""), client)
        curl = curl_client.CurlClient(**kwargs)
        return curl

    def __create_client(self, client):
        populate_properties(client)
        ssl = client.setdefault("ssl", False)
        cid = client["id"]
        if client["type"] in ["deproxy", "deproxy_h2"]:
            ip = None
            if client.get("interface", False):
                interface = tf_cfg.cfg.get("Server", "aliases_interface")
                base_ip = tf_cfg.cfg.get("Server", "aliases_base_ip")
                client_ip = tf_cfg.cfg.get("Client", "ip")
                (_, ip) = sysnet.create_interface(len(self.__ips), interface, base_ip)
                sysnet.create_route(interface, ip, client_ip)
                self.__ips.append(ip)
            self.__clients[cid] = self.__create_client_deproxy(client, ssl, ip)
            self.__clients[cid].set_rps(client.get("rps", 0))
        elif client["type"] == "wrk":
            self.__clients[cid] = self.__create_client_wrk(client, ssl)
        elif client["type"] == "curl":
            self.__clients[cid] = self.__create_client_curl(client)
        elif client["type"] == "external":
            self.__clients[cid] = self.__create_client_external(client)

    @staticmethod
    def __create_backend(tester, server):
        srv = None
        checks = []
        sid = server["id"]
        populate_properties(server)
        if "check_ports" in server:
            for check in server["check_ports"]:
                ip = fill_template(check["ip"], server)
                port = fill_template(check["port"], server)
                checks.append((ip, port))

        stype = server["type"]
        try:
            factory = backend_defs[stype]
        except Exception as e:
            tf_cfg.dbg(1, "Unsupported backend %s" % stype)
            tf_cfg.dbg(1, "Supported backends: %s" % backend_defs)
            raise e
        srv = factory(server, sid, tester)
        srv.port_checks = checks
        tester.__servers[sid] = srv

    @staticmethod
    def __create_servers(tester):
        for server in tester.backends:
            # Copy description to keep it clean between several tests.
            tester.__create_backend(tester, server.copy())

    def get_server(self, sid):
        """Return client with specified id"""
        if sid not in self.__servers:
            return None
        return self.__servers[sid]

    def get_servers(self):
        return self.__servers.values()

    def get_servers_id(self):
        """Return list of registered servers id"""
        return self.__servers.keys()

    def __create_clients(self):
        if not remote.wait_available():
            raise Exception("Client node is unavaliable")
        for client in self.clients:
            # Copy description to keep it clean between several tests.
            self.__create_client(client.copy())

    def get_client(self, cid):
        """Return client with specified id"""
        if cid not in self.__clients:
            return None
        return self.__clients[cid]

    def get_clients(self) -> list:
        return list(self.__clients.values())

    def get_clients_id(self):
        """Return list of registered clients id"""
        return self.__clients.keys()

    def get_tempesta(self):
        """Return Tempesta instance"""
        return self.__tempesta

    @staticmethod
    def __create_tempesta(tester):
        desc = tester.tempesta.copy()
        populate_properties(desc)
        custom_cert = False
        if "custom_cert" in desc:
            custom_cert = tester.tempesta["custom_cert"]
        config = ""
        if "config" in desc:
            config = desc["config"]
        if "type" in desc:
            factory = tempesta_defs[desc["type"]]
            tester.__tempesta = factory(desc)
        else:
            tester.__tempesta = default_tempesta_factory(desc)
        tester.__tempesta.config.set_defconfig(fill_template(config, desc), custom_cert)

    def start_all_servers(self):
        self.__start_all_servers(self)

    @staticmethod
    def __start_all_servers(tester):
        for sid in tester.__servers:
            srv = tester.__servers[sid]
            srv.start()
            if not srv.is_running():
                raise Exception("Can not start server %s" % sid)

    def start_tempesta(self):
        self.__start_tempesta(self)

    @staticmethod
    def __start_tempesta(tester):
        """Start Tempesta and wait until the initialization process finish."""
        if tester.__tempesta.state == stateful.STATE_STARTED:
            return None
        # "modules are started" string is only logged in debug builds while
        # "Tempesta FW is ready" is logged at all levels.
        with dmesg.wait_for_msg("[tempesta fw] Tempesta FW is ready", 1, True):
            tester.__tempesta.start()
            if not tester.__tempesta.is_running():
                raise Exception("Can not start Tempesta")

    def start_all_clients(self):
        for cid in self.__clients:
            client = self.__clients[cid]
            client.start()
            if not client.is_running():
                raise Exception("Can not start client %s" % cid)

    @classmethod
    def setUpClass(cls) -> None:
        tf_cfg.dbg(3, "\tsetUpClass - start.")
        if not remote.wait_available():
            raise Exception("Tempesta node is unavaliable")

        if run_config.NO_RELOAD and cls._no_reload:
            cls.__create_servers(cls)
            cls.__create_tempesta(cls)
            cls.__start_all_servers(cls)
            cls.__start_tempesta(cls)
            cls.deproxy_manager.start()
            assert cls.__wait_all_connections(cls), "Tempesta did not connect to servers."

        tf_cfg.dbg(3, "\tsetUpClass - complete.")

    def setUp(self):
        # `unittest.TestLoader.discover` returns initialized objects, we can't
        # raise `SkipTest` inside of `TempestaTest.__init__` because we are unable
        # to interfere `unittest` code and catch that exception inside of it.
        # Please, make sure to put the following check in your code if you override `setUp`.
        tf_cfg.dbg(3, "\tsetUp - start.")
        if self._base:
            self.skipTest("This is an abstract class")

        self.oops = dmesg.DmesgFinder()
        self.oops_ignore = []
        self.__create_clients()

        if not self._no_reload or not run_config.NO_RELOAD:
            self.__create_servers(self)
            self.__create_tempesta(self)

        self.__run_tcpdump()

        tf_cfg.dbg(3, "\tsetUp - complete.")

    def tearDown(self):
        tf_cfg.dbg(3, "\ttearDown - start.")
        if not run_config.NO_RELOAD or not self._no_reload:
            self.__stop_tempesta_servers_deproxy_manager(self)
        else:
            for sid in self.__servers:
                server = self.__servers[sid]
                server.clear_stats()

        for cid in self.__clients:
            client = self.__clients[cid]
            client.stop()

        tf_cfg.dbg(3, "Removing interfaces")
        interface = tf_cfg.cfg.get("Server", "aliases_interface")
        sysnet.remove_routes(interface, self.__ips)
        sysnet.remove_interfaces(interface, self.__ips)
        self.__ips = []

        self.oops.update()

        tf_cfg.dbg(
            4,
            (
                "----------------------dmesg---------------------\n"
                + self.oops.log.decode()
                + "-------------------end dmesg--------------------"
            ),
        )

        for err in ["Oops", "WARNING", "ERROR", "BUG"]:
            if err in self.oops_ignore:
                continue
            if self.oops._warn_count(err) > 0:
                print(self.oops.log.decode())
                self.oops_ignore = []
                raise Exception("%s happened during test on Tempesta" % err)
        # Drop the list of ignored errors to allow set different errors masks
        # for different tests.
        self.oops_ignore = []
        self.__stop_tcpdump()

        tf_cfg.dbg(3, "\ttearDown - complete.")

    @classmethod
    def tearDownClass(cls) -> None:
        tf_cfg.dbg(3, "\ttearDownClass - start.")

        if run_config.NO_RELOAD and cls._no_reload:
            cls.__stop_tempesta_servers_deproxy_manager(cls)

        tf_cfg.dbg(3, "\ttearDownClass - complete.")

    @staticmethod
    def __stop_tempesta_servers_deproxy_manager(tester):
        tester.__tempesta.stop()
        for sid in tester.__servers:
            server = tester.__servers[sid]
            server.stop()
        tester.deproxy_manager.stop()
        deproxy_manager.finish_all_deproxy()

    def wait_while_busy(self, *items):
        if items is None:
            return

        for item in items:
            if item.is_running():
                tf_cfg.dbg(4, f'\tClient "{item}" wait for finish ')
                item.wait_for_finish()
                tf_cfg.dbg(4, f'\tWaiting for client "{item}" is completed')

    # Should replace all duplicated instances of wait_all_connections
    def wait_all_connections(self, tmt=1):
        return self.__wait_all_connections(self, tmt)

    @staticmethod
    def __wait_all_connections(tester, tmt=1):
        for sid in tester.__servers:
            srv = tester.__servers[sid]
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def start_all_services(self, client: bool = True) -> None:
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()
        if client:
            self.start_all_clients()

        if "deproxy" or "deproxy_h2" in [
            element["type"] for element in (self.clients + self.backends)
        ]:
            self.deproxy_manager.start()

        self.assertTrue(self.wait_all_connections())

    def __run_tcpdump(self) -> None:
        """
        Run `tcpdump` before the test if `-s` (--save-tcpdump) option is used.
        Save result in a <name>.pcap file, where <name> is name of test.
        """
        if save_tcpdump and self.__tcpdump is None:
            tempesta_ip = tf_cfg.cfg.get("Tempesta", "ip")
            test_name = self.__update_tcpdump_filename()

            if not os.path.isdir(build_path):
                os.makedirs(build_path)

            self.__tcpdump = subprocess.Popen(
                [
                    "tcpdump",
                    "-U",
                    "-i",
                    "any",
                    f"ip src {tempesta_ip} and ip dst {tempesta_ip}",
                    "-w",
                    f"{build_path}/{test_name}.pcap",
                ],
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    def __stop_tcpdump(self) -> None:
        """
        Stop tcpdump.
        `wait()` always causes `TimeoutExpired` error because `tcpdump` cannot terminate on
        its own. But it requires a timeout to flush data from buffer.
        """
        if save_tcpdump:
            try:
                self.__tcpdump.send_signal(signal.SIGUSR2)
                self.__tcpdump.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.__tcpdump.kill()
                self.__tcpdump.wait()

            self.__tcpdump = None

    def __update_tcpdump_filename(self) -> str:
        """Update tcpdump file name for -R option."""
        global last_test_id
        test_id = self.id()
        if test_id in last_test_id:
            test_id_elements = last_test_id.split(" ")
            if len(test_id_elements) > 1:
                new_test_id = f"{test_id_elements[0]} {int(test_id_elements[1]) + 1}"
            else:
                new_test_id = test_id + " 2"
            last_test_id = new_test_id
            return new_test_id
        else:
            last_test_id = test_id
            return test_id
