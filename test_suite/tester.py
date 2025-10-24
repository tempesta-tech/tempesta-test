from __future__ import annotations, print_function

import dataclasses
import datetime
import os
import re
import signal
import subprocess
import typing
import unittest
from unittest.util import strclass

import run_config
from framework import (
    curl_client,
    deproxy_client,
    deproxy_manager,
    external_client,
    wrk_client,
)
from framework.deproxy_auto_parser import DeproxyAutoParser
from framework.deproxy_server import StaticDeproxyServer, deproxy_srv_factory
from framework.docker_server import DockerServer, docker_srv_factory
from framework.nginx_server import Nginx, nginx_srv_factory
from framework.stateful import Stateful
from helpers import clickhouse, control, dmesg, error, remote, tempesta, tf_cfg, util
from helpers.networker import NetWorker
from helpers.tf_cfg import test_logger
from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


backend_defs = {}
tempesta_defs = {"tempesta": control.Tempesta, "tempesta_fi": control.TempestaFI}
save_tcpdump = False
last_test_id = ""
build_path = f"/var/tcpdump/{datetime.date.today()}/{datetime.datetime.now().strftime('%H:%M:%S')}"


def register_backend(type_name, factory):
    global backend_defs
    """ Register backend type """
    test_logger.info(f"Registering backend '{type_name}'")
    backend_defs[type_name] = factory


register_backend("deproxy", deproxy_srv_factory)
register_backend("nginx", nginx_srv_factory)
register_backend("docker", docker_srv_factory)


@dataclasses.dataclass
class TempestaLoggers:
    dmesg: dmesg.DmesgFinder
    _get_tempesta: typing.Callable

    @property
    def clickhouse(self) -> clickhouse.ClickHouseFinder:
        return self._get_tempesta().clickhouse


class WaitUntilAsserts(unittest.TestCase):
    def assertWaitUntilEqual(
        self,
        func: typing.Callable,
        second,
        msg: str = None,
        timeout: int = 5,
        poll_freq: float = 0.1,
    ):
        success = util.wait_until(
            wait_cond=lambda: func() != second, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Not equals even after {timeout} seconds"))

    def assertWaitUntilNotEqual(
        self,
        func: typing.Callable,
        second,
        msg: str = None,
        timeout: int = 5,
        poll_freq: float = 0.1,
    ):
        success = util.wait_until(
            wait_cond=lambda: func() == second, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Still equals even after {timeout} seconds"))

    def assertWaitUntilIsNotNone(
        self, func: typing.Callable, msg: str = None, timeout: int = 5, poll_freq: float = 0.1
    ):
        success = util.wait_until(
            wait_cond=lambda: func() is None, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Is None event after {timeout} seconds"))

    def assertWaitUntilCountEqual(
        self,
        func: typing.Callable,
        count,
        msg: str = None,
        timeout: int = 5,
        poll_freq: float = 0.1,
    ):
        success = util.wait_until(
            wait_cond=lambda: len(func()) != count, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Count is not equals event after {timeout} seconds"))

    def assertWaitUntilTrue(
        self, func: typing.Callable, msg: str = None, timeout: int = 5, poll_freq: float = 0.1
    ):
        success = util.wait_until(
            wait_cond=lambda: func() is False, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Is False event after {timeout} seconds"))

    def assertWaitUntilFalse(
        self, func: typing.Callable, msg: str = None, timeout: int = 5, poll_freq: float = 0.1
    ):
        success = util.wait_until(
            wait_cond=lambda: func() is True, timeout=timeout, poll_freq=poll_freq
        )

        if success:
            return None

        self.fail(self._formatMessage(msg, f"Is True event after {timeout} seconds"))


class TempestaTest(WaitUntilAsserts, unittest.TestCase):
    """Basic tempesta test class.
    Tempesta tests should have:
    1) backends: [...]
    2) clients: [...]
    3) several test functions.
    function name should start with 'test'

    Verbose documentation is placed in README.md
    """

    backends: list[dict] = []

    clients: list[dict] = []

    tempesta = {"type": "tempesta", "config": "", "tfw_config": tempesta.TfwLogger()}

    def __init_subclass__(cls, base=False, check_memleak=False, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._base = base
        cls.__check_memleak = check_memleak

    def __str__(self):
        return f"{strclass(self.__class__)}.{self._testMethodName}"

    def enable_memleak_check(self):
        self.__check_memleak = True

    def disable_deproxy_auto_parser(self) -> None:
        """
        Disable Http parser for each response/request in tests.
        This method disables automatic checks in tests.
        """
        self._deproxy_auto_parser.parsing = False

    def __create_client_deproxy(self, client: dict, ssl: bool, bind_addr: str):
        client_factories = {
            "deproxy_h2": deproxy_client.DeproxyClientH2,
            "deproxy": deproxy_client.DeproxyClient,
        }

        return client_factories[client["type"]](
            # BaseDeproxy
            id_=client.get("id"),
            deproxy_auto_parser=self._deproxy_auto_parser,
            port=int(fill_template(client["port"], client)),
            bind_addr=bind_addr,
            segment_size=client.get("segment_size", 0),
            segment_gap=client.get("segment_gap", 0),
            is_ipv6=client.get("is_ipv6", False),
            # BaseDeproxyClient
            conn_addr=fill_template(client["addr"], client),
            is_ssl=ssl,
            server_hostname=fill_template(client.get("ssl_hostname", None), client),
        )

    def __create_client_wrk(self, client, ssl):
        addr = fill_template(client["addr"], client)
        wrk = wrk_client.Wrk(id_=client["id"], server_addr=addr, ssl=ssl)
        wrk.set_script(client["id"] + "_script", content="")
        return wrk

    def __create_client_external(self, client_descr):
        cmd_args = fill_template(client_descr["cmd_args"], client_descr)
        ext_client = external_client.ExternalTester(
            id_=client_descr["id"],
            binary=client_descr["binary"],
            cmd_args=cmd_args,
            server_addr=None,
            uri=None,
        )
        return ext_client

    def __create_client_curl(self, client, interface):
        # extract arguments that are supported by cURL client
        kwargs = {k: client[k] for k in curl_client.CurlArguments.get_arg_names() if k in client}
        kwargs["addr"] = fill_template(
            client.get("addr", "${tempesta_ip}"), client  # Address is Tempesta IP by default
        )
        kwargs["cmd_args"] = fill_template(client.get("cmd_args", ""), client)
        kwargs.setdefault("curl_iface", interface)
        curl = curl_client.CurlClient(**kwargs)
        return curl

    def __create_client(self, client):
        tf_cfg.populate_properties(client)
        ssl = client.setdefault("ssl", False)
        cid = client["id"]
        ctype = client["type"]
        test_logger.info(f"Creating client service with ID='{cid}' and TYPE='{ctype}'.")
        is_ipv6 = client.get("is_ipv6", False)
        if is_ipv6 and client.get("interface", False):
            raise ValueError("The framework does not support interfaces for IPv6.")
        client_ip = tf_cfg.cfg.get("Client", "ipv6" if is_ipv6 else "ip")
        if ctype in ["curl", "deproxy", "deproxy_h2"]:
            if client.get("interface", False):
                interface = tf_cfg.cfg.get("Server", "aliases_interface")
                base_ip = tf_cfg.cfg.get("Server", "aliases_base_ip")
                networker = NetWorker(node=remote.client)
                (_, bind_addr) = networker.create_interface(len(self.__ips), interface, base_ip)
                networker.create_route(interface, bind_addr, client_ip)
                self.__ips.append(bind_addr)
            else:
                bind_addr = client_ip
        if ctype in ["deproxy", "deproxy_h2"]:
            self.__clients[cid] = self.__create_client_deproxy(client, ssl, bind_addr)
            self.__clients[cid].set_rps(client.get("rps", 0))
            self.deproxy_manager.add_client(self.__clients[cid])
        elif ctype == "wrk":
            self.__clients[cid] = self.__create_client_wrk(client, ssl)
        elif ctype == "curl":
            self.__clients[cid] = self.__create_client_curl(client, bind_addr)
        elif ctype == "external":
            self.__clients[cid] = self.__create_client_external(client)

    def __create_backend(self, server):
        sid = server["id"]
        tf_cfg.populate_properties(server)
        stype = server["type"]
        test_logger.info(f"Creating backend service with ID='{sid}' and TYPE='{stype}'.")
        try:
            factory = backend_defs[stype]
        except ValueError as e:
            test_logger.error(
                f"Unsupported backend {stype}. Supported backends - {backend_defs}",
                exc_info=True,
            )
            raise e
        srv = factory(server, sid, self)

        if "check_ports" in server:
            for check in server["check_ports"]:
                ip = fill_template(check["ip"], server)
                port = int(fill_template(check["port"], server))
                srv.port_checker.add_port_to_checks(ip, port)

        self.__servers[sid] = srv

    def __create_servers(self):
        for server in self.backends:
            # Copy description to keep it clean between several tests.
            self.__create_backend(server.copy())

    def get_server(self, sid) -> StaticDeproxyServer | Nginx | DockerServer | None:
        """Return client with specified id"""
        return self.__servers.get(sid)

    def get_servers(self):
        return self.__servers.values()

    def get_servers_id(self):
        """Return list of registered servers id"""
        return self.__servers.keys()

    def __create_clients(self):
        for client in self.clients:
            # Copy description to keep it clean between several tests.
            self.__create_client(client.copy())

    def get_client(self, cid) -> typing.Union[
        deproxy_client.DeproxyClientH2,
        deproxy_client.DeproxyClient,
        curl_client.CurlClient,
        external_client.ExternalTester,
        wrk_client.Wrk,
        None,
    ]:
        """Return client with specified id"""
        return self.__clients.get(cid)

    def get_clients(self) -> list:
        return list(self.__clients.values())

    def get_all_services(self) -> typing.List[Stateful]:
        return (
            self.get_clients()
            + ([self.__tempesta] if self.__tempesta is not None else [])
            + list(self.get_servers())
            + [self.deproxy_manager]
        )

    def get_clients_id(self):
        """Return list of registered clients id"""
        return self.__clients.keys()

    def get_tempesta(self) -> control.Tempesta:
        """Return Tempesta instance"""
        return self.__tempesta

    def __create_tempesta(self):
        test_logger.info(f"Creating Tempesta service...")

        config = self.tempesta.copy()
        tf_cfg.populate_properties(config)

        self.__tempesta = tempesta_defs.get(config.get("type", "tempesta"))()
        self.__tempesta.config.set_defconfig(
            config=fill_template(config.get("config", ""), config),
            custom_cert=config.get("custom_cert", False),
            tfw_config=config.get("tfw_config", None),
        )

    def start_all_servers(self):
        for sid in self.__servers:
            srv = self.__servers[sid]
            srv.start()
            if not srv.is_running():
                raise Exception("Can not start server %s" % sid)

    def start_tempesta(self):
        """Start Tempesta and wait until the initialization process finish."""
        # "modules are started" string is only logged in debug builds while
        # "Tempesta FW is ready" is logged at all levels.
        with dmesg.wait_for_msg(re.escape("[tempesta fw] Tempesta FW is ready"), strict=False):
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

        test_logger.info(f"setUp '{self.id()}'")
        if not remote.wait_available():
            raise Exception("Tempesta node is unavailable")
        self.__exceptions = dict()
        self.__servers = {}
        self.__clients = {}
        self.__tcpdump: subprocess.Popen = None
        self.__ips = []
        self.__tempesta = None
        self.deproxy_manager = deproxy_manager.DeproxyManager()
        self.__save_memory_consumption()
        self.loggers = TempestaLoggers(dmesg=dmesg.DmesgFinder(), _get_tempesta=self.get_tempesta)
        self.oops_ignore = []
        self.__create_tempesta()
        self._deproxy_auto_parser = DeproxyAutoParser(
            self.deproxy_manager, self.get_tempesta().config
        )
        self.__create_servers()
        self.__create_clients()
        self.__run_tcpdump()
        # Cleanup part
        self.addCleanup(self.cleanup_check_memory_leaks)
        self.addCleanup(self.cleanup_deproxy_auto_parser)
        self.addCleanup(self.cleanup_check_exceptions_in_deproxy_auto_parser)
        self.addCleanup(self.cleanup_check_dmesg)
        self.addCleanup(self.cleanup_stop_tcpdump)
        self.addCleanup(self.cleanup_interfaces)
        self.addCleanup(self.cleanup_deproxy)
        self.addCleanup(self.cleanup_services)
        test_logger.info(f"setUp completed '{self.id()}'")

    def cleanup_services(self):
        test_logger.info("Cleanup: stopping all services...")

        for service in self.get_all_services():
            service.stop()
            service.clear_stats()
            if service.exceptions:
                self.__exceptions.update({str(service): "\n".join(service.exceptions)})

        self.__servers = {}
        self.__clients = {}
        self.__tempesta = None
        test_logger.info("Cleanup: all services are stopped.")

        if self.__exceptions:
            raise error.ServiceStoppingException(self.__exceptions)

    def cleanup_deproxy(self):
        test_logger.info("Cleanup: finish all deproxy sockets...")
        try:
            deproxy_manager.finish_all_deproxy()
        except Exception as e:
            test_logger.critical("Unknown exception in stopping deproxy", exc_info=True)
        self.deproxy_manager = None
        test_logger.info("Cleanup: all deproxy sockets are closed.")

    def cleanup_interfaces(self):
        test_logger.info("Cleanup: Removing interfaces")
        interface = tf_cfg.cfg.get("Server", "aliases_interface")
        networker = NetWorker(node=remote.client)
        networker.remove_routes(interface, self.__ips)
        networker.remove_interfaces(interface, self.__ips)
        self.__ips = []

    def cleanup_stop_tcpdump(self):
        test_logger.info("Cleanup: stopping tcpdump")
        self.__stop_tcpdump()

    def cleanup_check_dmesg(self):
        test_logger.info("Cleanup: checking dmesg")
        self.loggers.dmesg.update()

        test_logger.info(
            "\n----------------------dmesg---------------------\n"
            + self.loggers.dmesg.log.decode(errors="ignore")
            + "-------------------end dmesg--------------------"
        )

        for err in ["Oops", "WARNING", "ERROR", "BUG"]:
            if err in self.oops_ignore:
                continue
            if len(self.loggers.dmesg.log_findall(err)) > 0:
                self.loggers.dmesg.show()
                self.oops_ignore = []
                raise Exception(f"{err} happened during test on Tempesta")
        # Drop the list of ignored errors to allow set different errors masks
        # for different tests.
        self.oops_ignore = []
        self.loggers = None

    def cleanup_deproxy_auto_parser(self):
        test_logger.info("Cleanup: Cleanup the deproxy auto parser.")
        self._deproxy_auto_parser.cleanup()
        self._deproxy_auto_parser = None

    def cleanup_check_exceptions_in_deproxy_auto_parser(self):
        test_logger.info("Cleanup: Check exceptions in the deproxy auto parser.")
        self._deproxy_auto_parser.check_exceptions()

    def cleanup_check_memory_leaks(self):
        if run_config.CHECK_MEMORY_LEAKS or self.__check_memleak:
            test_logger.info("Cleanup: Check memory leaks.")
            used_memory = util.get_used_memory()
            delta_used_memory = used_memory - self.__used_memory
            msg = (
                f"Used memory before test: {self.__used_memory};\n"
                f"Used memory after test: {used_memory};\n"
                f"Delta for memory consumption: {delta_used_memory}."
            )
            test_logger.info("Cleanup: memory consumption:\n{msg}")
            if delta_used_memory >= run_config.MEMORY_LEAK_THRESHOLD:
                raise error.MemoryConsumptionException(
                    msg, delta_used_memory, run_config.MEMORY_LEAK_THRESHOLD
                )

    def wait_while_busy(self, *items, timeout=20):
        if items is None:
            return

        success = True
        for item in items:
            if item.is_running():
                test_logger.debug(f'Client "{item}" wait for finish')
                success = success and item.wait_for_finish(timeout)
                test_logger.debug(f'Waiting for client "{item}" is completed')

        self.assertTrue(success, f"Some of items exceeded the timeout {timeout}s while finishing")

    # Should replace all duplicated instances of wait_all_connections
    def wait_all_connections(self, tmt=5):
        for sid in self.__servers:
            srv = self.__servers[sid]
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def start_all_services(self, client: bool = True) -> None:
        """Start all services."""
        self.start_all_servers()
        self.start_tempesta()

        if "deproxy" or "deproxy_h2" in [
            element["type"] for element in (self.clients + self.backends)
        ]:
            self.deproxy_manager.start()

        self.assertTrue(self.wait_all_connections())
        self.assertTrue(self.__tempesta.wait_while_logger_start())

        if client:
            self.start_all_clients()

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
                    f"ip src {tempesta_ip} or ip dst {tempesta_ip}",
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

    def __save_memory_consumption(self) -> None:
        if run_config.CHECK_MEMORY_LEAKS or self.__check_memleak:
            self.__used_memory = util.get_used_memory()
            test_logger.info(f"Cleanup: used memory {self.__used_memory} KB.")
