__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.helpers import tf_cfg
from framework.test_suite import tester

NGINX_LARGE_PAGE_CONFIG_EMPTY_SERVER = """
pid ${pid};
worker_processes  auto;
#error_log /dev/stdout info;
error_log /dev/null emerg;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout 65;
    keepalive_requests 100;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # Disable access log altogether.
    access_log off;

    %s
}
"""


TEMPESTA_WORKDIR = tf_cfg.cfg.get("Tempesta", "workdir")
SERVER_IP = tf_cfg.cfg.get("Server", "ip")


class TestModifyServerGroup(tester.TempestaTest):
    """Tempesta FW tests for deadtime during reload."""

    max_deadtime = 1
    servers_n = 64
    requests_n = 1000

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_LARGE_PAGE_CONFIG_EMPTY_SERVER,
        }
    ]

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
        {
            "id": "sequential",
            "type": "curl",
            "uri": f"/[1-{requests_n}]",
            "cmd_args": f" --max-time 5",
            "disable_output": False,
        },
    ]

    tempesta_config_template = f"""
        listen 80 proto=http;
        listen 443 proto=https;
    
        tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
        tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
        tls_match_any_server_name;
    
        frang_limits {{ http_strict_host_checking false; }}
        max_concurrent_streams 10000;
        """

    def _generate_server_listener_list(self) -> list[str]:
        base_port = 16384
        server_listeners = []
        for _ in range(self.servers_n):
            server_listeners.append(f"{SERVER_IP}:{base_port}")
            base_port += 1
        return server_listeners

    def _generate_tempesta_config_with_multiple_srv_group(
        self, server_listeners: list[str]
    ) -> None:
        tfw = self.get_tempesta()
        servers_config = ""
        for server in server_listeners:
            servers_config += f"\tserver {server};\r\n"
        servers_config = f"srv_group default {{\r\n{servers_config}}}\r\n"

        tfw.config.defconfig = self.tempesta_config_template + servers_config

    def _add_nginx_backends(self, server_listeners: list[str]) -> None:
        nginx = self.get_server("nginx")
        servers_config = ""
        for server in server_listeners:
            servers_config += f"\tlisten  {server};\r\n"
        nginx.config.config = (
            nginx.config.config
            % f"""
            server {{
                {servers_config}
                listen 8000;
                location / {{
                    return 200;
                }}
                location /nginx_status {{ stub_status on; }}
            }}
        """
        )

    def _check_requests_delay(self, client) -> None:
        for stat in client.stats:
            self.assertGreater(
                self.max_deadtime,
                stat.get("time_total"),
                f"Tempesta FW deadtime is greater than {self.max_deadtime}.",
            )

    def test_simple_reload(self):
        """A simple reboot while sending requests by the client."""
        server_listeners = self._generate_server_listener_list()
        self._generate_tempesta_config_with_multiple_srv_group(server_listeners)
        self._add_nginx_backends(server_listeners)

        self.start_all_services(client=False)

        client = self.get_client("sequential")
        tfw = self.get_tempesta()
        server = self.get_server("nginx")

        client.start()
        server.wait_for_requests(n=self.requests_n // 3)
        tfw.reload()
        self.assertTrue(client.wait_for_finish())
        client.stop()

        self.assertGreater(
            client.statuses.get(200, 0), 0, "Tempesta FW doesn't forward requests to server."
        )
        self._check_requests_delay(client)

    def test_reload_with_adding_server(self):
        """A reboot with adding server to srv_group while sending requests by the client."""
        server_listeners = self._generate_server_listener_list()
        first_part = server_listeners[: (len(server_listeners) // 2)]
        self._generate_tempesta_config_with_multiple_srv_group(first_part)
        self._add_nginx_backends(server_listeners)

        self.start_all_services(client=False)

        client = self.get_client("sequential")
        tfw = self.get_tempesta()
        server = self.get_server("nginx")

        client.start()
        server.wait_for_requests(n=self.requests_n // 3)
        self._generate_tempesta_config_with_multiple_srv_group(server_listeners)
        tfw.reload()
        self.assertTrue(client.wait_for_finish())
        client.stop()

        self.assertGreater(
            client.statuses.get(200, 0), 0, "Tempesta FW doesn't forward requests to server."
        )
        self._check_requests_delay(client)

    def test_reload_with_removing_server(self):
        """A reboot with removing server from srv_group while sending requests by the client."""
        server_listeners = self._generate_server_listener_list()
        first_part = server_listeners[: (len(server_listeners) // 2)]
        self._generate_tempesta_config_with_multiple_srv_group(server_listeners)
        self._add_nginx_backends(server_listeners)

        self.start_all_services(client=False)

        client = self.get_client("sequential")
        tfw = self.get_tempesta()
        server = self.get_server("nginx")

        client.start()
        server.wait_for_requests(n=self.requests_n // 3)
        self._generate_tempesta_config_with_multiple_srv_group(first_part)
        tfw.reload()
        self.assertTrue(client.wait_for_finish())
        client.stop()

        self.assertGreater(
            client.statuses.get(200, 0), 0, "Tempesta FW doesn't forward requests to server."
        )
        self._check_requests_delay(client)
