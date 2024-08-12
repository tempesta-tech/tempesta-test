__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


from threading import Thread

from framework import deproxy_client, tester
from helpers.tcpreplay import DataFrame, HeadersFrame, HttpReader, SettingsFrame

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    client_max_body_size 10000M;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8443;

        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestReplay(tester.TempestaTest):

    h2_https_port = "443"
    http_port = "80"
    server_port = "8000"

    clients = []

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8443",
            "status_uri": "http://${server_ip}:8443/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:443 proto=h2,https;
            listen ${tempesta_ip}:80 proto=http;

            access_log on;
            client_tbl_size 134217728;

            block_action attack reply;
            block_action error reply;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            srv_group main {
                server ${server_ip}:8443;
            }

            vhost main {
                proxy_pass main;
            }

            http_chain {
                -> main;
            }
        """
    }

    def setUp(self):
        self.http_reader = HttpReader(
            file_names=[
                "/mnt/other/tempesta-test/tcpdump/"
                "selftests.test_deproxy.DeproxyTestH2.test_make_request.pcap"
            ],
            output_suffix="-test",
        )
        self.http_reader.prepare_http_messages()
        client_n = 0
        for _ in self.http_reader.http2_requests.keys():
            self.clients.append(
                {
                    "id": f"h2-{client_n}",
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": str(self.h2_https_port),
                    "ssl": True,
                    "ssl_hostname": "main",
                }
            )
            client_n += 1

        client_n = 0
        for _ in self.http_reader.https_requests.keys():
            self.clients.append(
                {
                    "id": f"https-{client_n}",
                    "type": "deproxy",
                    "addr": "${tempesta_ip}",
                    "port": str(self.h2_https_port),
                    "ssl": True,
                    "ssl_hostname": "main",
                }
            )
            client_n += 1

        client_n = 0
        for _ in self.http_reader.http_requests.keys():
            self.clients.append(
                {
                    "id": f"http-{client_n}",
                    "type": "deproxy",
                    "addr": "${tempesta_ip}",
                    "port": str(self.http_port),
                    "ssl": False,
                }
            )
            client_n += 1

        super().setUp()

    def send_http_requests(self, http_clients: list) -> None:
        for client, request_list in zip(http_clients, self.http_reader.http_requests.values()):
            for request in request_list:
                client.make_request(client.create_request(authority=None, **request.__dict__))

        for client in http_clients:
            self.assertTrue(client.wait_for_response())

    def send_https_requests(self, https_clients: list) -> None:
        for client, request_list in zip(https_clients, self.http_reader.https_requests.values()):
            for request in request_list:
                client.make_request(client.create_request(authority=None, **request.__dict__))

        for client in https_clients:
            self.assertTrue(client.wait_for_response())

    def send_h2_requests(self, h2_clients: list) -> None:
        for client, frames in zip(h2_clients, self.http_reader.http2_requests.values()):
            client: deproxy_client.DeproxyClientH2
            client.send_bytes(client.h2_connection.data_to_send())
            client.wait_for_ack_settings()

            for frame in frames:
                frame_type = type(frame)
                if frame_type is SettingsFrame:
                    frame: SettingsFrame
                    client.send_settings_frame(
                        **{k: v for k, v in frame.__dict__.items() if v is not None}
                    )
                elif frame_type is HeadersFrame:
                    frame: HeadersFrame
                    end_stream = True if frame.flags in ["0x05"] else False
                    client.stream_id = frame.stream_id
                    client.make_request(frame.headers, end_stream)
                elif frame_type is DataFrame:
                    frame: DataFrame
                    client.stream_id = frame.stream_id
                    end_stream = True if frame.flags in ["0x01", "0x05"] else False
                    client.make_request(frame.body, end_stream)

        for client in h2_clients:
            self.assertTrue(client.wait_for_response())

    def test_replay(self) -> None:
        self.start_all_services(client=True)

        h2_clients = [client for client in self.get_clients() if client.proto == "h2"]
        https_clients = [
            client for client in self.get_clients() if client.proto == "http/1.1" and client.ssl
        ]
        http_clients = [
            client for client in self.get_clients() if client.proto == "http/1.1" and not client.ssl
        ]

        t_h2 = Thread(target=self.send_h2_requests, args=(h2_clients,))
        t_https = Thread(target=self.send_https_requests, args=(https_clients,))
        t_http = Thread(target=self.send_http_requests, args=(http_clients,))

        for t in [t_h2, t_https, t_http]:
            t.start()

        for t in [t_h2, t_https, t_http]:
            t.join()
