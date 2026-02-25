__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy.deproxy_client import BaseDeproxyClient, DeproxyClientH2
from framework.deproxy.deproxy_message import HttpMessage
from framework.helpers import analyzer, asserts, custom_error_page, remote, tf_cfg
from framework.test_suite import tester


def generate_custom_error_page(data):
    workdir = tf_cfg.cfg.get("Tempesta", "workdir")
    cpage_gen = custom_error_page.CustomErrorPageGenerator(data=data, f_path=f"{workdir}/4xx.html")
    path = cpage_gen.get_file_path()
    remote.tempesta.copy_file(path, data)
    return path


class H2Base(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost good {
                frang_limits {http_strict_host_checking false;}
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            http_max_header_list_size 134217728; #128 KB
            
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    post_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    get_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    async def initiate_h2_connection(self, client: DeproxyClientH2):
        # add preamble + settings frame with default variable into data_to_send
        client.update_initial_settings()
        # send preamble + settings frame to Tempesta
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        self.assertTrue(
            await client.wait_for_ack_settings(),
            "Tempesta foes not returns SETTINGS frame with ACK flag.",
        )


class BlockActionH2Base(H2Base, asserts.Sniffer):
    tempesta_tmpl = """
        listen 443 proto=h2;
        srv_group default {
            server ${server_ip}:8000;
        }
        frang_limits {http_strict_host_checking false;}
        vhost good {
            proxy_pass default;
        }
        vhost frang {
            frang_limits {
                http_methods GET;
                http_resp_code_block 200 1 10;
            }
            proxy_pass default;
        }
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        block_action attack %s;
        block_action error %s;
        %s

        http_chain {
            host == "bad.com"   -> block;
            host == "good.com"  -> good;
            host == "frang.com" -> frang;
        }
    """

    @staticmethod
    async def setup_sniffer() -> analyzer.Sniffer:
        sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5, ports=(443,))
        await sniffer.start()
        return sniffer

    def check_fin_no_rst_in_sniffer(
        self, sniffer: analyzer.Sniffer, clients: list[BaseDeproxyClient]
    ) -> None:
        sniffer.stop()
        self.assert_fin_socks(sniffer.packets, clients)
        self.assert_unreset_socks(sniffer.packets, clients)

    def check_rst_no_fin_in_sniffer(
        self, sniffer: analyzer.Sniffer, clients: list[BaseDeproxyClient]
    ) -> None:
        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets, clients)
        self.assert_reset_socks(sniffer.packets, clients)

    def check_fin_and_rst_in_sniffer(
        self, sniffer: analyzer.Sniffer, clients: list[BaseDeproxyClient]
    ) -> None:
        sniffer.stop()
        self.assert_reset_socks(sniffer.packets, clients)
        self.assert_fin_socks(sniffer.packets, clients)

    def check_no_fin_no_rst_in_sniffer(
        self, sniffer: analyzer.Sniffer, clients: list[BaseDeproxyClient]
    ) -> None:
        sniffer.stop()
        self.assert_not_fin_socks(sniffer.packets, clients)
        self.assert_unreset_socks(sniffer.packets, clients)

    async def start_services_and_initiate_conn(self, client):
        await self.start_all_services()

        client.update_initial_settings(initial_window_size=self.INITIAL_WINDOW_SIZE)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(
            await client.wait_for_ack_settings(),
            "Tempesta does not returns SETTINGS frame with ACK flag.",
        )
