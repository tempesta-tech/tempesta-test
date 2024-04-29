__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


from h2.settings import SettingCodes
from hyperframe.frame import HeadersFrame, PingFrame, PriorityFrame, SettingsFrame

from framework.parameterize import param, parameterize
from helpers import dmesg
from http2_general.helpers import H2Base


# class TestH2ControlFramesFlood(tester.TempestaTest):
class TestH2ControlFramesFlood(H2Base):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",  # "deproxy" for HTTP/1
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        keepalive_timeout 1000;
        listen 443 proto=h2;

        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }
        """
    }

    @parameterize.expand(
        [
            param(
                name="ping",
            ),
            param(
                name="settings",
            ),
        ]
    )
    def test(self, name):
        self.oops_ignore = ["ERROR"]
        self.start_all_services()
        client = self.get_client("deproxy")
        self.initiate_h2_connection(client)
        client.disable_readable()

        if name == "ping":
            pf = PingFrame(
                opaque_data=b"\x00\x01\x02\x03\x04\x05\x06\x07",
            ).serialize()

            for _ in range(1000_0000):
                client.send_bytes(pf)
        elif name == "settings":
            new_settings = dict()
            new_settings[SettingCodes.MAX_CONCURRENT_STREAMS] = 100
            sf = SettingsFrame(settings=new_settings).serialize()

            for _ in range(1_0000_0000):
                client.send_bytes(sf)

        self.oops.find(
            "ERROR: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )

    def test_reset_stream(self):
        self.oops_ignore = ["ERROR"]
        self.start_all_services()
        client = self.get_client("deproxy")
        self.initiate_h2_connection(client)
        client.disable_readable()

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "tempesta-tech.com"),
            (":scheme", "https"),
        ]

        for i in range(1, 100_0000, 2):
            hf = HeadersFrame(
                stream_id=i,
                data=client.h2_connection.encoder.encode(headers),
                flags=["END_HEADERS"],
            ).serialize()
            pf = PriorityFrame(stream_id=i, depends_on=i).serialize()

            client.send_bytes(hf + pf)

        self.assertTrue(client.wait_for_connection_close(60))
        self.oops.find(
            "ERROR: Too many control frames in send queue, closing connection",
            cond=dmesg.amount_positive,
        )
