"""Functional tests for stream priority."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from hyperframe.frame import SettingsFrame

from http2_general.helpers import H2Base
from test_suite import marks


class TestPriorityBase(H2Base):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            frang_limits {
                http_hdr_len 0;
                http_header_cnt 0;
                http_strict_host_checking false;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            http_max_header_list_size 0;

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }


class TestPriorityParser(TestPriorityBase):
    """
    Tempesta FW ignores priority header in request in case of old
    prioritization scheme.
    """

    def test_invalid_priority_parameters_with_old_prio(self, name, extra_prio):
        self.start_all_services()
        client = self.get_client("deproxy")

        post_request = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("priority", "q i=3 u=9"),
        ]

        client.send_request(post_request, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(name="urgency_greater_then_max", extra_prio="i, u=9"),
            marks.Param(name="urgency_less_then_min", extra_prio="i, u=-1"),
            marks.Param(name="invalid_incremental", extra_prio="i=3"),
            marks.Param(name="invalid_param", extra_prio="q"),
        ]
    )
    def test_invalid_priority_parameters_with_new_prio(self, name, extra_prio):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.update_initial_settings(no_rfc7540_priority=True)
        print(client.state)

        client.send_bytes(client.h2_connection.data_to_send())
        print(client.state)

        client.wait_for_ack_settings()
        print(client.state)

        post_request = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("priority", extra_prio),
        ]

        client.send_request(post_request, "400")
