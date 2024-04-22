"""Functional tests for h2 streams."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import AllowedStreamIDs, ConnectionInputs
from h2.errors import ErrorCodes
from h2.stream import StreamInputs
from hyperframe.frame import (
    DataFrame,
    Frame,
    HeadersFrame,
    PriorityFrame,
    RstStreamFrame,
    WindowUpdateFrame,
)

from framework import deproxy_client, tester
from helpers import tf_cfg
from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base


class TestH2Stream(H2Base):
    def test_max_concurrent_stream(self):
        """
        An endpoint that receives a HEADERS frame that causes its advertised concurrent
        stream limit to be exceeded MUST treat this as a stream error
        of type PROTOCOL_ERROR or REFUSED_STREAM.
        RFC 9113 5.1.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        max_streams = 100

        for _ in range(max_streams):
            client.make_request(request=self.post_request, end_stream=False)
            client.stream_id += 2

        client.h2_connection.remote_settings.max_concurrent_streams = max_streams + 1
        client.h2_connection.remote_settings.acknowledge()

        client.make_request(request=self.post_request, end_stream=True)
        self.assertTrue(client.wait_for_reset_stream(stream_id=client.stream_id - 2))

        self.assertIn(ErrorCodes.REFUSED_STREAM, client.error_codes)

    def test_reuse_stream_id(self):
        """
        Stream identifiers cannot be reused.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.initiate_h2_connection(client)

        # send headers frame with stream_id = 1
        client.send_request(self.post_request, "200")
        # send headers frame with stream_id = 1 again.
        client.send_bytes(
            data=b"\x00\x00\n\x01\x05\x00\x00\x00\x01A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_headers_frame_with_zero_stream_id(self):
        """
        The identifier of a newly established stream MUST be numerically greater
        than all streams that the initiating endpoint has opened or reserved.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        # add preamble + settings frame with default variable into data_to_send
        self.initiate_h2_connection(client)
        # send headers frame with stream_id = 0.
        client.send_bytes(
            b"\x00\x00\n\x01\x05\x00\x00\x00\x00A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_request_with_even_numbered_stream_id(self):
        """
        Streams initiated by a client MUST use odd-numbered stream identifiers.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.initiate_h2_connection(client)
        # send headers frame with stream_id = 2.
        client.send_bytes(
            b"\x00\x00\n\x01\x05\x00\x00\x00\x02A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_request_with_large_stream_id(self):
        """
        stream id >= 0x7fffffff (2**31-1).

        A reserved 1-bit field. The semantics of this bit are undefined,
        and the bit MUST remain unset (0x00) when sending and MUST be ignored when receiving.
        RFC 9113 4.2
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.initiate_h2_connection(client)

        # Create stream that H2Connection object does not raise error.
        # We are creating stream with id = 2 ** 31 - 1 because Tempesta must return response
        # in stream with id = 2 ** 31 - 1, but request will be made in stream with id = 2 ** 32 - 1
        stream = client.h2_connection._begin_new_stream(
            (2**31 - 1), AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)
        # add request method that avoid error in handle_read
        client.methods.append("POST")
        # send headers frame with stream_id = 0xffffffff (2**32-1).
        client.send_bytes(
            b"\x00\x00\n\x01\x05\xff\xff\xff\xffA\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )

        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")


class TestH2StreamRstStreamAttack(H2Base):
    def test_reset_by_prio(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        stream = client.h2_connection._get_or_create_stream(
            client.stream_id, AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)
        client.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)

        hf = HeadersFrame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS"],
        )
        client.send_bytes(
            hf.serialize(),
            expect_response=False,
        )

        prio = PriorityFrame(stream_id=stream.stream_id, depends_on=stream.stream_id)
        client.send_bytes(
            prio.serialize(),
            expect_response=True,
        )

        self.assertTrue(client.wait_for_reset_stream(stream_id=1))
        self.assertFalse(client.wait_for_connection_close())

    def test_reset_by_req(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.make_request(
            self.get_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=1,
            priority_exclusive=False,
        )

        self.assertTrue(client.wait_for_reset_stream(stream_id=1))
        self.assertFalse(client.wait_for_connection_close())


class TestMultiplexing(tester.TempestaTest):
    clients = [
        {
            "id": "curl-1",
            "type": "curl",
            "cmd_args": f" --max-time 10",
            "http2": True,
        },
        {
            "id": "curl-2",
            "type": "curl",
            "cmd_args": f" --max-time 10",
            "http2": True,
        },
        {
            "id": "curl-3",
            "type": "curl",
            "cmd_args": f" --max-time 10",
            "http2": True,
        },
    ]

    backends = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "",
        },
        {
            "id": "deproxy-3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "",
        },
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            
            srv_group srv_1 {
                server ${server_ip}:8000;
            }
            srv_group srv_2 {
                server ${server_ip}:8001;
            }
            srv_group srv_3 {
                server ${server_ip}:8002;
            }
            vhost v_1 {
                proxy_pass srv_1;
            }
            vhost v_2 {
                proxy_pass srv_2;
            }
            vhost v_3 {
                proxy_pass srv_3;
            }
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            http_max_header_list_size 134217728; #128 KB

            block_action attack reply;
            block_action error reply;
            
            http_chain {
                host == "client1" -> v_1;
                host == "client2" -> v_2;
                host == "client3" -> v_3;
            }
         """
    }

    def test_base_multiplexing(self):
        """Exchange of different frames in responses and requests"""
        self.start_all_services(client=False)
        clients = self.get_clients()
        servers = list(self.get_servers())
        requests = int(tf_cfg.cfg.get("General", "stress_requests_count"))

        step = 1
        for client, server in list(zip(clients, servers)):
            server.set_response(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + f"Large_header: {'12345' * 4000}\r\n"
                + f"Content-Length: {step}\r\n\r\n"
                + f"{'x' * step}"
            )

            client.uri += f"[1-{requests}]"
            client.dump_headers = False
            client.parallel = tf_cfg.cfg.get("General", "concurrent_connections")
            client.headers = {"Host": f"client{step}"}
            header = f" -H '{step * 10}: {'asdfg' * 5000}' "
            client.options = [f" {header} --data 'request body {step}' "]

            step += 1

        for client in clients:
            client.start()
        self.wait_while_busy(*clients)
        for client in clients:
            client.stop()

        step = 1
        for client, server in list(zip(clients, servers)):
            self.assertEqual(len(client.stats), requests)
            self.assertEqual(len(server.requests), requests)

            for response, request in list(zip(client.stats, server.requests)):
                self.assertEqual(response["http_code"], 200)
                self.assertEqual(int(response["size_download"]), step)
                self.assertEqual(request.headers["Host"], f"client{step}")

            step += 1
