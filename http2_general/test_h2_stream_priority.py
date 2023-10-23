"""Functional tests for stream priority."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from h2.errors import ErrorCodes
from hyperframe.frame import PriorityFrame

import run_config
from helpers import util
from helpers.networker import NetWorker
from http2_general.helpers import H2Base

DEFAULT_MTU = 1500
DEFAULT_INITIAL_WINDOW_SIZE = 65535
BIG_HEADER_SIZE = 600000

"""
Make sure that all requests come to client, and we
receive headers for all responses. TODO: #528
"""


def wair_for_headers():
    timeout = 5 if run_config.TCP_SEGMENTATION else 2
    time.sleep(timeout)


class TestPriorityBase(H2Base, NetWorker):
    def setup_test_priority(self, extra_header=""):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + extra_header
            + "Content-Length: 100000\r\n\r\n"
            + ("x" * 100000)
        )

        client.update_initial_settings(initial_window_size=0)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()
        return client, server

    def wait_for_responses(
        self, client, initial_window_size=DEFAULT_INITIAL_WINDOW_SIZE, timeout=10
    ):
        wair_for_headers()
        client.send_settings_frame(initial_window_size=initial_window_size)
        client.wait_for_ack_settings()
        self.assertTrue(client.wait_for_response(timeout=timeout))

    def check_response_sequence(self, client, expected_length, expected_sequence=None):
        self.assertTrue(expected_length == len(client.response_sequence))
        self.assertTrue(expected_length == len(client.responses))
        for i in range(expected_length):
            if expected_sequence:
                self.assertTrue(expected_sequence[i] == client.response_sequence[i])
            self.assertEqual(client.responses[i].status, "200")
        client.response_sequence = []
        client.valid_req_num = 0
        client.responses = []

    def build_complex_priority_tree(self, client):
        """
        Build stream priority tree:
                        1 (256)
            3 (256)            5 (1)
        7 (256) 9 (1)      11 (256) 13 (1)
        """
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=0,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=1,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=1,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=3,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=3,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=5,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=5,
            priority_exclusive=False,
        )


class TestStreamPriorityInHeaders(TestPriorityBase, NetWorker):
    def test_stream_priority_from_non_existing_stream(self):
        """
        Client send headers with priority information,
        each new created stream depends from non existing stream.
        In this case each new created stream will be depend from
        root stream, so stream dependencies play no role, only
        stream weight affect priority.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_non_existing_stream, DEFAULT_MTU
        )

    def _test_stream_priority_from_non_existing_stream(self, client, server):
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=3,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=16,
            priority_depends_on=5,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=64,
            priority_depends_on=7,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=None,
            priority_exclusive=False,
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 4, [7, 5, 3, 1])

    def test_stream_priority_from_existing_stream(self):
        """
        Client send headers with priority information,
        each new created stream depends from existing stream.
        Dependency tree is 0->1->3->5->7, so weight play no
        role, since data for dependent stream is not sent,
        while parent stream is active.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_existing_stream, DEFAULT_MTU
        )

    def _test_stream_priority_from_existing_stream(self, client, server):
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=0,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=16,
            priority_depends_on=1,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=64,
            priority_depends_on=3,
            priority_exclusive=False,
        )
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=256,
            priority_depends_on=5,
            priority_exclusive=False,
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 4, [1, 3, 5, 7])

    def test_stream_priority_from_existing_stream_complex(self):
        """
        Same as previos, but much more complex priority tree.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_existing_stream_complex, DEFAULT_MTU
        )

    def _test_stream_priority_from_existing_stream_complex(self, client, server):
        self.build_complex_priority_tree(client)
        self.wait_for_responses(client)
        self.check_response_sequence(client, 7, [1, 3, 7, 9, 5, 11, 13])

    def test_stream_priority_from_existing_stream_complex_exclusive(self):
        """
        Build stream dependency tree using exclusive flag
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_stream_priority_from_existing_stream_complex_exclusive,
            DEFAULT_MTU,
        )

    def _test_stream_priority_from_existing_stream_complex_exclusive(self, client, server):
        self.build_complex_priority_tree(client)
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=1,
            priority_exclusive=True,
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 8, [1, 15, 3, 7, 9, 5, 11, 13])

    def test_stream_priority_from_existing_stream_with_removal(self):
        """
        Build stream dependency tree, close several streams from this
        tree. Check stream dependency tree after removal of several
        streams.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_stream_priority_from_existing_stream_with_removal,
            DEFAULT_MTU,
        )

    def _test_stream_priority_from_existing_stream_with_removal(self, client, server):
        """
        Build stream dependency tree same as it was in one of the previous test
        """
        self._test_stream_priority_from_existing_stream_complex(client, server)
        """
		When count of closed streams is greater then 5, the creation of new
		stream leads to deletion of one of the old closed streams.
		"""
        client.send_settings_frame(initial_window_size=0)
        client.wait_for_ack_settings()

        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=7,
            priority_exclusive=False,
        )

        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=1,
            priority_depends_on=None,
            priority_exclusive=False,
        )

        client.send_settings_frame(initial_window_size=DEFAULT_INITIAL_WINDOW_SIZE)
        client.wait_for_ack_settings()

        self.wait_for_responses(client)
        self.check_response_sequence(client, 2, [15, 17])


"""
This tests same as tests from previous class, but they use
PRIORITY frames instead of headers to specify priority
information.
"""


class TestStreamPriorityInPriorityFrames(TestPriorityBase, NetWorker):
    def test_stream_priority_from_non_existing_stream(self):
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_non_existing_stream, DEFAULT_MTU
        )

    def _test_stream_priority_from_non_existing_stream(self, client, server):
        client.send_bytes(
            PriorityFrame(stream_id=1, depends_on=3, stream_weight=0, exclusive=False).serialize()
        )
        client.send_bytes(
            PriorityFrame(stream_id=3, depends_on=5, stream_weight=15, exclusive=False).serialize()
        )
        client.send_bytes(
            PriorityFrame(stream_id=5, depends_on=7, stream_weight=63, exclusive=False).serialize()
        )
        client.send_bytes(
            PriorityFrame(stream_id=7, depends_on=9, stream_weight=255, exclusive=False).serialize()
        )

        client.make_requests(
            [self.post_request, self.post_request, self.post_request, self.post_request]
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 4, [7, 5, 3, 1])

    def test_stream_priority_from_existing_stream(self):
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_existing_stream, DEFAULT_MTU
        )

    def _test_stream_priority_from_existing_stream(self, client, server):
        client.send_bytes(
            PriorityFrame(stream_id=1, depends_on=0, stream_weight=0, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=3, depends_on=1, stream_weight=15, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=5, depends_on=3, stream_weight=63, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=7, depends_on=5, stream_weight=255, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        self.wait_for_responses(client)
        self.check_response_sequence(client, 4, [1, 3, 5, 7])

    def test_stream_priority_from_existing_stream_complex(self):
        """
        Same as previos, but much more complex priority tree.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_priority_from_existing_stream_complex, DEFAULT_MTU
        )

    def _test_stream_priority_from_existing_stream_complex(self, client, server):
        client.send_bytes(
            PriorityFrame(stream_id=1, depends_on=0, stream_weight=0, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=3, depends_on=1, stream_weight=255, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=5, depends_on=1, stream_weight=0, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=7, depends_on=3, stream_weight=255, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=9, depends_on=3, stream_weight=0, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(
                stream_id=11, depends_on=5, stream_weight=255, exclusive=False
            ).serialize()
        )
        client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(stream_id=13, depends_on=5, stream_weight=0, exclusive=False).serialize()
        )
        client.make_request(self.post_request)

        self.wait_for_responses(client)
        self.check_response_sequence(client, 7, [1, 3, 7, 9, 5, 11, 13])


"""
This tests checks rebuilding of streams priority tree,
because of changing streams priority
"""


class TestStreamPriorityTreeRebuild(TestPriorityBase, NetWorker):
    def test_stream_change_parent_stream_not_exlusive(self):
        """
        Simple case, stream with several childs change it's parent.
        New parent is not one of streams child. Stream dependency is
        not exclusive.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_change_parent_stream_not_exlusive, DEFAULT_MTU
        )

    def _test_stream_change_parent_stream_not_exlusive(self, client, server):
        self.build_complex_priority_tree(client)
        client.send_bytes(
            PriorityFrame(stream_id=5, depends_on=3, stream_weight=16, exclusive=False).serialize()
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 7, [1, 3, 7, 5, 11, 13, 9])

    def test_stream_change_parent_stream_exlusive(self):
        """
        Same as previous, but stream dependecy is exclusive.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client, server, self._test_stream_change_parent_stream_exlusive, DEFAULT_MTU
        )

    def _test_stream_change_parent_stream_exlusive(self, client, server):
        self.build_complex_priority_tree(client)
        client.send_bytes(PriorityFrame(stream_id=7, depends_on=3, stream_weight=16).serialize())
        client.send_bytes(PriorityFrame(stream_id=9, depends_on=3, stream_weight=64).serialize())
        client.send_bytes(
            PriorityFrame(stream_id=5, depends_on=3, stream_weight=16, exclusive=True).serialize()
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 7, [1, 3, 5, 11, 9, 7, 13])

    def test_stream_change_parent_stream_not_exlusive_with_rebuild(self):
        """
        Same as first test, but new parent is a child of stream.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_stream_change_parent_stream_not_exlusive_with_rebuild,
            DEFAULT_MTU,
        )

    def _test_stream_change_parent_stream_not_exlusive_with_rebuild(self, client, server):
        self.build_complex_priority_tree(client)
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=64,
            priority_depends_on=11,
            priority_exclusive=False,
        )
        client.send_bytes(
            PriorityFrame(stream_id=1, depends_on=11, stream_weight=1, exclusive=False).serialize()
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 8, [11, 15, 1, 3, 7, 9, 5, 13])

    def test_stream_change_parent_stream_exlusive_with_rebuild(self):
        """
        Same as first test, but new parent is a child of stream.
        """
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_stream_change_parent_stream_exlusive_with_rebuild,
            DEFAULT_MTU,
        )

    def _test_stream_change_parent_stream_exlusive_with_rebuild(self, client, server):
        self.build_complex_priority_tree(client)
        client.make_request(
            self.post_request,
            end_stream=True,
            priority_weight=64,
            priority_depends_on=11,
            priority_exclusive=False,
        )
        client.send_bytes(
            PriorityFrame(stream_id=1, depends_on=11, stream_weight=1, exclusive=True).serialize()
        )

        self.wait_for_responses(client)
        self.check_response_sequence(client, 8, [11, 1, 3, 7, 9, 15, 5, 13])


class TestStreamPriorityStress(TestPriorityBase, NetWorker):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            keepalive_timeout 120;
            max_concurrent_streams 1000;
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    def test_stream_priority_stress(self):
        client, server = self.setup_test_priority()
        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_stream_priority_stress,
            DEFAULT_MTU,
        )

    def _test_stream_priority_stress(self, client, server):
        first_level_streams = []
        for weight in range(1, 257):
            first_level_streams.append(client.stream_id)
            client.make_request(
                self.post_request,
                end_stream=True,
                priority_weight=weight,
                priority_depends_on=0,
                priority_exclusive=False,
            )

        weight = 1
        for stream_id in first_level_streams:
            client.make_request(
                self.post_request,
                end_stream=True,
                priority_weight=weight,
                priority_depends_on=stream_id,
                priority_exclusive=False,
            )
            client.make_request(
                self.post_request,
                end_stream=True,
                priority_weight=257 - weight,
                priority_depends_on=stream_id,
                priority_exclusive=False,
            )
            weight = weight + 1

        self.wait_for_responses(client, timeout=120)
        self.check_response_sequence(client, 256 + 256 * 2)


class TestMaxConcurrentStreams(TestPriorityBase, NetWorker):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            max_concurrent_streams 10;
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    def test_max_concurent_stream_exceed_by_stream(self):
        """
        If creation of new stream leads to exceeding of max_concurrent_streams, we should reset
        this stream. Check that all streams, which creation leads to exceedion of max_concurrent_streams
        will be reset and all previos streams will be finished successfully.
        """
        client, server = self.setup_test_priority()

        prev_stream_id = 0
        self.assertTrue(client.h2_connection.remote_settings.max_concurrent_streams == 10)

        # Create streams with "idle" state with the id range from 21 to 39
        for i in range(0, client.h2_connection.remote_settings.max_concurrent_streams):
            stream_id = 2 * client.h2_connection.remote_settings.max_concurrent_streams + 2 * i + 1
            client.send_bytes(
                PriorityFrame(
                    stream_id=stream_id,
                    depends_on=prev_stream_id,
                    stream_weight=1,
                    exclusive=False,
                ).serialize()
            )
            prev_stream_id = stream_id

        valid_req_num = client.valid_req_num
        """
        Try to open streams with the id range from 1 to 19, they should be reseted,
        because of exceed of max concurent stream limit.
        """
        for i in range(0, client.h2_connection.remote_settings.max_concurrent_streams):
            stream_id = client.stream_id
            client.make_request(self.post_request)
            self.assertTrue(client.wait_for_reset_stream(stream_id=stream_id))

        return client, valid_req_num

    def test_opening_created_idle_streams_after_exceed_max_concurent_streams_linit(self):
        client, valid_req_num = self.test_max_concurent_stream_exceed_by_stream()

        client.reinit_hpack_encoder()
        client.valid_req_num = valid_req_num
        # Opening of streams which was previously created with idle state is allowed.
        for i in range(0, client.h2_connection.remote_settings.max_concurrent_streams):
            client.make_request(self.post_request)

        self.wait_for_responses(client)
        self.check_response_sequence(client, 10, [21, 23, 25, 27, 29, 31, 33, 35, 37, 39])

    def test_opening_not_created_idle_streams_after_exceed_max_concurent_streams_linit(self):
        client, valid_req_num = self.test_max_concurent_stream_exceed_by_stream()

        client.reinit_hpack_encoder()
        client.valid_req_num = valid_req_num
        client.stream_id = 41
        client.make_request(self.post_request)
        self.wait_for_responses(client)
        self.check_response_sequence(client, 1, [41])

    def test_max_concurent_stream_exceed_by_priority_frame(self):
        """
        If creation of new stream leads to exceeding of max_concurrent_streams, we should reset
        this stream. But according to RFC we can't reset idle streams, so Tempesta FW just
        close the connetion with PROTOCOL_ERROR.
        """
        client, server = self.setup_test_priority()

        self.assertTrue(client.h2_connection.remote_settings.max_concurrent_streams == 10)
        for i in range(0, client.h2_connection.remote_settings.max_concurrent_streams - 1):
            client.make_request(self.post_request)

        client.send_bytes(
            PriorityFrame(
                stream_id=client.stream_id, depends_on=5, stream_weight=255, exclusive=False
            ).serialize()
        )
        client.send_bytes(
            PriorityFrame(
                stream_id=client.stream_id + 2, depends_on=5, stream_weight=255, exclusive=False
            ).serialize()
        )
        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)


class TestBigHeadersAndBodyForSeveralStreams(TestPriorityBase, NetWorker):
    def test_big_headers_and_body(self):
        client, server = self.setup_test_priority(
            extra_header=f"qwerty: {'y' * BIG_HEADER_SIZE}\r\n"
        )
        client.send_settings_frame(max_header_list_size=BIG_HEADER_SIZE * 2)
        client.wait_for_ack_settings()

        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_big_headers_and_body,
            DEFAULT_MTU,
        )

    def _test_big_headers_and_body(self, client, server):
        for i in range(1, 3):
            client.make_request(self.post_request)

        self.wait_for_responses(client)
        self.check_response_sequence(client, 2)


class TestSameWeightsWithOneParent(TestPriorityBase, NetWorker):
    def test_content_type_not_progessive(self):
        """
        Check that we don't use raund robin for non progressive
        streams and don't switch between such streams, when we
        send data to client.
        """
        client, server = self.setup_test_priority(extra_header=f"content-type: image/png\r\n")

        self.run_test_tso_gro_gso_def(
            client,
            server,
            self._test_same_weights_streams_not_progressive,
            DEFAULT_MTU,
        )

    def _test_same_weights_streams_not_progressive(self, client, server):
        for i in range(1, 4):
            client.make_request(
                self.post_request,
                end_stream=True,
                priority_weight=16,
                priority_depends_on=0,
                priority_exclusive=False,
            )
            # Need to sure that tempesta receive requests in the correct order.
            wair_for_headers()

        """
        Increment initial_window_size to max value, to prevent its affecting
        on data sending (We switch to another stream if current stream exceeds
        http window).
        """
        self.wait_for_responses(client, initial_window_size=2**31 - 1)
        """
        We send headers for all streams, and then blocked untlil initial
        window size will be updated. Since the last stream has id == 5,
        we start from it and don't switch to another stream until all data
        will be sent or we exceeded HTTP window for this stream.
        """
        self.check_response_sequence(client, 3, [5, 1, 3])
