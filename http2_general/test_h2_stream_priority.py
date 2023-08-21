"""Functional tests for stream priority."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from http2_general.helpers import H2Base
from hyperframe.frame import PriorityFrame
from helpers.networker import NetWorker
from helpers import util
import time

DEFAULT_MTU = 1500
DEFAULT_INITIAL_WINDOW_SIZE = 65535


class TestPriorityBase(H2Base, NetWorker):
    def setup_test_priority(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 100000\r\n\r\n"
            + ("x" * 100000)
        )

        client.update_initial_settings(initial_window_size=0)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()
        return client, server

    def wait_for_responses(self, client, timeout=60):
        """
        Make sure that all requests come to client, before updating
        initial window size.
        """
        time.sleep(2)
        client.send_settings_frame(initial_window_size=DEFAULT_INITIAL_WINDOW_SIZE)
        client.wait_for_ack_settings()
        self.assertTrue(client.wait_for_response(timeout=timeout))

    def check_response_sequence(self, client, expected_sequence):
        self.assertTrue(len(expected_sequence) == len(client.response_sequence))
        for i in range(len(expected_sequence)):
            self.assertTrue(expected_sequence[i] == client.response_sequence[i])
        client.response_sequence = []

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
        self.check_response_sequence(client, [7, 5, 3, 1])

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
        self.check_response_sequence(client, [1, 3, 5, 7])

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
        self.check_response_sequence(client, [1, 3, 7, 9, 5, 11, 13])

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
        self.check_response_sequence(client, [1, 15, 3, 7, 9, 5, 11, 13])

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
        self.check_response_sequence(client, [15, 17])


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
        self.check_response_sequence(client, [7, 5, 3, 1])

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
        self.check_response_sequence(client, [1, 3, 5, 7])

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
        self.check_response_sequence(client, [1, 3, 7, 9, 5, 11, 13])


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
        self.check_response_sequence(client, [1, 3, 7, 5, 11, 13, 9])

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
        self.check_response_sequence(client, [1, 3, 5, 11, 9, 7, 13])

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
        self.check_response_sequence(client, [11, 15, 1, 3, 7, 9, 5, 13])

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
        self.check_response_sequence(client, [11, 1, 3, 7, 9, 15, 5, 13])


class TestStreamPriorityStress(TestPriorityBase, NetWorker):
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

        self.wait_for_responses(client, timeout=240)
