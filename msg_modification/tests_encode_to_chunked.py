"""
Transform payload to chunked encoding.

When a server doesn't provide message framing information like `Content-Length`
header or chunked encoding, it indicates end of message by connection close,
RFC 7230 3.3.3. Tempesta doesn't propagate connection close to clients, instead
it adds message framing information and leaves connection open.
"""

from __future__ import print_function
from testers import functional
from helpers import chains, tempesta, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestTransformPayload(functional.FunctionalTest):
    """Server sends response without massage framing information, client must
    receive valid response with message framing information, connection must
    remain open.
    """

    config = ('')

    def create_servers(self):
        """Server doesn't provide message framing information and indicates
        message end by connection close. Set keep-alive as 1 to close connection
        immediately after response is sent."""
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, keep_alive=1)]

    @staticmethod
    def make_chain(body):
        chain = chains.base()
        chunked_body = '\r\n'.join([str(len(body)), body, '0', '', ''])

        # Server doesn't provide message framing information
        chain.server_response.headers.delete_all('Content-Length')
        chain.server_response.body = body
        chain.server_response.build_message()

        # Client receives response with the message framing information
        chain.response.headers.delete_all('Content-Length')
        chain.response.headers.add('Transfer-Encoding', 'chunked')
        chain.response.body = chunked_body
        chain.response.update()

        return [chain]

    def test_small_body_to_chunked(self):
        """ Server sends relatively small body"""
        msg_chains = self.make_chain('1234')
        self.generic_test_routine(self.config, msg_chains)

    def test_big_body_to_chunked(self):
        """ Server sends relatively small body"""
        body = ('abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789'
                'abcdefghijklmnopqrstuvwxyz0123456789')
        msg_chains = self.make_chain(body)
        self.generic_test_routine(self.config, msg_chains)
