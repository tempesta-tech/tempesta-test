"""
Transform payload to chunked encoding.

When a server doesn't provide message framing information like `Content-Length`
header or chunked encoding, it indicates end of message by connection close,
RFC 7230 3.3.3. Tempesta doesn't propagate connection close to clients, instead
it adds message framing information and leaves connection open.
"""

from helpers import deproxy
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class MessageTransformations(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : ''
        }
    ]

    tempesta = {
        'config' :
        """
        listen 80;
        
        srv_group * {
            server ${server_ip}:8000;
        }
        vhost * {
            proxy_pass *;
        }

        """
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        },
    ]

    def start_all(self):
        #force server to close the connection after response is sent.
        srv = self.get_server('deproxy')
        srv.keep_alive = 1
        srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(1))

    def send_req(self, client):
        curr_responses = len(client.responses)
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n")
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    @staticmethod
    def gen_body(body_len=0):
        return ''.join([chr(i % 26 + ord('a')) for i in range(body_len)])

    @staticmethod
    def chunked_body(body):
        if body:
            chunked_body = '\r\n'.join(["%X" %len(body), body, '0', '', ''])
        else:
            chunked_body = '\r\n'.join(['0', '', ''])
        return chunked_body

    def test_small_body_to_chunked(self):
        """ Server sends relatively small body, Tempesta converts the message
        to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, self.chunked_body(body),
                         'Body is not in chunked encoding!')

    def test_big_body_to_chunked(self):
        """ Server sends huge body, that can't fit single skb. Tempesta converts
        the message to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(32*4096)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, self.chunked_body(body),
                         'Body is not in chunked encoding!')

    def test_zero_body_to_chunked(self):
        """Server doesn't send a body (zero sized body). Tempesta converts
        the message to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(0)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, self.chunked_body(body),
                         'Body is not in chunked encoding!')

    def test_transform_not_possible(self):
        """ Chunked is not last encoding in the backend response, Tempesta
        can't add framing information and closes the connection to indicate
        the message end.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Date: %s\r\n'
                'Transfer-Encoding: chunked, gzip\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertTrue(client.connection_is_closed(),
                        'Client connection was not closed to indicate message'
                        ' end')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked, gzip', 'Unexpected transfer encoding!')
        self.assertEqual(rec_resp.body, body,
                         'Body is incorrectly modified!')

    def test_transform_possible(self):
        """ Chunked is not used as encoding in the backend response, Tempesta
        can add framing information and doesn't need to close the connection
        to indicate the message end.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Date: %s\r\n'
                'Transfer-Encoding: gzip\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'gzip, chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, self.chunked_body(body),
                         'Body is not in chunked encoding!')
