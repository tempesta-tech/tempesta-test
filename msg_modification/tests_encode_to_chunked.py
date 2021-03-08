"""
Transform HTTP/1 payload to chunked encoding.

Tempesta always cuts chunked encoding and adds it back for chunked messages.
This behaviour is optimised for HTTP/2 client processing, but it involes a lot
of skb operations. Check that message framing is still correct.

Sometimes backend servers doesn't provide framing information and indicate
message end by connection close. Check that Tempesta makes it best to add
correct framing without propagating connection close.

"""

from helpers import deproxy
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Chunked(tester.TempestaTest):

    # Close server connection every time response is sent
    KEEP_ALIVE = 1

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
        server ${server_ip}:8000;

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
        srv.keep_alive = self.KEEP_ALIVE
        srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(3))

    def send_req(self, client):
        curr_responses = len(client.responses)
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n")
        client.make_requests(req)
        client.wait_for_response(timeout=5)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    @staticmethod
    def gen_body(body_len=0):
        return ''.join([chr(i % 26 + ord('a')) for i in range(body_len)])

    @staticmethod
    def chunked_body(body, lowercase=False):
        fmt = "%x" if lowercase else "%X"
        if body:
            chunked_body = '\r\n'.join([fmt % len(body), body, '0', '', ''])
        else:
            chunked_body = '\r\n'.join(['0', '', ''])
        return chunked_body

    @staticmethod
    def chunked_body_with_trailer(body, trailer, lowercase=False):
        fmt = "%x" if lowercase else "%X"
        if body:
            chunked_body = '\r\n'.join([fmt % len(body), body, '0', trailer, ''])
        else:
            chunked_body = '\r\n'.join(['0', trailer, ''])
        return chunked_body


class AddChunkedEncoding(Chunked):
    """
    When a server doesn't provide message framing information like
    `Content-Length` header or chunked encoding, it indicates end of message
    by connection close, RFC 7230 3.3.3. Tempesta doesn't propagate connection
    close to clients, instead it adds message framing information and leaves
    connection open.
    """

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


class RechunkMessage(Chunked):
    """
    Every response in chunked encoding losing chunked encoding during message
    parsing and then it's added only if client is talking http/1 protocol.
    Chunked body looks different in than case: only firs and last chunk
    descriptors are left.
    """

    KEEP_ALIVE = 100

    def test_small_body_to_chunked(self):
        """ Server sends relatively small body in chunked encoding,
        Tempesta strips the chunked encoding and applies it back, but message
        looks absolutely identical.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        chunked_body = self.chunked_body(body)
        expected_body = self.chunked_body(body, lowercase=True)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')

    def test_big_body_to_chunked(self):
        """ Server sends huge body, that can't fit single skb. Tempesta converts
        the message to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(32 *4096)
        chunked_body = self.chunked_body(body)
        expected_body = self.chunked_body(body, lowercase=True)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')

    def test_zero_body_to_chunked(self):
        """Server doesn't send a body (zero sized body). Tempesta converts
        the message to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(0)
        chunked_body = self.chunked_body(body)
        expected_body = self.chunked_body(body, lowercase=True)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')

    def test_trailer_headers(self):
        """ Server sends chunked trailer.
        Tempesta strips the chunked encoding and applies it back, but message
        looks absolutely identical and trailer header sits on it's place.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        trailer = 'X-My-trailer-Header: somevalue'
        chunked_body = self.chunked_body_with_trailer(body, trailer)
        # self.chunked_body() adds extra CRLF after '0' chunk descriptor,
        # not needed here because of chunked trailer
        expected_body = '\r\n'.join(["%x" % len(body), body, '0', ''])
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s\r\n'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         'chunked', 'Chunked encoding is missed!')
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')

    def test_heavily_chunked_body(self):
        """ Server sends relatively small body, Tempesta converts the message
        to chunked encoding.
        """
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        chunk_len = 40
        chunks = 10
        body = ''
        expected_body = '%x\r\n' % (chunk_len * chunks)
        chunk = self.gen_body(chunk_len)
        chunk_desc = '%X\r\n%s\r\n' % (len(chunk), chunk)
        for _ in range(chunks):
            body += chunk_desc
            expected_body += chunk
        body += '0\r\n\r\n'
        expected_body += '\r\n0\r\n\r\n'
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
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
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')


class ChunkedRequest(Chunked):
    """
    The same code is used for both request and response, but Tempesta never
    modifies chunked encoded request body. Check that client code is not broken
    by server code.
    """

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        }
    ]

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

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

    KEEP_ALIVE = 100

    def start_all(self):
        #force server to close the connection after response is sent.
        srv = self.get_server('deproxy')
        srv.keep_alive = self.KEEP_ALIVE
        srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(1))

    def test_chunked_request(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')
        body = self.gen_body(40)
        chunked_body = self.chunked_body(body)
        req = ('GET / HTTP/1.1\r\n'
               'Host: localhost\r\n'
               'Transfer-Encoding: chunked\r\n'
               '\r\n%s' % chunked_body)
        client.make_requests(req)
        client.wait_for_response(timeout=5)
        self.assertEqual(1, len(client.responses))

        fwd_req = srv.requests[-1]
        self.assertEqual(fwd_req.body, chunked_body,
                         'Body is not in chunked encoding or mismatch!')


    def test_heavily_chunked_request(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        chunk_len = 40
        chunks = 10
        body = ''
        chunk = self.gen_body(chunk_len)
        chunk_desc = '%X\r\n%s\r\n' % (len(chunk), chunk)
        for _ in range(chunks):
            body += chunk_desc
        body += '0\r\n\r\n'
        req = ('GET / HTTP/1.1\r\n'
               'Host: localhost\r\n'
               'Transfer-Encoding: chunked\r\n'
               '\r\n%s' % body)
        client.make_requests(req)
        client.wait_for_response(timeout=5)
        self.assertEqual(1, len(client.responses))

        fwd_req = srv.requests[-1]
        self.assertEqual(fwd_req.body, body,
                         'Body is not in chunked encoding or mismatch!')


class AddChunkedEncodingCached(Chunked):
    """
    When a message is saved in cache, it looses the chunked encoding and
    Content-Length header is used to provide correct message framing.
    """

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
        server ${server_ip}:8000;

        cache 2;
        cache_fulfill * *;

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

    KEEP_ALIVE = 100

    def send_req(self, client, server):
        """Make two requests: first to populate cache and second will served
        from cache. Don't check anything in the first request-response pair,
        we already have test classes to cover that cases.
        """
        cur_requests = len(server.requests)
        for _ in range(2):
            curr_responses = len(client.responses)
            req = ("GET / HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   "\r\n")
            client.make_requests(req)
            client.wait_for_response(timeout=5)
            self.assertEqual(curr_responses + 1, len(client.responses))
        # There is no much sense if the second response is not from cache
        self.assertEqual(curr_responses + 1, len(client.responses))
        return client.responses[-1]

    def test_small_body(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body_len = 40
        body = self.gen_body(body_len)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client, srv)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         None, 'Unexpectedly got chunked encoding!')
        self.assertEqual(rec_resp.headers.get('Content-Length', None),
                         '%i' % body_len, 'Content-Length header mismatch!')
        self.assertEqual(rec_resp.body, body,
                         'Body is not in chunked encoding or mismatch!')

    def test_huge_body(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body_len = 32 * 4096
        body = self.gen_body(body_len)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client, srv)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         None, 'Unexpectedly got chunked encoding!')
        self.assertEqual(rec_resp.headers.get('Content-Length', None),
                         '%i' % body_len, 'Content-Length header mismatch!')
        self.assertEqual(rec_resp.body, body,
                         'Body is not in chunked encoding or mismatch!')

    def test_zero_body(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body_len = 0
        body = self.gen_body(body_len)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client, srv)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         None, 'Unexpectedly got chunked encoding!')
        self.assertEqual(rec_resp.headers.get('Content-Length', None),
                         None, 'Content-Length present but must not!')
        self.assertEqual(rec_resp.body, body,
                         'Body is not in chunked encoding or mismatch!')

    def test_small_body_with_trailer(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body_len = 40
        body = self.gen_body(body_len)
        trailer = 'X-My-trailer-Header: somevalue'
        chunked_body = self.chunked_body_with_trailer(body, trailer)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s\r\n'
                % (date, chunked_body))
        srv.set_response(resp)

        rec_resp = self.send_req(client, srv)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         None, 'Unexpectedly got chunked encoding!')
        self.assertEqual(rec_resp.headers.get('Content-Length', None),
                         '%i' % body_len, 'Content-Length header mismatch!')
        self.assertEqual(rec_resp.body, body,
                         'Body is not in chunked encoding or mismatch!')

    def test_heavily_chunked_body(self):
        self.start_all()
        client = self.get_client('deproxy')
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        chunk_len = 40
        chunks = 10
        body = ''
        expected_body = ''
        chunk = self.gen_body(chunk_len)
        chunk_desc = '%X\r\n%s\r\n' % (len(chunk), chunk)
        for _ in range(chunks):
            body += chunk_desc
            expected_body += chunk
        body += '0\r\n\r\n'
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        rec_resp = self.send_req(client, srv)
        self.assertFalse(client.connection_is_closed(),
                         'Client connection was unexpectedly closed')
        self.assertEqual(rec_resp.status, '200', 'Unexpected response')
        self.assertEqual(rec_resp.headers.get('Transfer-Encoding', None),
                         None, 'Unexpectedly got chunked encoding!')
        self.assertEqual(rec_resp.headers.get('Content-Length', None),
                         '%i' % len(expected_body), 'Content-Length header mismatch!')
        self.assertEqual(rec_resp.body, expected_body,
                         'Body is not in chunked encoding or mismatch!')
