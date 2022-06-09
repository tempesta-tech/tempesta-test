from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from helpers import dmesg
from .common import AccessLogLine


class CheckedResponses(tester.TempestaTest):
    HTTP_200_OK = 'HTTP/1.1 200 OK\r\n' \
                  'Content-Length: 0\r\n' \
                  'Connection: keep-alive\r\n\r\n'

    clients = [
        {
            'id': 'client',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80'
        }
    ]

    backends = [
        {
            'id': '0',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content':
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 8\r\n'
                'Connection: keep-alive\r\n\r\n'
                'response'
        }
    ]

    tempesta = {
        'config': """
            cache 0;
            listen 80;
            access_log on;

            srv_group localhost {
                server ${server_ip}:8000;
            }

            vhost localhost {
                proxy_pass localhost;

            }

            http_chain {
                -> localhost;
            }
        """
    }

    # prepare request and set _expected method/version/ua/referer fields
    def make_request(self, uri, method='GET', version='1.1',
                     request_body=None, **kwargs):
        request = [
            '{method} {uri} HTTP/{version}'.format(method=method, uri=uri,
                                                   version=version),
            'Host: ' + kwargs.get('host', 'localhost'),

        ]
        if method == 'POST' or request_body is not None:
            request_body_len = 0 if request_body is None else len(request_body)
            request.append('Content-Length: %d' % request_body_len)

        self._expected_method = method
        self._expected_version = '1.1' if version != '2.0' else '2.0'
        self._expected_uri = uri
        self._expected_user_agent = kwargs.get('user_agent', '-')
        self._expected_referer = kwargs.get('referer', '-')
        for k, v in kwargs.items():
            if v is not None:
                name = '-'.join(map(str.capitalize, k.split('_')))
                request.append('%s: %s' % (name, v))
        request.append('\r\n')
        return '\r\n'.join(request)

    def set_response(self, status, body=None):
        self._expected_content_len = (0 if body is None else len(body))
        self._expected_status = status
        response = [
            'HTTP/1.1 {status} STATUS_{status}'.format(status=status),
        ]
        if self._expected_status not in [204]:
            response.append('Content-Length: %d' % self._expected_content_len)
        if body is not None:
            response.extend(['', body])
        else:
            response.append('\r\n')
        self.get_server('0').response = '\r\n'.join(response)

    def get_expected_log_msg(self):
        return '"{method} {uri} HTTP/{version}" {status}' \
               ' {response_content_length} "{referer}" "{user_agent}"'.format(
                method=self._expected_method,
                uri=self._expected_uri,
                version=self._expected_version,
                status=self._expected_status,
                response_content_length=self._expected_content_len,
                referer=self._expected_referer,
                user_agent=self._expected_user_agent,
                )

    def send_request_and_get_dmesg(self, klog, request_as_str,
                                   response_as_str=HTTP_200_OK):
        self.get_server('0').response = response_as_str
        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(request_as_str)
        deproxy_cl.wait_for_response()
        return AccessLogLine.from_dmesg(klog)

    # send request that will be replied with specified
    # `status` and `body` and check dmesg for expected access_log string
    def check_response(self, klog, status, body):
        user_agent = 'ua-code-string-%d' % status
        referer = 'referer-code-string-%d' % status
        request = self.make_request('/expect-status-%d' % status,
                                    referer=referer, user_agent=user_agent)
        self.set_response(status, body)

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(request)
        deproxy_cl.wait_for_response()
        self.assertEqual(int(deproxy_cl.last_response.status), status)
        klog.update()

        log_string = self.get_expected_log_msg()
        found = False
        for line in klog.log.decode().split('\n'):
            if line[-len(log_string):] == log_string:
                found = True
                break

        self.assertTrue(found,
                        "Expected log string <<%s>> not found in dmesg" % log_string)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(srv.wait_for_connections(timeout=1))


#######################################
# Happy-path tests (backend response) #
#######################################
class AccessLogTest(CheckedResponses):
    def test_success_path_http1x(self):
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)
        for status, body in [
            (200, 'body http ok'),
            (204, None),
            (302, 'redirect body'),
            (404, 'not-found body'),
            (500, 'internal-server-error body'),
        ]:
            self.check_response(klog, status, body)

    def test_uri_truncate(self):
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)
        req = self.make_request('/too-long-uri_' + '1' * 4000,
                                user_agent='user-agent',
                                referer='referer')
        msg = self.send_request_and_get_dmesg(klog, req)
        self.assertTrue(msg is not None, "No access_log message in dmesg")
        self.assertEqual(msg.method, 'GET', 'Wrong method')
        self.assertEqual(msg.status, 200, 'Wrong HTTP status')
        self.assertEqual(msg.uri[:len('/too-long-uri_1111')],
                         '/too-long-uri_1111',
                         'Wrong uri prefix')
        self.assertEqual(msg.uri[-4:], '1...', 'URI does not looks truncated')
        self.assertEqual(msg.user_agent, 'user-agent', 'Wrong user-agent')
        self.assertEqual(msg.referer, 'referer', 'Wrong referer')
        self.assertNotEqual(msg.ip, '-', 'Wrong ip')

    def test_bad_user_agent(self):
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)
        req = self.make_request('/some-uri',
                                user_agent='bad\nagent',
                                referer='Ok-Referer')
        msg = self.send_request_and_get_dmesg(klog, req)
        self.assertTrue(msg is not None, "No access_log message in dmesg")
        self.assertNotEqual(msg.status, 0, 'Empty response status')
        # Make sure that some fields are properly set
        self.assertEqual(msg.method, 'GET', 'Wrong method')
        self.assertEqual(msg.uri, '/some-uri', 'Wrong uri')
        self.assertNotEqual(msg.ip, '-', 'Wrong ip')


# Ensure message is logged when request is rejected by frang
class AccessLogFrang(CheckedResponses):
    tempesta = {
        'config': """
            cache 0;
            listen 80;
            access_log on;

            frang_limits {
                ip_block off;
                http_uri_len 10;
            }

            server ${general_ip}:8000;
        """
    }

    def test_frang(self):
        self.start_all()
        klog = dmesg.DmesgFinder(ratelimited=False)
        req = self.make_request('/longer-than-10-symbols-uri',
                                user_agent='user-agent',
                                referer='referer')
        msg = self.send_request_and_get_dmesg(klog, req)
        self.assertTrue(msg is not None, 'No access_log message in dmesg')
        self.assertEqual(msg.method, 'GET', 'Wrong method')
        self.assertEqual(msg.status, 403, 'Wrong HTTP status')
        self.assertEqual(msg.uri, '/longer-than-10-symbols-uri', 'Wrong uri')
        self.assertEqual(msg.user_agent, 'user-agent', 'Wrong user-agent')
        self.assertEqual(msg.referer, 'referer', 'Wrong referer')
        self.assertNotEqual(msg.ip, '-', 'Wrong ip')
