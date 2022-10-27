"""Tests for long body in request."""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import os

from framework import curl_client
from framework.tester import TempestaTest
from helpers import tf_cfg, remote
from helpers import checks_for_tests as checks
from t_long_body import utils
from t_stress.test_stress import CustomMtuMixin

BODY_SIZE = 1024 ** 2 * int(tf_cfg.cfg.get("General", "long_body_size"))

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    client_max_body_size 10000M;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        chunked_transfer_encoding on;
        location / {
            return 200;

        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class LongBodyInRequest(TempestaTest, CustomMtuMixin):
    tempesta = {
        'config': """
    listen 80;
    listen 443 proto=https;
    listen 4433 proto=h2;

    server ${server_ip}:8000;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    cache 0;
    """
    }

    clients = [
        {
            'id': 'deproxy-http',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
        },
        {
            'id': 'deproxy-https',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '443',
            'ssl': True,
        },
        {
            "id": "curl-h2",
            "type": "curl",
            "addr": "${tempesta_ip}:4433",
            "http2": True,
        },
    ]

    backends = [
        {
            'id': 'nginx',
            'type': 'nginx',
            'port': '8000',
            'status_uri': 'http://${server_ip}:8000/nginx_status',
            'config': NGINX_CONFIG,
        },
    ]

    def setUp(self):
        location = tf_cfg.cfg.get('Client', 'workdir')
        self.abs_path = os.path.join(location, 'long_body.bin')
        remote.client.copy_file(self.abs_path, 'x' * BODY_SIZE)
        super().setUp()

    def tearDown(self):
        super().tearDown()
        if not remote.DEBUG_FILES:
            remote.client.run_cmd(f'rm {self.abs_path}')

    def _test(self, client_id: str, header: str, body: str):
        """Send request with long body and check that Tempesta does not crash."""
        self.start_all_services(client=False)

        client = self.get_client(client_id)
        if isinstance(client, curl_client.CurlClient):
            client.options = [f" --data-binary @'{self.abs_path}'"]
            client.start()
            client.wait_for_finish()
            client.stop()
        else:
            client.start()
            client.send_request(
                request=(
                        'POST / HTTP/1.1\r\n'
                        + 'Host: localhost\r\n'
                        + 'Content-type: text/html\r\n'
                        + f'{header}\r\n'
                        + '\r\n'
                        + body
                ),
                expected_status_code='200',
            )

        tempesta = self.get_tempesta()
        tempesta.get_stats()

        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_forwarded=1,
            cl_msg_received=1,
            srv_msg_received=1,
            srv_msg_forwarded=1,
        )

    def test_http(self):
        self._test(client_id='deproxy-http', header=f'Content-Length: {BODY_SIZE}',
                   body='x' * BODY_SIZE)

    def test_https(self):
        self._test(client_id='deproxy-https', header=f'Content-Length: {BODY_SIZE}',
                   body='x' * BODY_SIZE)

    def test_h2(self):
        self._test(client_id='curl-h2', header=f'Content-Length: {BODY_SIZE}',
                   body='x' * BODY_SIZE)

    def test_one_big_chunk_in_request_http(self):
        self._test(client_id='deproxy-http', header='Transfer-Encoding: chunked',
                   body=utils.create_one_big_chunk(BODY_SIZE))

    def test_one_big_chunk_in_request_https(self):
        self._test(client_id='deproxy-https', header='Transfer-Encoding: chunked',
                   body=utils.create_one_big_chunk(BODY_SIZE))

    def test_many_big_chunks_in_request_http(self):
        self._test(client_id='deproxy-http', header='Transfer-Encoding: chunked',
                   body=utils.create_many_big_chunks(BODY_SIZE))

    def test_many_big_chunks_in_request_https(self):
        self._test(client_id='deproxy-https', header='Transfer-Encoding: chunked',
                   body=utils.create_many_big_chunks(BODY_SIZE))
