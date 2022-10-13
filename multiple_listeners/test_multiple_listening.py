"""
TestCase for multiple listening sockets.

Config for test is being auto generated and imported before test.
"""
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

ID = 'id'
CONNECTION_TIMEOUT = 2
STATUS_OK = '200'
H2SPEC_OK = '4 passed'
H2SPEC_EXTRA_SETTINGS = 'generic/4'


class TestMultipleListening(tester.TempestaTest):

    backends = [
        {
            'id': 'nginx',
            'type': 'nginx',
            'port': '8000',
            'status_uri': 'http://${server_ip}:8000/nginx_status',
            'config': """
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
                    error_log /dev/null emerg;
                    access_log off;
                    server {
                        listen        ${server_ip}:8000;
                        location / {
                            return 200;
                        }
                        location /nginx_status {
                            stub_status on;
                        }
                    }
                }
            """,
        }
    ]

    clients = [
        {
            'id': 'h2spec-1',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 8080',
        },

        {
            'id': 'h2spec-2',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 80',
        },

        {
            'id': 'curl-3',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8080/ '
        },

        {
            'id': 'curl-4',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.4:8080/ '
        },

        {
            'id': 'h2spec-5',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-6',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8080/ '
        },

        {
            'id': 'h2spec-7',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6580',
        },

        {
            'id': 'h2spec-8',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 8081',
        },

        {
            'id': 'h2spec-9',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 80',
        },

        {
            'id': 'curl-10',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8081/ '
        },

        {
            'id': 'curl-11',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.4:8081/ '
        },

        {
            'id': 'h2spec-12',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-13',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8081/ '
        },

        {
            'id': 'h2spec-14',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6581',
        },

        {
            'id': 'h2spec-15',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 8082',
        },

        {
            'id': 'h2spec-16',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 80',
        },

        {
            'id': 'curl-17',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8082/ '
        },

        {
            'id': 'curl-18',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.4:8082/ '
        },

        {
            'id': 'h2spec-19',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-20',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8082/ '
        },

        {
            'id': 'h2spec-21',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6582',
        },

        {
            'id': 'h2spec-22',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 8083',
        },

        {
            'id': 'h2spec-23',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 80',
        },

        {
            'id': 'curl-24',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8083/ '
        },

        {
            'id': 'curl-25',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.4:8083/ '
        },

        {
            'id': 'h2spec-26',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-27',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8083/ '
        },

        {
            'id': 'h2spec-28',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6583',
        },

        {
            'id': 'h2spec-29',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 8084',
        },

        {
            'id': 'h2spec-30',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.4 -p 80',
        },

        {
            'id': 'curl-31',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8084/ '
        },

        {
            'id': 'curl-32',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.4:8084/ '
        },

        {
            'id': 'h2spec-33',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-34',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8084/ '
        },

        {
            'id': 'h2spec-35',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6584',
        },

        {
            'id': 'h2spec-36',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 8085',
        },

        {
            'id': 'h2spec-37',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 80',
        },

        {
            'id': 'curl-38',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8085/ '
        },

        {
            'id': 'curl-39',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.5:8085/ '
        },

        {
            'id': 'h2spec-40',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-41',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8085/ '
        },

        {
            'id': 'h2spec-42',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6585',
        },

        {
            'id': 'h2spec-43',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 8086',
        },

        {
            'id': 'h2spec-44',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 80',
        },

        {
            'id': 'curl-45',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8086/ '
        },

        {
            'id': 'curl-46',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.5:8086/ '
        },

        {
            'id': 'h2spec-47',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-48',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8086/ '
        },

        {
            'id': 'h2spec-49',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6586',
        },

        {
            'id': 'h2spec-50',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 8087',
        },

        {
            'id': 'h2spec-51',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 80',
        },

        {
            'id': 'curl-52',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8087/ '
        },

        {
            'id': 'curl-53',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.5:8087/ '
        },

        {
            'id': 'h2spec-54',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-55',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8087/ '
        },

        {
            'id': 'h2spec-56',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6587',
        },

        {
            'id': 'h2spec-57',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 8088',
        },

        {
            'id': 'h2spec-58',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 80',
        },

        {
            'id': 'curl-59',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8088/ '
        },

        {
            'id': 'curl-60',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.5:8088/ '
        },

        {
            'id': 'h2spec-61',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-62',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8088/ '
        },

        {
            'id': 'h2spec-63',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6588',
        },

        {
            'id': 'h2spec-64',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 8089',
        },

        {
            'id': 'h2spec-65',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.5 -p 80',
        },

        {
            'id': 'curl-66',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8089/ '
        },

        {
            'id': 'curl-67',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.5:8089/ '
        },

        {
            'id': 'h2spec-68',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-69',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8089/ '
        },

        {
            'id': 'h2spec-70',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6589',
        },

        {
            'id': 'h2spec-71',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 8090',
        },

        {
            'id': 'h2spec-72',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 80',
        },

        {
            'id': 'curl-73',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8090/ '
        },

        {
            'id': 'curl-74',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.6:8090/ '
        },

        {
            'id': 'h2spec-75',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-76',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8090/ '
        },

        {
            'id': 'h2spec-77',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6590',
        },

        {
            'id': 'h2spec-78',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 8091',
        },

        {
            'id': 'h2spec-79',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 80',
        },

        {
            'id': 'curl-80',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8091/ '
        },

        {
            'id': 'curl-81',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.6:8091/ '
        },

        {
            'id': 'h2spec-82',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-83',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8091/ '
        },

        {
            'id': 'h2spec-84',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6591',
        },

        {
            'id': 'h2spec-85',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 8092',
        },

        {
            'id': 'h2spec-86',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 80',
        },

        {
            'id': 'curl-87',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8092/ '
        },

        {
            'id': 'curl-88',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.6:8092/ '
        },

        {
            'id': 'h2spec-89',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-90',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8092/ '
        },

        {
            'id': 'h2spec-91',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6592',
        },

        {
            'id': 'h2spec-92',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 8093',
        },

        {
            'id': 'h2spec-93',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 80',
        },

        {
            'id': 'curl-94',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8093/ '
        },

        {
            'id': 'curl-95',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.6:8093/ '
        },

        {
            'id': 'h2spec-96',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-97',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8093/ '
        },

        {
            'id': 'h2spec-98',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6593',
        },

        {
            'id': 'h2spec-99',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 8094',
        },

        {
            'id': 'h2spec-100',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.6 -p 80',
        },

        {
            'id': 'curl-101',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8094/ '
        },

        {
            'id': 'curl-102',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.6:8094/ '
        },

        {
            'id': 'h2spec-103',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-104',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8094/ '
        },

        {
            'id': 'h2spec-105',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6594',
        },

        {
            'id': 'h2spec-106',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 8095',
        },

        {
            'id': 'h2spec-107',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 80',
        },

        {
            'id': 'curl-108',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8095/ '
        },

        {
            'id': 'curl-109',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.7:8095/ '
        },

        {
            'id': 'h2spec-110',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-111',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8095/ '
        },

        {
            'id': 'h2spec-112',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6595',
        },

        {
            'id': 'h2spec-113',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 8096',
        },

        {
            'id': 'h2spec-114',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 80',
        },

        {
            'id': 'curl-115',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8096/ '
        },

        {
            'id': 'curl-116',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.7:8096/ '
        },

        {
            'id': 'h2spec-117',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-118',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8096/ '
        },

        {
            'id': 'h2spec-119',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6596',
        },

        {
            'id': 'h2spec-120',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 8097',
        },

        {
            'id': 'h2spec-121',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 80',
        },

        {
            'id': 'curl-122',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8097/ '
        },

        {
            'id': 'curl-123',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.7:8097/ '
        },

        {
            'id': 'h2spec-124',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-125',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8097/ '
        },

        {
            'id': 'h2spec-126',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6597',
        },

        {
            'id': 'h2spec-127',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 8098',
        },

        {
            'id': 'h2spec-128',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 80',
        },

        {
            'id': 'curl-129',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8098/ '
        },

        {
            'id': 'curl-130',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.7:8098/ '
        },

        {
            'id': 'h2spec-131',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-132',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8098/ '
        },

        {
            'id': 'h2spec-133',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6598',
        },

        {
            'id': 'h2spec-134',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 8099',
        },

        {
            'id': 'h2spec-135',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.7 -p 80',
        },

        {
            'id': 'curl-136',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8099/ '
        },

        {
            'id': 'curl-137',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.7:8099/ '
        },

        {
            'id': 'h2spec-138',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-139',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8099/ '
        },

        {
            'id': 'h2spec-140',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6599',
        },

        {
            'id': 'h2spec-141',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 8100',
        },

        {
            'id': 'h2spec-142',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 80',
        },

        {
            'id': 'curl-143',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8100/ '
        },

        {
            'id': 'curl-144',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.8:8100/ '
        },

        {
            'id': 'h2spec-145',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-146',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8100/ '
        },

        {
            'id': 'h2spec-147',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6600',
        },

        {
            'id': 'h2spec-148',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 8101',
        },

        {
            'id': 'h2spec-149',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 80',
        },

        {
            'id': 'curl-150',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8101/ '
        },

        {
            'id': 'curl-151',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.8:8101/ '
        },

        {
            'id': 'h2spec-152',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-153',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8101/ '
        },

        {
            'id': 'h2spec-154',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6601',
        },

        {
            'id': 'h2spec-155',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 8102',
        },

        {
            'id': 'h2spec-156',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 80',
        },

        {
            'id': 'curl-157',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8102/ '
        },

        {
            'id': 'curl-158',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.8:8102/ '
        },

        {
            'id': 'h2spec-159',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-160',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8102/ '
        },

        {
            'id': 'h2spec-161',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6602',
        },

        {
            'id': 'h2spec-162',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 8103',
        },

        {
            'id': 'h2spec-163',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 80',
        },

        {
            'id': 'curl-164',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8103/ '
        },

        {
            'id': 'curl-165',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.8:8103/ '
        },

        {
            'id': 'h2spec-166',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-167',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8103/ '
        },

        {
            'id': 'h2spec-168',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6603',
        },

        {
            'id': 'h2spec-169',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 8104',
        },

        {
            'id': 'h2spec-170',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 127.0.1.8 -p 80',
        },

        {
            'id': 'curl-171',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8104/ '
        },

        {
            'id': 'curl-172',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf https://127.0.2.8:8104/ '
        },

        {
            'id': 'h2spec-173',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh 0.0.0.0 -p 443',
        },

        {
            'id': 'curl-174',
            'type': 'external',
            'binary': 'curl',
            'ssl': False,
            'cmd_args': '-Ikf http://[::1]:8104/ '
        },

        {
            'id': 'h2spec-175',
            'type': 'external',
            'binary': 'h2spec',
            'ssl': True,
            'cmd_args': '-tkh [::1] -p 6604',
        },

    ]

    tempesta = {
        'config': """
            listen 127.0.2.4:8080 proto=https;
            listen [::1]:8084;
            listen [::1]:8085;
            listen [::1]:6603 proto=h2;
            listen [::1]:6595 proto=h2;
            listen 127.0.1.5:8089 proto=h2;
            listen 127.0.2.4:8083 proto=https;
            listen [::1]:6588 proto=h2;
            listen [::1]:8097;
            listen [::1]:8102;
            listen [::1]:6598 proto=h2;
            listen [::1]:6599 proto=h2;
            listen 127.0.1.8:8101 proto=h2;
            listen 127.0.1.4:8081 proto=h2;
            listen 127.0.1.6:8093 proto=h2;
            listen [::1]:6581 proto=h2;
            listen [::1]:8093;
            listen 127.0.2.6:8093 proto=https;
            listen [::1]:8100;
            listen [::1]:8089;
            listen 127.0.1.7:8097 proto=h2;
            listen 127.0.2.7:8096 proto=https;
            listen [::1]:8081;
            listen 127.0.2.7:8095 proto=https;
            listen [::1]:6600 proto=h2;
            listen [::1]:8087;
            listen [::1]:6582 proto=h2;
            listen [::1]:8094;
            listen 127.0.2.4:8081 proto=https;
            listen [::1]:8096;
            listen 127.0.2.8:8104 proto=https;
            listen 127.0.1.5:8087 proto=h2;
            listen [::1]:8090;
            listen 127.0.1.5:8085 proto=h2;
            listen [::1]:8080;
            listen 127.0.1.7:8098 proto=h2;
            listen 127.0.2.5:8087 proto=https;
            listen 127.0.1.5 proto=h2;
            listen 127.0.2.6:8092 proto=https;
            listen 127.0.1.7:8096 proto=h2;
            listen [::1]:8092;
            listen 127.0.1.6:8091 proto=h2;
            listen [::1]:8086;
            listen [::1]:8104;
            listen 127.0.2.4:8084 proto=https;
            listen 127.0.2.7:8098 proto=https;
            listen [::1]:8103;
            listen 127.0.1.7 proto=h2;
            listen [::1]:6590 proto=h2;
            listen [::1]:8101;
            listen 127.0.1.6 proto=h2;
            listen [::1]:8098;
            listen [::1]:8091;
            listen 127.0.2.6:8090 proto=https;
            listen 127.0.1.4:8080 proto=h2;
            listen 127.0.2.8:8101 proto=https;
            listen [::1]:6597 proto=h2;
            listen [::1]:6591 proto=h2;
            listen [::1]:6601 proto=h2;
            listen 127.0.1.7:8099 proto=h2;
            listen [::1]:6593 proto=h2;
            listen 127.0.1.6:8094 proto=h2;
            listen [::1]:6592 proto=h2;
            listen [::1]:8095;
            listen [::1]:6586 proto=h2;
            listen [::1]:6583 proto=h2;
            listen [::1]:6580 proto=h2;
            listen 127.0.1.7:8095 proto=h2;
            listen 127.0.2.6:8094 proto=https;
            listen 127.0.1.8:8104 proto=h2;
            listen [::1]:6602 proto=h2;
            listen 127.0.1.4:8083 proto=h2;
            listen [::1]:6596 proto=h2;
            listen 127.0.1.5:8088 proto=h2;
            listen [::1]:6584 proto=h2;
            listen 127.0.1.8:8103 proto=h2;
            listen 127.0.1.8:8102 proto=h2;
            listen 127.0.1.4 proto=h2;
            listen [::1]:8083;
            listen 127.0.2.8:8100 proto=https;
            listen 127.0.2.5:8089 proto=https;
            listen 127.0.2.8:8102 proto=https;
            listen 127.0.1.6:8092 proto=h2;
            listen 127.0.1.8 proto=h2;
            listen 127.0.2.6:8091 proto=https;
            listen [::1]:6587 proto=h2;
            listen 127.0.1.4:8082 proto=h2;
            listen [::1]:8088;
            listen [::1]:6589 proto=h2;
            listen 127.0.1.5:8086 proto=h2;
            listen [::1]:8099;
            listen 127.0.2.5:8085 proto=https;
            listen 127.0.1.8:8100 proto=h2;
            listen 127.0.2.8:8103 proto=https;
            listen 127.0.1.6:8090 proto=h2;
            listen [::1]:6585 proto=h2;
            listen 127.0.2.4:8082 proto=https;
            listen [::1]:6594 proto=h2;
            listen [::1]:8082;
            listen 443 proto=h2;
            listen 127.0.1.4:8084 proto=h2;
            listen [::1]:6604 proto=h2;
            listen 127.0.2.7:8099 proto=https;
            listen 127.0.2.5:8088 proto=https;
            listen 127.0.2.7:8097 proto=https;
            listen 127.0.2.5:8086 proto=https;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost tempesta-cat {
                proxy_pass default;
            }

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;

            http_chain {
                -> tempesta-cat;
            }
        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

    def test_multiple_listeners_success(self):

        # h2spec
        for cli in self.clients:
            if cli[ID].startswith('h2spec'):
                h2spec = self.get_client(
                    cli[ID],
                )
                h2spec.options.append(H2SPEC_EXTRA_SETTINGS)

        self.start_all()

        for cli in self.clients:

            # h2spec
            if cli[ID].startswith('h2spec'):
                h2spec = self.get_client(
                    cli[ID],
                )
                self.wait_while_busy(h2spec)
                h2spec.stop()
                self.assertIn(
                    H2SPEC_OK,
                    h2spec.response_msg,
                )

            # curl
            if cli[ID].startswith('curl'):
                curl = self.get_client(
                    cli[ID],
                )
                curl.start()
                self.wait_while_busy(curl)
                curl.stop()
                self.assertIn(
                    STATUS_OK,
                    curl.response_msg,
                )
                curl.stop()
