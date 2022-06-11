"""Config for frang.test_host_required.py."""
ERROR_MSG = 'Frang limits warning is not shown'
ERROR_CURL = 'Curl return code is not `0`: {0}.'

RESPONSE_CONTENT = """
HTTP/1.1 200 OK\r\n
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

TEMPESTA_CONF = """
cache 0;
listen 80;

frang_limits {
    http_host_required;
}

server ${server_ip}:8000;
"""

WARN_OLD_PROTO = 'frang: Host header field in protocol prior to HTTP/1.1'
WARN_UNKNOWN = 'frang: Request authority is unknown'
WARN_DIFFER = 'frang: Request authority in URI differs from host header'
WARN_IP_ADDR = 'frang: Host header field contains IP address'

REQUEST_SUCCESS = """
GET / HTTP/1.1\r
Host: tempesta-tech.com\r
\r
GET / HTTP/1.1\r
Host:    tempesta-tech.com     \r
\r
GET http://tempesta-tech.com/ HTTP/1.1\r
Host: tempesta-tech.com\r
\r
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: tempesta-tech.com\r
\r
"""

REQUEST_EMPTY_HOST = """
GET / HTTP/1.1\r
Host: \r
\r
"""

REQUEST_MISMATCH = """
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: example.com\r
\r
"""

REQUEST_EMPTY_HOST_B = """
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: \r
\r
"""

CURL_A = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: tempesta-tech.com"'
CURL_B = '-Ikf -v --http2 https://127.0.0.4:443/'
CURL_C = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: "'
CURL_D = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: example.com"'
CURL_E = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: 127.0.0.1"'
CURL_F = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: [::1]"'

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
    },
]

clients = [
    {
        'id': 'curl-1',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_A,
    },
    {
        'id': 'curl-2',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_B,
    },
    {
        'id': 'curl-3',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_C,
    },
    {
        'id': 'curl-4',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_D,
    },
    {
        'id': 'curl-5',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_E,
    },
    {
        'id': 'curl-6',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_F,
    },
]

tempesta = {
    'config': """
        frang_limits {
            http_host_required;
        }

        listen 127.0.0.4:443 proto=h2;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-cat {
            proxy_pass default;
        }

        tls_match_any_server_name;
        tls_certificate RSA/tfw-root.crt;
        tls_certificate_key RSA/tfw-root.key;

        cache 0;
        cache_fulfill * *;
        block_action attack reply;

        http_chain {
            -> tempesta-cat;
        }
    """,
}
