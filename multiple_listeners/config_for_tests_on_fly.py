# backends = [
#
#     {
#         'id': 'nginx',
#         'type': 'nginx',
#         'port': '8000',
#         'status_uri': 'http://127.0.0.100:8000/nginx_status',
#         'config': """
#             pid ${pid};
#             worker_processes  auto;
#             events {
#                 worker_connections   1024;
#                 use epoll;
#             }
#             http {
#                 keepalive_timeout ${server_keepalive_timeout};
#                 keepalive_requests ${server_keepalive_requests};
#                 sendfile         on;
#                 tcp_nopush       on;
#                 tcp_nodelay      on;
#                 open_file_cache max=1000;
#                 open_file_cache_valid 30s;
#                 open_file_cache_min_uses 2;
#                 open_file_cache_errors off;
#                 error_log /dev/null emerg;
#                 access_log off;
#                 server {
#                     listen        127.0.0.100:8000;
#                     location / {
#                         return 200;
#                     }
#                     location /nginx_status {
#                         stub_status on;
#                     }
#                 }
#             }
#         """,
#     }
#
# ]

# tempesta = {
#     'config': """
#
#         %s
#
#         srv_group default {
#             server 127.0.0.100:8000;
#         }
#
#         vhost tempesta-cat {
#             proxy_pass default;
#         }
#
#         tls_match_any_server_name;
#         tls_certificate ECDSA/tfw-root.crt;
#         tls_certificate_key ECDSA/tfw-root.key;
#
#         cache 0;
#         cache_fulfill * *;
#         block_action attack reply;
#
#         http_chain {
#             -> tempesta-cat;
#         }
#
#     """
# }
