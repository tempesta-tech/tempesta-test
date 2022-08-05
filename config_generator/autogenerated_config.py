"""
198.3.3.3:8765 proto=https;
202.0.2.1:8764 proto=h2;

srv_group default {
    server 127.0.0.1:80;
}

vhost tempesta-cat {
    proxy_pass default;
}

tls_match_any_server_name;
tls_certificate root.crt;
tls_certificate_key root.key;

cache 0;
cache_fulfill * *;
block_action attack reply;

http_chain {
    -> tempesta-cat;
}

"""