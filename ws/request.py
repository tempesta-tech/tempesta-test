#! /usr/bin/python3

import requests

host = "localhost"
port = 9080

headers_ = {
    "Host": host,
    "Connection": "Upgrade",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Upgrade": "websocket",
    "Origin": "null",
    "Sec-WebSocket-Version": "13",
    "Accept-Encoding": "gzip, deflate",
    "Sec-WebSocket-Key": "V4wPm2Z/oOIUvp+uaX3CFQ==",
    "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
}


def exclude_key(d, keys):
    return {x: d[x] for x in d if x not in keys}


def test_no_upgrade():
    r = requests.get(f'http://{host}:{port}', auth=('user', 'pass'),
                     headers=exclude_key(headers_, "Upgrade"), data="message")

    print(r)
    print(r.status_code)
    print(r.text)


def test_no_connection():
    r = requests.get(f'http://{host}:{port}', auth=('user', 'pass'),
                     headers=exclude_key(headers_, "Connection"), data="message")

    print(r)
    print(r.status_code)
    print(r.text)


test_no_upgrade()
test_no_connection()
