import string

from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class CustomTemplate(string.Template):
    delimiter = "&"


@marks.parameterize_class(
    [
        {"name": "MethodHEADStatus200", "method": "HEAD", "status": "200"},
        {"name": "MethodPOSTStatus200", "method": "POST", "status": "200"},
        {"name": "MethodDeleteStatus200", "method": "DELETE", "status": "200"},
        {"name": "MethodDeleteStatus204", "method": "DELETE", "status": "204"},
        {"name": "MethodPatchStatus200", "method": "PATCH", "status": "200"},
        {
            "name": "MethodPUTStatus200",
            "method": "PUT",
            "status": "200",
        },
        {
            "name": "MethodPUTStatus204",
            "method": "PUT",
            "status": "204",
        },
    ]
)
class TestMissedContentLengthInMethod(tester.TempestaTest):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": (
                "pid ${pid}; "
                "worker_processes  auto; "
                "events { "
                "   worker_connections   1024; "
                "   use epoll; "
                "} "
                "http { "
                "   keepalive_timeout ${server_keepalive_timeout}; "
                "   keepalive_requests ${server_keepalive_requests}; "
                "   access_log off; "
                "   server { "
                "       listen        ${server_ip}:8000; "
                "       location / { "
                "          add_header Content-Length 0; "
                "          return &response_status; "
                "       } "
                "       location /nginx_status { "
                "           stub_status on; "
                "       } "
                "   } "
                "} "
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            access_log dmesg;
            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]
    method: str = None
    status: str = None

    def setUp(self):
        nginx_conf = self.backends[0]["config"]
        self.backends[0]["config"] = CustomTemplate(nginx_conf).substitute(
            response_status=self.status,
        )
        super().setUp()

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method=self.method, headers=[]),
            expected_status_code=self.status,
        )
        self.assertEqual(
            client.last_response.headers["content-length"],
            "0",
            msg="Tempesta should proxy the Content-Length header for the 204 status code also",
        )


@marks.parameterize_class(
    [
        {
            "name": "POST",
            "method": "POST",
        },
        {
            "name": "PUT",
            "method": "PUT",
        },
        {
            "name": "PATCH",
            "method": "PATCH",
        },
        {
            "name": "DELETE",
            "method": "DELETE",
        },
    ]
)
class TestMissedContentType(tester.TempestaTest):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": (
                "pid ${pid}; "
                "worker_processes  auto; "
                "events { "
                "   worker_connections   1024; "
                "   use epoll; "
                "} "
                "http { "
                "   keepalive_timeout ${server_keepalive_timeout}; "
                "   keepalive_requests ${server_keepalive_requests}; "
                "   access_log off; "
                "   server { "
                "       listen        ${server_ip}:8000; "
                "       location / { "
                "          add_header Content-Type 'text/html; charset=utf-8'; "
                "          return 200; "
                "       } "
                "       location /nginx_status { "
                "           stub_status on; "
                "       } "
                "   } "
                "} "
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            access_log dmesg;
            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            http_allow_empty_body_content_type true;
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]
    method: str = None

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method=self.method, headers=[]),
            expected_status_code="200",
        )
        self.assertEqual(
            client.last_response.headers["content-type"],
            "text/html; charset=utf-8",
            msg="Tempesta should proxy the Content-Type header for the CRUD method with empty body also",
        )
