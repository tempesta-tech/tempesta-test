"""Tests for `framework.docker_server.DockerComposeServer`."""
import unittest

from framework import docker_server, tester
from helpers import tf_cfg


class TestDockerComposeServer(tester.TempestaTest):
    backends = [
        {
            "id": "nginx_test",
            "type": "docker_compose",
            "project_name": "nginx_test",
            "ports": [8000],
        },
    ]

    clients = [
        {
            "id": "default",
            "type": "curl",
        },
    ]

    tempesta = {
        "config": """
            listen 80 proto=http;

            srv_group nginx-test { server ${server_ip}:8000; }

            vhost nginx-test {
                proxy_pass nginx-test;
            }

            http_chain {
              host == "nginx-test" -> nginx-test;
            }
        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(10))

    def get_response(self, host, uri="/"):
        client = self.get_client("default")
        client.headers["Host"] = host
        client.set_uri(uri)
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def test_request_to_server_completed(self):
        self.start_all()

        with self.subTest("nginx-test"):
            response = self.get_response("nginx-test")
            self.assertEqual(response.status, 200)
            self.assertIn("nginx", response.stdout)


# class TestHealthCheck(tester.TempestaTest):
#     backends = [
#         {
#             "id": "default",
#             "type": "docker",
#             "image": "python",
#             "ports": {8000: 8000},
#             "cmd_args": "hello.py",
#         },
#     ]

#     tempesta = {
#         "config": """
#         listen 80 proto=http;
#         server ${server_ip}:8000;
#         """
#     }

#     def test_service_long_start(self):
#         """
#         Test that requests succeed when web server start is delayed
#         from the time the container was started.
#         """
#         server = self.get_server("default")
#         server.cmd_args = "-c 'import time ; time.sleep(3); import hello'"

#         server.start()
#         self.assertEqual(server.health_status, "starting")

#         self.start_tempesta()

#         self.assertFalse(server.wait_for_connections(timeout=1))
#         self.assertTrue(server.wait_for_connections(timeout=3))
#         self.assertEqual(server.health_status, "healthy")

#     def test_unhealthy_server(self):
#         server = self.get_server("default")
#         server.cmd_args = "-c 'import time ; time.sleep(10)'"

#         server.start()

#         self.assertEqual(server.health_status, "starting")
#         self.assertFalse(server.wait_for_connections(timeout=7))
#         self.assertEqual(server.health_status, "unhealthy")

#     def test_override_default_healthcheck(self):
#         server = self.get_server("default")
#         server.options = "--health-interval 0.1s --health-cmd 'exit 0'"
#         server.cmd_args = "-c 'import time ; time.sleep(10)'"

#         server.start()

#         server.wait_for_connections(timeout=1)
#         self.assertEqual(server.health_status, "healthy")
