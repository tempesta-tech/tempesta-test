"""Tests for `framework.docker_server.DockerServer`."""
import unittest

from framework import docker_server, tester
from helpers import tf_cfg


class TestDockerServer(tester.TempestaTest):

    backends = [
        {
            "id": "python_simple_server",
            "type": "docker",
            "ports": {8000: 8000},
            "tag": "python",
            "cmd_args": "-m http.server",
        },
        {
            "id": "python_hello",
            "type": "docker",
            "ports": {8001: 8080},
            "tag": "python",
            "cmd_args": "hello.py",
        },
        {
            "id": "httpbin",
            "type": "docker",
            "ports": {8002: 8000},
            "tag": "httpbin",
        },
        {
            "id": "wordpress",
            "type": "docker",
            "ports": {8003: 80},
            "tag": "wordpress",
            "env": {
                "WP_HOME": "http://${tempesta_ip}",
                "WP_SITEURL": "http://${tempesta_ip}",
            },
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

            srv_group python-simple-server { server ${server_ip}:8000; }
            srv_group python-hello { server ${server_ip}:8001; }
            srv_group httpbin { server ${server_ip}:8002; }
            srv_group wordpress { server ${server_ip}:8003; }

            vhost python-simple-server {
                proxy_pass python-simple-server;
            }

            vhost python-hello {
                proxy_pass python-hello;
            }

            vhost httpbin {
                proxy_pass httpbin;
            }

            vhost wordpress {
                proxy_pass wordpress;
            }

            http_chain {
              host == "python-simple-server" -> python-simple-server;
              host == "python-hello" -> python-hello;
              host == "httpbin" -> httpbin;
              host == "wordpress" -> wordpress;
            }
        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(5))

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

        with self.subTest("python -m http.server"):
            response = self.get_response("python-simple-server")
            self.assertEqual(response.status, 200)
            self.assertIn("Directory listing", response.stdout)

        with self.subTest("python hello.py"):
            response = self.get_response("python-hello")
            self.assertEqual(response.status, 200)
            self.assertEqual(response.stdout, "Hello")

        with self.subTest("httpbin"):
            response = self.get_response("httpbin", "/status/202")
            self.assertEqual(response.status, 202)

        with self.subTest("wordpress"):
            response = self.get_response("wordpress")
            self.assertEqual(response.status, 200)
            self.assertTrue(response.headers["x-powered-by"].startswith("PHP/"))
            link = response.headers["link"]
            self.assertTrue(link.startswith(f"<http://{tf_cfg.cfg.get('Tempesta', 'ip')}/"), link)


    def test_service_long_start(self):
        """
        Test that requests succeed when web server start is delayed
        from the time the container was started.
        """
        server = self.get_server("python_hello")
        server.cmd_args = "-c 'import time ; time.sleep(5); import hello'"

        server.start()
        self.start_tempesta()

        self.assertFalse(server.wait_for_connections(timeout=1))
        self.assertTrue(server.wait_for_connections(timeout=6))

        response = self.get_response("python-hello")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.stdout, "Hello")
