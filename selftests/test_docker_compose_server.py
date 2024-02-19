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

