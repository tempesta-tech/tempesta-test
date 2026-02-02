"""Tests for `framework.docker_server.DockerServer`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from test_suite import tester


class TestDockerServer(tester.TempestaTest):
    response_body = "a" * 100

    backends = [
        {
            "id": "python_simple_server",
            "type": "docker",
            "image": "python",
            "ports": {8000: 8000},
            "cmd_args": "-m http.server",
        },
        {
            "id": "python_hello",
            "type": "docker",
            "image": "python",
            "ports": {8001: 8000},
            "cmd_args": f"hello.py --body {response_body}",
        },
        {
            "id": "httpbin",
            "type": "docker",
            "image": "httpbin",
            "ports": {8002: 8000},
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

            vhost python-simple-server {
                proxy_pass python-simple-server;
            }

            vhost python-hello {
                proxy_pass python-hello;
            }

            vhost httpbin {
                proxy_pass httpbin;
            }


            http_chain {
              host == "python-simple-server" -> python-simple-server;
              host == "python-hello" -> python-hello;
              host == "httpbin" -> httpbin;
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
            self.assertEqual(response.stdout, self.response_body)

        with self.subTest("httpbin"):
            response = self.get_response("httpbin", "/status/202")
            self.assertEqual(response.status, 202)


class TestHealthCheck(tester.TempestaTest):
    backends = [
        {
            "id": "default",
            "type": "docker",
            "image": "python",
            "ports": {8000: 8000},
            "cmd_args": "hello.py",
        },
    ]

    tempesta = {
        "config": """
        listen 80 proto=http;
        server ${server_ip}:8000;
        """
    }

    def test_service_long_start(self):
        """
        Test that requests succeed when web server start is delayed
        from the time the container was started.
        """
        server = self.get_server("default")
        server.cmd_args = "-c 'import time ; time.sleep(3); import hello'"

        server.start()
        self.assertEqual(server.health_status, "starting")

        self.start_tempesta()

        self.assertFalse(server.wait_for_connections(timeout=1))
        self.assertTrue(server.wait_for_connections(timeout=3))
        self.assertEqual(server.health_status, "healthy")

    def test_unhealthy_server(self):
        server = self.get_server("default")
        server.cmd_args = "-c 'import time ; time.sleep(10)'"

        server.start()

        self.assertEqual(server.health_status, "starting")
        self.assertFalse(server.wait_for_connections(timeout=7))
        self.assertEqual(server.health_status, "unhealthy")

    def test_override_default_healthcheck(self):
        server = self.get_server("default")
        server.options = "--health-interval 0.1s --health-cmd 'exit 0'"
        server.cmd_args = "-c 'import time ; time.sleep(10)'"

        server.start()

        server.wait_for_connections(timeout=1)
        self.assertEqual(server.health_status, "healthy")
