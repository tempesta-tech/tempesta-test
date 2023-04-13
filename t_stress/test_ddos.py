__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from framework import tester
from helpers import remote, tf_cfg

CLIENTS_N = 2
IMAGE_NAME = "mhddos"
NETWORK_NAME = "ddos_network"
PRE_SUBNET = "10.5.0"
MHDDOS_PATH = "/usr/mhddos"
TEST_METHOD = "POST"
TEMPESTA_IP = tf_cfg.cfg.get("Tempesta", "ip")
SOCKET_TYPE = "1"  # for HTTP requests
THREADS = tf_cfg.cfg.get("General", "stress_threads")
PROXY_LIST = "./proxy.txt"
RPS = tf_cfg.cfg.get("General", "stress_requests_count")
DURATION = tf_cfg.cfg.get("General", "duration")


class TestDDoSL7(tester.TempestaTest):
    tempesta = {
        "config": """
cache 0;
cache_fulfill * *;
cache_methods GET HEAD;
cache_ttl 3600;

listen 443 proto=https;
listen 80;

srv_group default {server 127.0.0.1:8000;}

srv_group auth {server 127.0.0.1:8000;}

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

req_hdr_add X-Forwarded-Proto "https";
resp_hdr_set Strict-Transport-Security "max-age=31536000; includeSubDomains";

vhost tempesta-tech.com {
        resp_hdr_set Cache-Control;
        proxy_pass default;
}

vhost default {
        proxy_pass default;
        nonidempotent GET * *;
        nonidempotent HEAD * *;
        nonidempotent POST * *;
}

vhost auth {proxy_pass auth;}

vhost wp-auth {
        req_hdr_add Location "wp-admin";
        proxy_pass auth;
}

frang_limits {
        http_method_override_allowed true;
        http_methods post put get;
}

cache_purge;
cache_purge_acl 3.72.94.204 127.0.0.1;

block_action attack reply;
block_action error reply;

http_chain admin {
        mark == 23  -> default;
        -> auth;
}

http_chain {
	# Set cache_ttl for speciefic locations
	uri == "/blog/*" -> cache_ttl = 1;
    uri == "/knowledge-base/*" -> cache_ttl = 600;
        
	# Set Security
	mark == 23 -> default;
    uri == "*/google/*" -> auth;
    uri == "*/wp-admin/*" -> admin;
    uri == "*/wp-login.php*" -> admin;
    uri == "*/phpmyadmin*" -> admin;
    -> default;
}
        """
    }

    backends = [
        {
            "id": "wordpress",
            "type": "docker",
            "image": "wordpress",
            "ports": {8000: 80},
            "env": {
                "WP_HOME": "http://${tempesta_ip}",
                "WP_SITEURL": "http://${tempesta_ip}",
            },
        },
    ]

    def setUp(self):
        self.containers = []
        super(TestDDoSL7, self).setUp()

    def test_ddos_post_method(self):
        self.start_all_services(client=False)

        self.__create_docker_image()
        self.__create_docker_network()
        self.__create_docker_containers()
        self.__start_all_containers()

        # wait all containers
        time.sleep(int(DURATION) + 10)

    def tearDown(self):
        # remove docker containers
        for container_name in self.containers:
            try:
                remote.client.run_cmd(cmd=f"docker rm {container_name}")
            except:
                continue
        # remove docker image
        try:
            remote.client.run_cmd(f"docker rmi {IMAGE_NAME}")
        except:
            pass
        # remove docker network
        try:
            remote.client.run_cmd(f"docker network rm {NETWORK_NAME}")
        except:
            pass
        super(TestDDoSL7, self).tearDown()

    @staticmethod
    def __prepare_dockerfile():
        with open(f"{MHDDOS_PATH}/Dockerfile", "r+") as f:
            old_data = f.readlines()
            f.seek(0)
            old_data[-1] = (
                'CMD ["python3", "/app/start.py", '
                + f'"{TEST_METHOD}", '
                + f'"http://{TEMPESTA_IP}", '
                + f'"{SOCKET_TYPE}", '
                + f'"{THREADS}", '
                + f'"{PROXY_LIST}", '
                + f'"{RPS}", '
                + f'"{DURATION}"'
                + "]\n"
            )
            f.writelines(old_data)

    @staticmethod
    def __create_docker_image():
        remote.client.run_cmd(cmd=f"docker build -t {IMAGE_NAME} {MHDDOS_PATH}", timeout=30)

    @staticmethod
    def __create_docker_network():
        remote.client.run_cmd(
            cmd=f"docker network create --subnet={PRE_SUBNET}.0/24 {NETWORK_NAME}"
        )

    def __create_docker_containers(self):
        for step in range(1, CLIENTS_N):
            container_name = f"mhddos_{TEST_METHOD}_{step}"
            try:
                remote.client.run_cmd(
                    cmd=(
                        f"docker create "
                        + f"--ip {PRE_SUBNET}.{step} "
                        + f"--network {NETWORK_NAME} "
                        + f"--name {container_name} "
                        + f"mhddos python3 "
                        + "/app/start.py "
                        + f"{TEST_METHOD} "
                        + f"http://{TEMPESTA_IP}:80 "
                        + f"{SOCKET_TYPE} "
                        + f"{THREADS} "
                        + f"{PROXY_LIST} "
                        + f"{RPS} "
                        + f"{DURATION}"
                    )
                )
            except Exception as e:
                tf_cfg.dbg(2, f"\tDocker container creation failed: {e}")
                continue
            self.containers.append(container_name)

    def __start_all_containers(self):
        for container_name in self.containers:
            remote.client.run_cmd(cmd=f"docker start {container_name}")
