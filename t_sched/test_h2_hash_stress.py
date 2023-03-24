"""H2 tests for sched hash. See test_hash_stress.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS
from t_sched import test_hash_stress


class BindToServerH2(test_hash_stress.BindToServer):
    clients = [
        {
            "id": "client",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    def test_hash(self):
        super(BindToServerH2, self).test_hash()


class BindToServerFailoveringH2(BindToServerH2, test_hash_stress.BindToServerFailovering):
    def test_hash(self):
        super(BindToServerFailoveringH2, self).test_hash()
