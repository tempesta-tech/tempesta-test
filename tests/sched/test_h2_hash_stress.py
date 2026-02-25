"""H2 tests for sched hash. See test_hash_stress.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, DURATION, THREADS
from tests.sched import test_hash_stress


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
                f" --max-concurrent-streams 10"  # 10 streams to not overflow forwarding queue
                f" --duration {DURATION}"
            ),
        },
    ]

    async def test_hash(self):
        await super(BindToServerH2, self).test_hash()


class BindToServerFailoveringH2(BindToServerH2, test_hash_stress.BindToServerFailovering):
    async def test_hash(self):
        await super(BindToServerFailoveringH2, self).test_hash()
