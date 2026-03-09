"""H2 tests for ratio static scheduler. See test_ratio_static.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, DURATION, THREADS
from tests.sched import test_ratio_static


class RatioH2(test_ratio_static.Ratio):
    clients = [
        {
            "id": "client",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443/"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams 10"  # 10 streams to not overflow forwarding queue
                f" --duration {DURATION}"
            ),
        }
    ]

    async def test_load_distribution(self):
        await super(RatioH2, self).test_load_distribution()


class RatioVariableConnsH2(RatioH2, test_ratio_static.RatioVariableConns):
    async def test_load_distribution(self):
        await super(RatioVariableConnsH2, self).test_load_distribution()
