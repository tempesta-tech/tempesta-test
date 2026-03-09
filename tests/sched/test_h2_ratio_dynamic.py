"""H2 tests for sched dynamic and predict. See test_ratio_dynamic.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, REQUESTS_COUNT, THREADS
from tests.sched import test_ratio_dynamic


class RatioDynamicH2(test_ratio_dynamic.RatioDynamic):
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
            ),
        },
    ]

    async def test_load_distribution(self):
        await super(RatioDynamicH2, self).test_load_distribution()


class RatioDynamicMinH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicMin):
    async def test_load_distribution(self):
        await super(RatioDynamicMinH2, self).test_load_distribution()


class RatioDynamicMaxH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicMax):
    async def test_load_distribution(self):
        await super(RatioDynamicMaxH2, self).test_load_distribution()


class RatioDynamicAvH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicAv):
    async def test_load_distribution(self):
        await super(RatioDynamicAvH2, self).test_load_distribution()


class RatioDynamicPercH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicPerc):
    async def test_load_distribution(self):
        await super(RatioDynamicPercH2, self).test_load_distribution()


class RatioPredictH2(RatioDynamicH2, test_ratio_dynamic.RatioPredict):
    async def test_load_distribution(self):
        await super(RatioPredictH2, self).test_load_distribution()


class RatioPredictMinH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictMin):
    async def test_load_distribution(self):
        await super(RatioPredictMinH2, self).test_load_distribution()


class RatioPredictMaxH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictMax):
    async def test_load_distribution(self):
        await super(RatioPredictMaxH2, self).test_load_distribution()


class RatioPredictAvH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictAv):
    async def test_load_distribution(self):
        await super(RatioPredictAvH2, self).test_load_distribution()


class RatioPredictPercH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictPerc):
    async def test_load_distribution(self):
        await super(RatioPredictPercH2, self).test_load_distribution()
