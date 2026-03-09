"""H2 tests for sched automatic weight re-calculation. See test_ratio_dynamic_recalc.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, REQUESTS_COUNT, THREADS
from tests.sched import test_ratio_dynamic_recalc


class RatioDynamicH2(test_ratio_dynamic_recalc.RatioDynamic):
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


class RatioDynamicMinH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicMin):
    async def test_load_distribution(self):
        await super(RatioDynamicMinH2, self).test_load_distribution()


class RatioDynamicMaxH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicMax):
    async def test_load_distribution(self):
        await super(RatioDynamicMaxH2, self).test_load_distribution()


class RatioDynamicAvH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicAv):
    async def test_load_distribution(self):
        await super(RatioDynamicAvH2, self).test_load_distribution()


class RatioDynamicPercH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicPerc):
    async def test_load_distribution(self):
        await super(RatioDynamicPercH2, self).test_load_distribution()


class RatioPredictH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredict):
    async def test_load_distribution(self):
        await super(RatioPredictH2, self).test_load_distribution()


class RatioPredictMinH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictMin):
    async def test_load_distribution(self):
        await super(RatioPredictMinH2, self).test_load_distribution()


class RatioPredictMaxH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictMax):
    async def test_load_distribution(self):
        await super(RatioPredictMaxH2, self).test_load_distribution()


class RatioPredictAvH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictAv):
    async def test_load_distribution(self):
        await super(RatioPredictAvH2, self).test_load_distribution()


class RatioPredictPerc(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictPerc):
    async def test_load_distribution(self):
        await super(RatioPredictPerc, self).test_load_distribution()
