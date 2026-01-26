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

    def test_load_distribution(self):
        super(RatioDynamicH2, self).test_load_distribution()


class RatioDynamicMinH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicMin):
    def test_load_distribution(self):
        super(RatioDynamicMinH2, self).test_load_distribution()


class RatioDynamicMaxH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicMax):
    def test_load_distribution(self):
        super(RatioDynamicMaxH2, self).test_load_distribution()


class RatioDynamicAvH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicAv):
    def test_load_distribution(self):
        super(RatioDynamicAvH2, self).test_load_distribution()


class RatioDynamicPercH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioDynamicPerc):
    def test_load_distribution(self):
        super(RatioDynamicPercH2, self).test_load_distribution()


class RatioPredictH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredict):
    def test_load_distribution(self):
        super(RatioPredictH2, self).test_load_distribution()


class RatioPredictMinH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictMin):
    def test_load_distribution(self):
        super(RatioPredictMinH2, self).test_load_distribution()


class RatioPredictMaxH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictMax):
    def test_load_distribution(self):
        super(RatioPredictMaxH2, self).test_load_distribution()


class RatioPredictAvH2(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictAv):
    def test_load_distribution(self):
        super(RatioPredictAvH2, self).test_load_distribution()


class RatioPredictPerc(RatioDynamicH2, test_ratio_dynamic_recalc.RatioPredictPerc):
    def test_load_distribution(self):
        super(RatioPredictPerc, self).test_load_distribution()
