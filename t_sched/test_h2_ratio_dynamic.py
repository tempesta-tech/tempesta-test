"""H2 tests for sched dynamic and predict. See test_ratio_dynamic.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, REQUESTS_COUNT, THREADS
from t_sched import test_ratio_dynamic


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

    def test_load_distribution(self):
        super(RatioDynamicH2, self).test_load_distribution()


class RatioDynamicMinH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicMin):
    def test_load_distribution(self):
        super(RatioDynamicMinH2, self).test_load_distribution()


class RatioDynamicMaxH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicMax):
    def test_load_distribution(self):
        super(RatioDynamicMaxH2, self).test_load_distribution()


class RatioDynamicAvH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicAv):
    def test_load_distribution(self):
        super(RatioDynamicAvH2, self).test_load_distribution()


class RatioDynamicPercH2(RatioDynamicH2, test_ratio_dynamic.RatioDynamicPerc):
    def test_load_distribution(self):
        super(RatioDynamicPercH2, self).test_load_distribution()


class RatioPredictH2(RatioDynamicH2, test_ratio_dynamic.RatioPredict):
    def test_load_distribution(self):
        super(RatioPredictH2, self).test_load_distribution()


class RatioPredictMinH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictMin):
    def test_load_distribution(self):
        super(RatioPredictMinH2, self).test_load_distribution()


class RatioPredictMaxH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictMax):
    def test_load_distribution(self):
        super(RatioPredictMaxH2, self).test_load_distribution()


class RatioPredictAvH2(RatioDynamicH2, test_ratio_dynamic.RatioPredictAv):
    def test_load_distribution(self):
        super(RatioPredictAvH2, self).test_load_distribution()


class RatioPredictPerc(RatioDynamicH2, test_ratio_dynamic.RatioPredictPerc):
    def test_load_distribution(self):
        super(RatioPredictPerc, self).test_load_distribution()
