"""
H2 tests for ratio static scheduler. Each server has random weight. See test_ratio_weight.py.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.tf_cfg import cfg
from t_sched import test_ratio_weight


class RatioH2(test_ratio_weight.Ratio):
    clients = [
        {
            "id": "client",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443/"
                + " --clients {0}".format(cfg.get("General", "concurrent_connections"))
                + " --threads {0}".format(cfg.get("General", "stress_threads"))
                + " --max-concurrent-streams {0}".format(
                    cfg.get("General", "stress_requests_count")
                )
                + " --duration {0}".format(cfg.get("General", "duration"))
            ),
        },
    ]

    def test_load_distribution(self):
        super(RatioH2, self).test_load_distribution()


class RatioVariableConnsH2(RatioH2, test_ratio_weight.RatioVariableConns):
    def test_load_distribution(self):
        super(RatioVariableConnsH2, self).test_load_distribution()
