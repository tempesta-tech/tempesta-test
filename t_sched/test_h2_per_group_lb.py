"""H2 test per group load balancers. See test_per_group_lb.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS
from t_sched import test_per_group_lb


class AllDefaultsH2(test_per_group_lb.AllDefaults):
    clients = [
        {
            "id": "client_vhost_1",
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
        {
            "id": "client_vhost_2",
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

    def test_inherit(self):
        super(AllDefaultsH2, self).test_inherit()


class RedefineGlobalSchedH2(AllDefaultsH2, test_per_group_lb.RedefineGlobalSched):
    def test_inherit(self):
        super(RedefineGlobalSchedH2, self).test_inherit()


class RedefineGroupSchedH2(AllDefaultsH2, test_per_group_lb.RedefineGroupSched):
    def test_inherit(self):
        super(RedefineGroupSchedH2, self).test_inherit()


class RedefineAllSchedsH2(AllDefaultsH2, test_per_group_lb.RedefineAllScheds):
    def test_inherit(self):
        super(RedefineAllSchedsH2, self).test_inherit()


class LateRedefineGlobalSchedH2(AllDefaultsH2, test_per_group_lb.LateRedefineGlobalSched):
    def test_inherit(self):
        super(LateRedefineGlobalSchedH2, self).test_inherit()
