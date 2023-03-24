"""H2 tests for sched hash. See test_hash_func.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_sched import test_hash_func


class HashSchedulerH2(test_hash_func.HashScheduler):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    @staticmethod
    def _generate_request(uri):
        return [
            (":authority", "example.com"),
            (":path", f"/resource-{uri}"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

    def test_hash_scheduler(self):
        super(HashSchedulerH2, self).test_hash_scheduler()
