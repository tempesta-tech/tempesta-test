"""h2 tests for backup server in vhost. See test_backup_server.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_http_rules import test_backup_servers


class HttpRulesBackupServersH2(test_backup_servers.HttpRulesBackupServers):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def test_scheduler(self):
        super(HttpRulesBackupServersH2, self).test_scheduler()
