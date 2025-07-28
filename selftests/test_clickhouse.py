__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.remote import client
from test_suite import tester


class TestClickhouse(tester.TempestaTest):
    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            access_log mmap logger_config=${tfw_logger_logger_config};
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_wait_while_logger_start(self):
        """
        Test that documents issue #2314 - logs missing during first second of startup.
        This test verifies that logs are not lost in clickhouse immediately after startup.
        """
        self.start_all_clients()
        self.deproxy_manager.start()

        self.start_tempesta()
        self.get_tempesta().wait_while_logger_start()

        client = self.get_client("deproxy")
        client.start()

        client.send_request(client.create_request(method="GET", headers=[]), "502")

        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 1)
        self.assertEqual(self.loggers.clickhouse.access_log_last_message().status, 502)

    def test_create_table(self):
        self.start_tempesta()
        self.deproxy_manager.start()

        client = self.get_client("deproxy")
        request = client.create_request(uri="/", headers=[])

        def wait():
            client.restart()
            try:
                client.send_request(request)
                self.get_tempesta().wait_while_logger_start()
            except clickhouse_connect.driver.exceptions.DatabaseError:
                ...

        self.assertWaitUntilTrue(wait)
