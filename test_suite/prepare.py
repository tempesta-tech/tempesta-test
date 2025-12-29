__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers import remote


def configure_tcp():
    """
    Configuring TCP for faster reuse the same TCP ports.
    A lot of sockets are created in tests and bound to specific ports.
    Release them quicker to reuse the ports in the next test case.
    """

    # Allow more ephimeral ports, required for a client making many
    # short-living connections.
    remote.server.run_cmd("sysctl -w net.ipv4.tcp_tw_reuse=1")
    remote.server.run_cmd("sysctl -w net.ipv4.tcp_fin_timeout=10")

    # Do not overwrite sysctl settings from tempesta.sh
    if remote.server.host != remote.tempesta.host:
        remote.server.run_cmd("sysctl -w net.core.somaxconn=131072")
        remote.server.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
        
    # The test suite creates a lot of short living TCP connections and we have
    # specific testing logic for DDoS mitigation, so let the suite create many
    # connections.
    remote.tempesta.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
