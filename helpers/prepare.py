__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from . import remote

def configure_tcp():
    """ Configuring TCP for faster reuse the same TCP ports.
    A lot of sockets are created in tests and bound to specific ports.
    Release them quicker to reuse the ports in the next test case. """

    for node in [remote.server, remote.tempesta, remote.client]:
        node.run_cmd("sysctl -w net.ipv4.tcp_tw_reuse=1")
        node.run_cmd("sysctl -w net.ipv4.tcp_fin_timeout=10")

    if remote.server.host != remote.tempesta.host:
        remote.server.run_cmd("sysctl -w net.core.somaxconn=131072")
        remote.server.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
    # tempesta somaxconn sysctl setups from tempesta.sh
    remote.tempesta.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
    if remote.client.host != remote.tempesta.host:
        remote.client.run_cmd("sysctl -w net.core.somaxconn=131072")
        remote.client.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
    # temporary solution, while deproxy runs on 'host' instead clent and server
    if remote.host.host != remote.tempesta.host:
        remote.host.run_cmd("sysctl -w net.core.somaxconn=131072")
        remote.host.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")


def configure():
    """ Prepare nodes before running tests """

    configure_tcp()
