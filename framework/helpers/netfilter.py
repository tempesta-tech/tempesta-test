"""Filter for network packets."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from contextlib import contextmanager
from typing import Any, Generator, Optional

from framework.helpers import remote


class _Filter(object):
    """Control iptables on target node (Client, Server or Tempesta)."""

    directions = ["INPUT", "OUTPUT", "FORWARD"]

    def __init__(self, node: remote.ANode, direction: list[str] = None):
        self._node: remote.ANode = node
        self._direction: Optional[list[str]] = direction if direction else self.directions[0]
        self._chain = f"TfwTestChain{self._node.type}{self._direction}"
        self.init_chains()

    def init_chains(self) -> None:
        """Create custom chain and insert before every other chain or rule."""
        self._node.run_cmd(f"iptables -N {self._chain}")
        self._node.run_cmd(f"iptables -I {self._direction} -j {self._chain}")

    def block_ports(self, ports: list[int]) -> None:
        """Block given list of ports."""
        for port in ports:
            self._node.run_cmd(f"iptables -A {self._chain} -p tcp --dport {port} -j DROP")

    def clean(self) -> None:
        """Remove all rules from custom chain."""
        self._node.run_cmd(f"iptables -F {self._chain}")

    def clean_up(self) -> None:
        """Full cleanup: completely remove custom rule."""
        self.clean()
        self._node.run_cmd(f"iptables -D {self._direction} -j {self._chain}")
        self._node.run_cmd(f"iptables -X {self._chain}")


@contextmanager
def block_ports_on_node(
    *, blocked_ports: list[int], node: remote.ANode
) -> Generator[_Filter, Any, None]:
    netfilter = _Filter(node)

    try:
        netfilter.block_ports(blocked_ports)
        yield netfilter
    finally:
        netfilter.clean_up()
