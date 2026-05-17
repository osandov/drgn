import ipaddress
import re

from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.net import (
    for_each_netdev,
    neigh_table_for_each_neighbor,
    netdev_ipv4_addrs,
    netdev_ipv6_addrs,
    netdev_name,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestNet(CrashCommandTestCase):
    def test_net(self):
        cmd = self.run_crash_command("net")

        self.assertFalse(cmd.stderr)
        self.assertRegex(cmd.stdout, r"(?m)^NET_DEVICE\s+NAME\s+IP ADDRESS\(ES\)$")

        lo = next(
            dev for dev in for_each_netdev(self.prog) if netdev_name(dev) == b"lo"
        )
        ips = ", ".join(str(a) for a in netdev_ipv4_addrs(lo) + netdev_ipv6_addrs(lo))

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{lo.value_():x}\s+"
            rf"{re.escape(escape_ascii_string(netdev_name(lo), escape_backslash=True))}"
            rf"\s+{re.escape(ips)}$",
        )

    def test_net_arp(self):
        neighbors = list(neigh_table_for_each_neighbor(self.prog["arp_tbl"].nht))
        if not neighbors:
            self.skipTest("no ARP entries in neighbor cache")

        cmd = self.run_crash_command("net -a")

        self.assertFalse(cmd.stderr)
        self.assertRegex(
            cmd.stdout,
            r"(?m)^NEIGHBOUR\s+IP ADDRESS\s+HW TYPE\s+HW ADDRESS\s+DEVICE\s+STATE$",
        )

        neigh = neighbors[0]
        ip_addr = str(
            ipaddress.IPv4Address(self.prog.read(neigh.primary_key.address_of_(), 4))
        )
        hw_addr = ":".join(
            f"{b:02x}"
            for b in self.prog.read(neigh.ha.address_of_(), int(neigh.dev.addr_len))
        )
        dev_name = escape_ascii_string(netdev_name(neigh.dev), escape_backslash=True)

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{neigh.value_():x}\s+{re.escape(ip_addr)}\s+.*\s+"
            rf"{re.escape(hw_addr)}\s+{re.escape(dev_name)}\s+.*$",
        )
