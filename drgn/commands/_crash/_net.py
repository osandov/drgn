# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "net" command for drgn."""

import argparse
import ipaddress
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands._crash.common import crash_command
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.net import (
    for_each_netdev,
    neigh_table_for_each_neighbor,
    netdev_ipv4_addrs,
    netdev_ipv6_addrs,
    netdev_name,
)

_NETDEV_HASHBITS = 8
_NETDEV_HASHENTRIES = 1 << _NETDEV_HASHBITS

hwtype_dict = {
    0: "ARPHRD_NETROM",
    1: "ARPHRD_ETHER",
    2: "ARPHRD_EETHER",
    3: "ARPHRD_AX25",
    4: "ARPHRD_PRONET",
    5: "ARPHRD_CHAOS",
    6: "ARPHRD_IEEE802",
    7: "ARPHRD_ARCNET",
    8: "ARPHRD_APPLETLK",
    15: "ARPHRD_DLCI",
    19: "ARPHRD_ATM",
    23: "ARPHRD_METRICOM",
    24: "ARPHRD_IEEE1394",
    27: "ARPHRD_EUI64",
    32: "ARPHRD_INFINIBAND",
}

state_dict = {
    1: "NUD_INCOMPLETE",
    2: "NUD_REACHABLE",
    4: "NUD_STALE",
    8: "NUD_DELAY",
    16: "NUD_PROBE",
    32: "NUD_FAILED",
    64: "NUD_NOARP",
    128: "NUD_PERMANENT",
}


def print_arp_cache(prog: Program) -> None:
    rows = [["NEIGHBOUR", "IP ADDRESS", "HW TYPE", "HW ADDRESS", "DEVICE", "STATE"]]

    nht = prog["arp_tbl"].nht

    for neigh in neigh_table_for_each_neighbor(nht):
        neigh_addr = hex(neigh.value_())[2:]
        ip_bytes = prog.read(neigh.primary_key.address_of_(), 4)
        ip_addr = str(ipaddress.IPv4Address(ip_bytes))

        addr_len = neigh.dev.addr_len

        mac_bytes = prog.read(neigh.ha.address_of_(), addr_len)
        hw_addr = ":".join(f"{b:02x}" for b in mac_bytes)
        dev_name = neigh.dev.name.string_().decode()

        hw_type = str(hwtype_dict.get(int(neigh.dev.type)))
        if int(neigh.dev.type) not in hwtype_dict.keys():
            hw_type = "ARPHRD_UNKNOWN"
        hw_type = hw_type[7:]
        dev_state = str(state_dict.get(int(neigh.nud_state.value_())))[4:]
        rows.append(
            [
                neigh_addr,
                ip_addr,
                hw_type,
                hw_addr,
                dev_name,
                dev_state,
            ]
        )
        neigh = neigh.next
    print_table(rows)


def print_net_devices(prog: Program) -> None:
    rows: List[Sequence[Any]] = [
        [CellFormat("NET_DEVICE", "^"), "NAME", "IP ADDRESS(ES)"]
    ]
    net_namespace = prog["init_net"]

    for dev in for_each_netdev(net_namespace):
        ip_list = [str(a) for a in netdev_ipv4_addrs(dev) + netdev_ipv6_addrs(dev)]
        ips = ", ".join(ip_list)
        rows.append(
            [
                CellFormat(dev.value_(), "^x"),
                escape_ascii_string(netdev_name(dev), escape_backslash=True),
                ips,
            ]
        )
    print_table(rows)


@crash_command(
    description="provides net command output",
    arguments=(
        argument(
            "-a",
            dest="all_data",
            action="store_true",
            help="Displays the ARP table",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_net(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.all_data:
        print_arp_cache(prog)
    else:
        print_net_devices(prog)
