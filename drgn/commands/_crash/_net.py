# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "net" command for drgn."""

import argparse
import ipaddress
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import (
    CellFormat,
    decode_flags,
    escape_ascii_string,
    print_table,
)
from drgn.helpers.linux.net import (
    for_each_netdev,
    neigh_table_for_each_neighbor,
    netdev_ipv4_addrs,
    netdev_ipv6_addrs,
    netdev_name,
)

# ARP protocol HARDWARE identifiers.
# kernel path: /usr/include/linux/if_arp.h
hwtype_dict = {
    0: "NETROM",
    1: "ETHER",
    2: "EETHER",
    3: "AX25",
    4: "PRONET",
    5: "CHAOS",
    6: "IEEE802",
    7: "ARCNET",
    8: "APPLETLK",
    15: "DLCI",
    19: "ATM",
    23: "METRICOM",
    24: "IEEE1394",
    27: "EUI64",
    32: "INFINIBAND",
}

# Neighbor Cache Entry States.
# Kernel path: /usr/include/linux/neighbour.h
nud_flags = [
    ("INCOMPLETE", 1),
    ("REACHABLE", 2),
    ("STALE", 4),
    ("DELAY", 8),
    ("PROBE", 16),
    ("FAILED", 32),
    ("NOARP", 64),
    ("PERMANENT", 128),
]


def print_arp_cache(prog: Program) -> None:
    rows: List[Sequence[Any]] = [
        ["NEIGHBOUR", "IP ADDRESS", "HW TYPE", "HW ADDRESS", "DEVICE", "STATE"]
    ]

    nht = prog["arp_tbl"].nht

    for neigh in neigh_table_for_each_neighbor(nht):
        ip_bytes = prog.read(neigh.primary_key.address_of_(), 4)
        ip_addr = str(ipaddress.IPv4Address(ip_bytes))
        addr_len = neigh.dev.addr_len
        mac_bytes = prog.read(neigh.ha.address_of_(), addr_len)
        hw_addr = ":".join(f"{b:02x}" for b in mac_bytes)
        hw_type = hwtype_dict.get(int(neigh.dev.type), "UNKNOWN")
        neigh_state = decode_flags(neigh.nud_state, nud_flags, False)
        rows.append(
            [
                CellFormat(neigh.value_(), "<x"),
                ip_addr,
                hw_type,
                hw_addr,
                escape_ascii_string(netdev_name(neigh.dev), escape_backslash=True),
                neigh_state,
            ]
        )
    print_table(rows)


def print_net_devices(prog: Program) -> None:
    rows: List[Sequence[Any]] = [
        [CellFormat("NET_DEVICE", "^"), "NAME", "IP ADDRESS(ES)"]
    ]

    for dev in for_each_netdev(prog):
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


def print_net_devices_drgn(prog: Program) -> None:
    code = CrashDrgnCodeBuilder(prog)
    code.add_from_import(
        "drgn.helpers.common.format",
        "CellFormat",
        "escape_ascii_string",
        "print_table",
    )
    code.add_from_import(
        "drgn.helpers.linux.net",
        "for_each_netdev",
        "netdev_ipv4_addrs",
        "netdev_ipv6_addrs",
        "netdev_name",
    )
    code.append(
        """\
rows = [[CellFormat("NET_DEVICE", "^"), "NAME", "IP ADDRESS(ES)"]]
for dev in for_each_netdev(prog):
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
"""
    )
    code.print()


def print_arp_cache_drgn(prog: Program) -> None:
    code = CrashDrgnCodeBuilder(prog)
    code.add_import("ipaddress")
    code.add_from_import(
        "drgn.helpers.common.format",
        "CellFormat",
        "decode_flags",
        "escape_ascii_string",
        "print_table",
    )
    code.add_from_import(
        "drgn.helpers.linux.net",
        "neigh_table_for_each_neighbor",
        "netdev_name",
    )
    code.append(
        f"""\
hwtype_dict = {hwtype_dict!r}
nud_flags = {nud_flags!r}

rows = [["NEIGHBOUR", "IP ADDRESS", "HW TYPE", "HW ADDRESS", "DEVICE", "STATE"]]
nht = prog["arp_tbl"].nht
for neigh in neigh_table_for_each_neighbor(nht):
    ip_bytes = prog.read(neigh.primary_key.address_of_(), 4)
    ip_addr = str(ipaddress.IPv4Address(ip_bytes))
    addr_len = neigh.dev.addr_len
    mac_bytes = prog.read(neigh.ha.address_of_(), addr_len)
    hw_addr = ":".join(f"{{b:02x}}" for b in mac_bytes)
    hw_type = hwtype_dict.get(int(neigh.dev.type), "UNKNOWN")
    neigh_state = decode_flags(neigh.nud_state, nud_flags, False)
    rows.append(
        [
            CellFormat(neigh.value_(), "<x"),
            ip_addr,
            hw_type,
            hw_addr,
            escape_ascii_string(netdev_name(neigh.dev), escape_backslash=True),
            neigh_state,
        ]
    )
print_table(rows)
"""
    )
    code.print()


@crash_command(
    description="provides net command output",
    arguments=(
        argument(
            "-a",
            dest="arp",
            action="store_true",
            help="Displays the ARP table",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_net(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.arp:
        if args.drgn:
            print_arp_cache_drgn(prog)
        else:
            print_arp_cache(prog)
    else:
        if args.drgn:
            print_net_devices_drgn(prog)
        else:
            print_net_devices(prog)
