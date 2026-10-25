# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "net" command for drgn."""

import argparse
import ipaddress
import socket as socketlib
from typing import Any, List, Sequence

from drgn import Object, PlatformFlags, Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import (
    CrashDrgnCodeBuilder,
    _TaskSelector,
    crash_command,
    print_task_header,
)
from drgn.helpers.common.format import (
    CellFormat,
    decode_flags,
    escape_ascii_string,
    print_table,
)
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.net import (
    SOCKET_I,
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
        hw_addr = mac_bytes.hex(sep=":")
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
        "drgn.helpers.linux.net",
        "for_each_netdev",
        "netdev_ipv4_addrs",
        "netdev_ipv6_addrs",
        "netdev_name",
    )
    code.append(
        """\
for dev in for_each_netdev():
    name = netdev_name(dev)
    ipv4_addrs = netdev_ipv4_addrs(dev)
    ipv6_addrs = netdev_ipv6_addrs(dev)
"""
    )
    code.print()


def print_arp_cache_drgn(prog: Program) -> None:
    code = CrashDrgnCodeBuilder(prog)
    code.add_import("ipaddress")
    code.add_from_import(
        "drgn.helpers.linux.net",
        "neigh_table_for_each_neighbor",
        "netdev_name",
    )
    code.append(
        """\
for neigh in neigh_table_for_each_neighbor(prog["arp_tbl"].nht):
    ip_bytes = prog.read(neigh.primary_key.address_of_(), 4)
    ip_addr = ipaddress.IPv4Address(ip_bytes)
    mac_bytes = prog.read(neigh.ha.address_of_(), neigh.dev.addr_len)
    hw_addr = mac_bytes.hex(sep=":")
    hw_type = neigh.dev.type
    state = neigh.nud_state
"""
    )
    code.print()


sockfamily_dict = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    10: "AF_INET6",
    16: "AF_NETLINK/ROUTE",
}

socktype_dict = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    6: "SOCK_DCCP",
    10: "SOCK_PACKET",
}


def print_task_sockets(prog: Program, task: Object) -> None:
    print_task_header(task)
    platform = prog.platform
    if platform is None:
        raise RuntimeError("program platform is unknown")
    rows: List[Sequence[Any]] = [
        [
            "FD",
            "SOCKET",
            "SOCK",
            "FAMILY:TYPE",
            "SOURCE-PORT",
            "DESTINATION-PORT",
        ]
    ]

    for fd, file in for_each_file(task):
        if not file:
            continue
        try:
            socket = SOCKET_I(file.f_inode)
        except ValueError:
            continue

        sock = socket.sk
        family = sockfamily_dict.get(int(sock.__sk_common.skc_family), "AF_")[3:]
        sock_type = socktype_dict.get(int(socket.type), "SOCK_")[5:]

        if family == "INET":
            skc = sock.__sk_common
            saddr = ipaddress.IPv4Address(prog.read(skc.skc_rcv_saddr.address_of_(), 4))
            daddr = ipaddress.IPv4Address(prog.read(skc.skc_daddr.address_of_(), 4))
            sport = int(skc.skc_num)
            dport = int(skc.skc_dport)
            if platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
                dport = socketlib.ntohs(dport)
            source = f"{saddr}:{sport}"
            destination = f"{daddr}:{dport}"
        elif family == "INET6":
            skc = sock.__sk_common
            source_addr = bytes(int(b) for b in skc.skc_v6_rcv_saddr.in6_u.u6_addr8)
            destination_addr = bytes(int(b) for b in skc.skc_v6_daddr.in6_u.u6_addr8)
            sport = int(skc.skc_num)
            dport = int(skc.skc_dport)
            if platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
                dport = socketlib.ntohs(dport)
            source = f"{ipaddress.IPv6Address(source_addr)}:{sport}"
            destination = f"{ipaddress.IPv6Address(destination_addr)}:{dport}"
        else:
            source = destination = ""

        rows.append(
            [
                fd,
                f"{socket.value_():x}",
                f"{sock.value_():x}",
                f"{family}:{sock_type}",
                source,
                destination,
            ]
        )

    print_table(rows)


def print_task_sockets_drgn(prog: Program, task_selector: _TaskSelector) -> None:
    code = CrashDrgnCodeBuilder(prog)
    code.add_from_import("drgn.helpers.linux.fs", "for_each_file")
    code.add_from_import("drgn.helpers.linux.net", "SOCKET_I")
    with task_selector.begin_task_loop(code):
        code.append_task_header()
        code.append("for fd, file in for_each_file(task):\n")
        code.append(
            "    try:\n"
            "        socket = SOCKET_I(file.f_inode)\n"
            "    except ValueError:\n"
            "        continue\n"
            "    sock = socket.sk\n"
            "    family = sock.__sk_common.skc_family\n"
            "    socket_type = socket.type\n"
        )
    code.print()


@crash_command(
    description="provides net command output",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-a",
                dest="arp",
                action="store_true",
                help="Displays the ARP table",
            ),
            argument(
                "-s",
                dest="socket_task",
                metavar="pid|task",
                nargs="?",
                const=True,
                type="pid_or_task",
                help="Displays open sockets for a task",
            ),
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
    elif args.socket_task is not None:
        task_arg = None if args.socket_task is True else args.socket_task
        task_selector = _TaskSelector(prog, [task_arg])
        if args.drgn:
            print_task_sockets_drgn(prog, task_selector)
        else:
            for task in task_selector.tasks():
                print_task_sockets(prog, task)
    else:
        if args.drgn:
            print_net_devices_drgn(prog)
        else:
            print_net_devices(prog)
