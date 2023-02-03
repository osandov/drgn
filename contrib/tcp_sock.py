#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List all TCP sockets and their cgroup v2 paths"""

import ipaddress
import socket
import struct

from drgn import cast
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (
    cgroup_path,
    hlist_nulls_empty,
    hlist_nulls_for_each_entry,
    sk_fullsock,
    sk_nulls_for_each,
    sk_tcpstate,
    sock_cgroup_ptr,
)

TcpState = enum_type_to_class(
    prog["TCP_ESTABLISHED"].type_,
    "TcpState",
    exclude=("TCP_MAX_STATES",),
    prefix="TCP_",
)


def inet_sk(sk):
    return cast("struct inet_sock *", sk)


def _ipv4(be32):
    return ipaddress.IPv4Address(struct.pack("I", be32.value_()))


def _ipv6(in6_addr):
    return ipaddress.IPv6Address(struct.pack("IIII", *in6_addr.in6_u.u6_addr32))


def _brackets(ip):
    if ip.version == 4:
        return "{}".format(ip.compressed)
    elif ip.version == 6:
        return "[{}]".format(ip.compressed)
    return ""


def _ip_port(ip, port):
    return "{:>40}:{:<6}".format(_brackets(ip), port)


def _print_sk(sk):
    inet = inet_sk(sk)

    tcp_state = TcpState(sk_tcpstate(sk))

    if sk.__sk_common.skc_family == socket.AF_INET:
        src_ip = _ipv4(sk.__sk_common.skc_rcv_saddr)
        dst_ip = _ipv4(sk.__sk_common.skc_daddr)
    elif sk.__sk_common.skc_family == socket.AF_INET6:
        src_ip = _ipv6(sk.__sk_common.skc_v6_rcv_saddr)
        dst_ip = _ipv6(sk.__sk_common.skc_v6_daddr)
    else:
        return

    src_port = socket.ntohs(inet.inet_sport)
    dst_port = socket.ntohs(sk.__sk_common.skc_dport)

    cgrp_path = ""
    if sk_fullsock(sk):
        cgrp = sock_cgroup_ptr(sk.sk_cgrp_data)
        cgrp_path = cgroup_path(cgrp).decode()

    print(
        "{:<12} {} {} {}".format(
            tcp_state.name,
            _ip_port(src_ip, src_port),
            _ip_port(dst_ip, dst_port),
            cgrp_path,
        )
    )

    # Uncomment to print whole struct:
    #   print(sk)
    #   print(inet)
    #   print(cgrp)


tcp_hashinfo = prog.object("tcp_hashinfo")

# 1. Iterate over all TCP sockets in TCP_LISTEN state.

# Since Linux kernel commit cae3873c5b3a ("net: inet: Retire port only
# listening_hash") (in v5.19), listening_hash is removed and we need
# to iterate lhash2 table.

try:
    for ilb in tcp_hashinfo.listening_hash:
        for sk in hlist_nulls_for_each_entry(
            "struct sock", ilb.nulls_head, "__sk_common.skc_node"
        ):
            _print_sk(sk)
except AttributeError:
    for i in range(tcp_hashinfo.lhash2_mask + 1):
        head = tcp_hashinfo.lhash2[i].nulls_head
        if hlist_nulls_empty(head):
            continue
        for sk in sk_nulls_for_each(head):
            _print_sk(sk)

# 2. And all other TCP sockets.
for i in range(tcp_hashinfo.ehash_mask + 1):
    head = tcp_hashinfo.ehash[i].chain
    if hlist_nulls_empty(head):
        continue
    for sk in sk_nulls_for_each(head):
        _print_sk(sk)
