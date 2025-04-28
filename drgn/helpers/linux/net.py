# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Networking
----------

The ``drgn.helpers.linux.net`` module provides helpers for working with the
Linux kernel networking subsystem.
"""

import operator
from typing import Iterator, Optional, Union

from drgn import NULL, IntegerLike, Object, Program, Type, cast, container_of, sizeof
from drgn.helpers.common.prog import (
    takes_object_or_program_or_default,
    takes_program_or_default,
)
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry
from drgn.helpers.linux.list_nulls import hlist_nulls_for_each_entry

__all__ = (
    "SOCK_INODE",
    "SOCKET_I",
    "for_each_net",
    "get_net_ns_by_inode",
    "get_net_ns_by_fd",
    "netdev_for_each_tx_queue",
    "netdev_get_by_index",
    "netdev_get_by_name",
    "netdev_priv",
    "sk_fullsock",
    "sk_nulls_for_each",
    "skb_shinfo",
    "skb_headlen",
    "skb_headroom",
    "skb_is_nonlinear",
    "skb_tailroom",
    "skb_availroom",
    "skb_dump",
)


_S_IFMT = 0o170000
_S_IFSOCK = 0o140000


def SOCKET_I(inode: Object) -> Object:
    """
    Get a socket from an inode referring to the socket.

    :param inode: ``struct inode *``
    :return: ``struct socket *``
    :raises ValueError: If *inode* does not refer to a socket
    """
    if inode.i_mode & _S_IFMT != _S_IFSOCK:
        raise ValueError("not a socket inode")

    return container_of(inode, "struct socket_alloc", "vfs_inode").socket.address_of_()


def SOCK_INODE(sock: Object) -> Object:
    """
    Get the inode of a socket.

    :param sock: ``struct socket *``
    :return: ``struct inode *``
    """
    return container_of(sock, "struct socket_alloc", "socket").vfs_inode.address_of_()


@takes_program_or_default
def for_each_net(prog: Program) -> Iterator[Object]:
    """
    Iterate over all network namespaces in the system.

    :return: Iterator of ``struct net *`` objects.
    """
    return list_for_each_entry(
        "struct net", prog["net_namespace_list"].address_of_(), "list"
    )


_CLONE_NEWNET = 0x40000000


def get_net_ns_by_inode(inode: Object) -> Object:
    """
    Get a network namespace from a network namespace NSFS inode, e.g.
    ``/proc/$PID/ns/net`` or ``/var/run/netns/$NAME``.

    :param inode: ``struct inode *``
    :return: ``struct net *``
    :raises ValueError: if *inode* is not a network namespace inode
    """
    if inode.i_fop != inode.prog_["ns_file_operations"].address_of_():
        raise ValueError("not a namespace inode")

    ns = cast("struct ns_common *", inode.i_private)
    if ns.ops.type != _CLONE_NEWNET:
        raise ValueError("not a network namespace inode")

    return container_of(ns, "struct net", "ns")


def get_net_ns_by_fd(task: Object, fd: IntegerLike) -> Object:
    """
    Get a network namespace from a task and a file descriptor referring to a
    network namespace NSFS inode, e.g. ``/proc/$PID/ns/net`` or
    ``/var/run/netns/$NAME``.

    :param task: ``struct task_struct *``
    :param fd: File descriptor.
    :return: ``struct net *``
    :raises ValueError: If *fd* does not refer to a network namespace inode
    """
    return get_net_ns_by_inode(fget(task, fd).f_inode)


def netdev_for_each_tx_queue(dev: Object) -> Iterator[Object]:
    """
    Iterate over all TX queues for a network device.

    :param dev: ``struct net_device *``
    :return: Iterator of ``struct netdev_queue *`` objects.
    """
    for i in range(dev.num_tx_queues):
        yield dev._tx + i


_NETDEV_HASHBITS = 8
_NETDEV_HASHENTRIES = 1 << _NETDEV_HASHBITS


@takes_object_or_program_or_default
def netdev_get_by_index(
    prog: Program, net: Optional[Object], ifindex: IntegerLike
) -> Object:
    """
    Get the network device with the given interface index number.

    :param net: ``struct net *``. Defaults to the initial network namespace if
        given a :class:`~drgn.Program` or :ref:`omitted <default-program>`.
    :param ifindex: Network interface index number.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if net is None:
        net = prog["init_net"]
    ifindex = operator.index(ifindex)

    head = net.dev_index_head[ifindex & (_NETDEV_HASHENTRIES - 1)]
    for netdev in hlist_for_each_entry("struct net_device", head, "index_hlist"):
        if netdev.ifindex.value_() == ifindex:
            return netdev

    return NULL(prog, "struct net_device *")


@takes_object_or_program_or_default
def netdev_get_by_name(
    prog: Program, net: Optional[Object], name: Union[str, bytes]
) -> Object:
    """
    Get the network device with the given interface name.

    :param net: ``struct net *``. Defaults to the initial network namespace if
        given a :class:`~drgn.Program` or :ref:`omitted <default-program>`.
    :param name: Network interface name.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if net is None:
        net = prog["init_net"]
    if isinstance(name, str):
        name = name.encode()

    # Since Linux kernel commit ff92741270bf ("net: introduce name_node struct
    # to be used in hashlist") (in v5.5), the device name hash table contains
    # struct netdev_name_node entries. Before that, it contained the struct
    # net_device directly.
    try:
        entry_type = prog.type("struct netdev_name_node")
        member = "hlist"
        entry_is_name_node = True
    except LookupError:
        entry_type = prog.type("struct net_device")
        member = "name_hlist"
        entry_is_name_node = False

    for i in range(_NETDEV_HASHENTRIES):
        head = net.dev_name_head[i]
        for entry in hlist_for_each_entry(entry_type, head, member):
            if entry.name.string_() == name:
                if entry_is_name_node:
                    return entry.dev
                else:
                    return entry

    return NULL(prog, "struct net_device *")


def netdev_priv(dev: Object, type: Union[str, Type] = "void") -> Object:
    """
    Return the private data of a network device.

    >>> dev = netdev_get_by_name("wlp0s20f3")
    >>> netdev_priv(dev)
    (void *)0xffff9419c9dec9c0
    >>> netdev_priv(dev, "struct ieee80211_sub_if_data")
    *(struct ieee80211_sub_if_data *)0xffff9419c9dec9c0 = {
        ...
    }

    :param dev: ``struct net_device *``
    :param type: Type of private data.
    :return: ``type *``
    """
    prog = dev.prog_
    try:
        offset = prog.cache["net_device_aligned_size"]
    except KeyError:
        # 31 is NETDEV_ALIGN - 1
        offset = (sizeof(prog.type("struct net_device")) + 31) & ~31
        prog.cache["net_device_aligned_size"] = offset
    return Object(prog, prog.pointer_type(prog.type(type)), dev.value_() + offset)


def sk_fullsock(sk: Object) -> bool:
    """
    Check whether a socket is a full socket, i.e., not a time-wait or request
    socket.

    :param sk: ``struct sock *``
    """
    prog = sk.prog_
    state = sk.__sk_common.skc_state.value_()
    return state != prog["TCP_SYN_RECV"] and state != prog["TCP_TIME_WAIT"]


def sk_nulls_for_each(head: Object) -> Iterator[Object]:
    """
    Iterate over all the entries in a nulls hash list of sockets specified by
    ``struct hlist_nulls_head`` head.

    :param head: ``struct hlist_nulls_head *``
    :return: Iterator of ``struct sock *`` objects.
    """
    return hlist_nulls_for_each_entry("struct sock", head, "__sk_common.skc_nulls_node")


def skb_shinfo(skb: Object) -> Object:
    """
    Get the shared info for a socket buffer.

    :param skb: ``struct sk_buff *``
    :return: ``struct skb_shared_info *``
    """
    prog = skb.prog_
    try:
        NET_SKBUFF_DATA_USES_OFFSET = prog.cache["NET_SKBUFF_DATA_USES_OFFSET"]
    except KeyError:
        NET_SKBUFF_DATA_USES_OFFSET = sizeof(prog.type("long")) > 4
        prog.cache["NET_SKBUFF_DATA_USES_OFFSET"] = NET_SKBUFF_DATA_USES_OFFSET
    if NET_SKBUFF_DATA_USES_OFFSET:
        return cast("struct skb_shared_info *", skb.head + skb.end)
    else:
        return cast("struct skb_shared_info *", skb.end)


def skb_headlen(skb: Object) -> Object:
    return skb.len - skb.data_len


def skb_headroom(skb: Object) -> Object:
    return skb.data - skb.head


def skb_is_nonlinear(skb: Object) -> Object:
    return skb.data_len


def skb_tailroom(skb: Object) -> IntegerLike:
    if skb_is_nonlinear(skb):
        return 0
    return skb.end - skb.tail


def skb_availroom(skb: Object) -> IntegerLike:
    if skb_is_nonlinear(skb):
        return 0

    return skb.end - skb.tail - skb.reserved_tailroom


def skb_network_header_len(skb: Object) -> Object:
    return skb.transport_header - skb.network_header


def skb_mac_header_len(skb: Object) -> Object:
    return skb.network_header - skb.mac_header


def skb_mac_header_was_set(skb: Object) -> bool:
    return skb.mac_header != 65535


def skb_transport_header_was_set(skb: Object) -> bool:
    return skb.transport_header != 65535


def skb_dump(skb: Object) -> None:
    headroom = skb_headroom(skb)
    tailroom = skb_tailroom(skb)
    sh = skb_shinfo(skb)

    has_mac = skb_mac_header_was_set(skb)
    has_trans = skb_transport_header_was_set(skb)

    print(
        "skb len=%u headroom=%u headlen=%u tailroom=%u\n"
        "mac=(%d,%d) net=(%d,%d) trans=%d\n"
        "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
        "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
        "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n"
        % (
            int(skb.len),
            int(headroom),
            int(skb_headlen(skb)),
            int(tailroom),
            int(skb.mac_header) if has_mac else -1,
            int(skb_mac_header_len(skb)) if has_mac else -1,
            int(skb.network_header),
            int(skb_network_header_len(skb)) if has_trans else -1,
            int(skb.transport_header) if has_trans else -1,
            int(sh.tx_flags),
            int(sh.nr_frags),
            int(sh.gso_size),
            int(sh.gso_type),
            int(sh.gso_segs),
            int(skb.csum),
            int(skb.ip_summed),
            int(skb.csum_complete_sw),
            int(skb.csum_valid),
            int(skb.csum_level),
            int(skb.hash),
            int(skb.sw_hash),
            int(skb.l4_hash),
            int(skb.protocol),
            int(skb.pkt_type),
            int(skb.skb_iif),
        )
    )
