# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Networking
----------

The ``drgn.helpers.linux.net`` module provides helpers for working with the
Linux kernel networking subsystem.
"""

import operator
from typing import Iterator, Union

from drgn import NULL, IntegerLike, Object, Program, cast, container_of
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry
from drgn.helpers.linux.list_nulls import hlist_nulls_for_each_entry

__all__ = (
    "for_each_net",
    "get_net_ns_by_inode",
    "get_net_ns_by_fd",
    "netdev_for_each_tx_queue",
    "netdev_get_by_index",
    "netdev_get_by_name",
    "sk_fullsock",
    "sk_nulls_for_each",
)


def for_each_net(prog: Program) -> Iterator[Object]:
    """
    Iterate over all network namespaces in the system.

    :return: Iterator of ``struct net *`` objects.
    """
    for net in list_for_each_entry(
        "struct net", prog["net_namespace_list"].address_of_(), "list"
    ):
        yield net


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


def netdev_get_by_index(
    prog_or_net: Union[Program, Object], ifindex: IntegerLike
) -> Object:
    """
    Get the network device with the given interface index number.

    :param prog_or_net: ``struct net *`` containing the device, or
        :class:`Program` to use the initial network namespace.
    :param ifindex: Network interface index number.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if isinstance(prog_or_net, Program):
        prog_or_net = prog_or_net["init_net"]
    if isinstance(ifindex, Object):
        ifindex = ifindex.read_()

    head = prog_or_net.dev_index_head[
        operator.index(ifindex) & (_NETDEV_HASHENTRIES - 1)
    ]
    for netdev in hlist_for_each_entry("struct net_device", head, "index_hlist"):
        if netdev.ifindex == ifindex:
            return netdev

    return NULL(prog_or_net.prog_, "struct net_device *")


def netdev_get_by_name(
    prog_or_net: Union[Program, Object], name: Union[str, bytes]
) -> Object:
    """
    Get the network device with the given interface name.

    :param prog_or_net: ``struct net *`` containing the device, or
        :class:`Program` to use the initial network namespace.
    :param name: Network interface name.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if isinstance(prog_or_net, Program):
        prog_or_net = prog_or_net["init_net"]
    if isinstance(name, str):
        name = name.encode()

    # Since Linux kernel commit ff92741270bf ("net: introduce name_node struct
    # to be used in hashlist") (in v5.5), the device name hash table contains
    # struct netdev_name_node entries. Before that, it contained the struct
    # net_device directly.
    try:
        entry_type = prog_or_net.prog_.type("struct netdev_name_node")
        member = "hlist"
        entry_is_name_node = True
    except LookupError:
        entry_type = prog_or_net.prog_.type("struct net_device")
        member = "name_hlist"
        entry_is_name_node = False

    for i in range(_NETDEV_HASHENTRIES):
        head = prog_or_net.dev_name_head[i]
        for entry in hlist_for_each_entry(entry_type, head, member):
            if entry.name.string_() == name:
                if entry_is_name_node:
                    return entry.dev
                else:
                    return entry

    return NULL(prog_or_net.prog_, "struct net_device *")


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
    for sk in hlist_nulls_for_each_entry(
        "struct sock", head, "__sk_common.skc_nulls_node"
    ):
        yield sk
