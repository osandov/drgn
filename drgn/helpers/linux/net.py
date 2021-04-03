# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Networking
----------

The ``drgn.helpers.linux.net`` module provides helpers for working with the
Linux kernel networking subsystem.
"""

from typing import Iterator

from drgn import Object
from drgn.helpers.linux.list_nulls import hlist_nulls_for_each_entry
from drgn.helpers.linux.tcp import sk_tcpstate

__all__ = (
    "sk_fullsock",
    "sk_nulls_for_each",
)


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
