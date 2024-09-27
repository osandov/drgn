# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Traffic Control (TC)
--------------------

The ``drgn.helpers.linux.tc`` module provides helpers for working with the
Linux kernel Traffic Control (TC) subsystem.
"""

import operator
from typing import Iterator

from drgn import NULL, IntegerLike, Object
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry

__all__ = (
    "for_each_tcf_chain",
    "for_each_tcf_proto",
    "get_tcf_chain_by_index",
    "get_tcf_proto_by_prio",
    "qdisc_lookup",
)


def for_each_tcf_chain(block: Object) -> Iterator[Object]:
    """
    Iterate over all TC filter chains on a block.

    This is only supported since Linux v4.13.

    :param block: ``struct tcf_block *``
    :return: Iterator of ``struct tcf_chain *`` objects.
    """
    # Before Linux kernel commit 5bc1701881e3 ("net: sched: introduce
    # multichain support for filters") (in v4.13), each block contained only
    # one chain.
    try:
        chain_list = block.chain_list.address_of_()
    except AttributeError:
        # Before Linux kernel commit 2190d1d0944f ("net: sched: introduce
        # helpers to work with filter chains") (in v4.13), struct tcf_chain
        # didn't exist.
        return block.chain

    for chain in list_for_each_entry("struct tcf_chain", chain_list, "list"):
        yield chain


def for_each_tcf_proto(chain: Object) -> Iterator[Object]:
    """
    Iterate over all TC filters on a chain.

    This is only supported since Linux v4.13.

    :param chain: ``struct tcf_chain *``
    :return: Iterator of ``struct tcf_proto *`` objects.
    """
    # Before Linux kernel commit 2190d1d0944f ("net: sched: introduce helpers
    # to work with filter chains") (in v4.13), struct tcf_chain::filter_chain
    # didn't exist.
    proto = chain.filter_chain

    while proto:
        yield proto
        proto = proto.next


def get_tcf_chain_by_index(block: Object, index: IntegerLike) -> Object:
    """
    Get the TC filter chain with the given index number from a block.

    This is only supported since Linux v4.13.

    :param block: ``struct tcf_block *``
    :param index: TC filter chain index number
    :return: ``struct tcf_chain *`` (``NULL`` if not found)
    """
    index = operator.index(index)

    for chain in for_each_tcf_chain(block):
        # Before Linux kernel commit 5bc1701881e3 ("net: sched: introduce
        # multichain support for filters") (in v4.13), struct tcf_chain::index
        # didn't exist.
        if chain.index == index:
            return chain

    return NULL(block.prog_, "struct tcf_chain *")


def get_tcf_proto_by_prio(chain: Object, prio: IntegerLike) -> Object:
    """
    Get the TC filter with the given priority from a chain.

    This is only supported since Linux v4.13.

    :param chain: ``struct tcf_chain *``
    :param prio: TC filter priority (preference) number
    :return: ``struct tcf_proto *`` (``NULL`` if not found)
    """
    prio = operator.index(prio) << 16

    for proto in for_each_tcf_proto(chain):
        if proto.prio == prio:
            return proto

    return NULL(chain.prog_, "struct tcf_proto *")


def qdisc_lookup(dev: Object, major: IntegerLike) -> Object:
    """
    Get a Qdisc from a device and a major handle number.  It is worth noting
    that conventionally handles are hexadecimal, e.g. ``10:`` in a ``tc``
    command means major handle 0x10.

    :param dev: ``struct net_device *``
    :param major: Qdisc major handle number.
    :return: ``struct Qdisc *`` (``NULL`` if not found)
    """
    major = operator.index(major) << 16

    roots = [dev.qdisc]
    if dev.ingress_queue:
        roots.append(dev.ingress_queue.qdisc_sleeping)

    # Since Linux kernel commit 59cc1f61f09c ("net: sched: convert qdisc linked
    # list to hashtable") (in v4.7), a device's child Qdiscs are maintained in
    # a hashtable in its struct net_device. Before that, they are maintained in
    # a linked list in their root Qdisc.
    use_hashtable = dev.prog_.type("struct net_device").has_member("qdisc_hash")

    for root in roots:
        if root.handle == major:
            return root

        if use_hashtable:
            for head in root.dev_queue.dev.qdisc_hash:
                for qdisc in hlist_for_each_entry(
                    "struct Qdisc", head.address_of_(), "hash"
                ):
                    if qdisc.handle == major:
                        return qdisc
        else:
            for qdisc in list_for_each_entry(
                "struct Qdisc", root.list.address_of_(), "list"
            ):
                if qdisc.handle == major:
                    return qdisc

    return NULL(dev.prog_, "struct Qdisc *")
