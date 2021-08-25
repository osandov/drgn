# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Traffic Control (TC)
--------------------

The ``drgn.helpers.linux.tc`` module provides helpers for working with the
Linux kernel Traffic Control (TC) subsystem.
"""

import operator

from drgn import NULL, IntegerLike, Object
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry

__all__ = ("qdisc_lookup",)


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
