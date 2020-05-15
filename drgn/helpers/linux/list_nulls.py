# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Nulls Lists
-----------

The ``drgn.helpers.linux.list_nulls`` module provides helpers for working with
the special version of lists (``struct hlist_nulls_head`` and ``struct
hlist_nulls_node``) in :linux:`include/linux/list_nulls.h` where the end of
list is not a ``NULL`` pointer, but a "nulls" marker.
"""

from drgn import container_of


__all__ = (
    "hlist_nulls_empty",
    "hlist_nulls_entry",
    "hlist_nulls_for_each_entry",
    "is_a_nulls",
)


def is_a_nulls(pos):
    """
    .. c:function:: bool is_a_nulls(struct hlist_nulls_node *pos)

    Return whether a a pointer is a nulls marker.
    """
    return bool(pos.value_() & 1)


def hlist_nulls_empty(head):
    """
    .. c:function:: bool hlist_nulls_empty(struct hlist_nulls_head *head)

    Return whether a nulls hash list is empty.
    """
    return is_a_nulls(head.first)


def hlist_nulls_entry(pos, type, member):
    """
    .. c:function:: type *hlist_nulls_entry(struct hlist_nulls_node *pos, type, member)

    Return an entry in a nulls hash list.

    The nulls hash list is assumed to be non-empty.
    """
    return container_of(pos, type, member)


def hlist_nulls_for_each_entry(type, head, member):
    """
    .. c:function:: hlist_nulls_for_each_entry(type, struct hlist_nulls_head *head, member)

    Iterate over all the entries in a nulls hash list specified by ``struct
    hlist_nulls_head`` head, given the type of the entry and the ``struct
    hlist_nulls_node`` member in that type.

    :return: Iterator of ``type *`` objects.
    """
    pos = head.first
    while not is_a_nulls(pos):
        yield hlist_nulls_entry(pos, type, member)
        pos = pos.next
