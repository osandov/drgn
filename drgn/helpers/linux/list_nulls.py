# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Nulls Lists
-----------

The ``drgn.helpers.linux.list_nulls`` module provides helpers for working with
the special version of lists (``struct hlist_nulls_head`` and ``struct
hlist_nulls_node``) in :linux:`include/linux/list_nulls.h` where the end of
list is not a ``NULL`` pointer, but a "nulls" marker.
"""

from typing import Iterator

from drgn import Object, container_of

__all__ = (
    "hlist_nulls_empty",
    "hlist_nulls_for_each_entry",
    "is_a_nulls",
)


def is_a_nulls(pos: Object) -> bool:
    """
    Return whether a a pointer is a nulls marker.

    :param pos: ``struct hlist_nulls_node *``
    """
    return bool(pos.value_() & 1)


def hlist_nulls_empty(head: Object) -> bool:
    """
    Return whether a nulls hash list is empty.

    :param head: ``struct hlist_nulls_head *``
    """
    return is_a_nulls(head.first)


def hlist_nulls_for_each_entry(
    type: str, head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all the entries in a nulls hash list.

    :param type: Entry type.
    :param head: ``struct hlist_nulls_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    pos = head.first
    while not is_a_nulls(pos):
        yield container_of(pos, type, member)
        pos = pos.next
