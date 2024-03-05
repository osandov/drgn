# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Priority-Sorted Lists
---------------------

The ``drgn.helpers.linux.plist`` module provides helpers for working with
descending-priority-sorted doubly-linked lists (``struct plist_head`` and
``struct plist_node``) from :linux:`include/linux/plist.h`.
"""

from typing import Iterator, Union

from drgn import Object, Type, container_of
from drgn.helpers.linux.list import list_empty, list_for_each_entry

__all__ = (
    "plist_first_entry",
    "plist_for_each",
    "plist_for_each_entry",
    "plist_head_empty",
    "plist_last_entry",
    "plist_node_empty",
)


def plist_head_empty(head: Object) -> bool:
    """
    Return whether a plist is empty.

    :param head: ``struct plist_head *``
    """
    return list_empty(head.node_list.address_of_())


def plist_node_empty(node: Object) -> bool:
    """
    Return whether a plist node is empty (i.e., not on a list).

    :param node: ``struct plist_node *``
    """
    return list_empty(node.node_list.address_of_())


def plist_first_entry(head: Object, type: Union[str, Type], member: str) -> Object:
    """
    Return the first (highest priority) entry in a plist.

    The list is assumed to be non-empty.

    :param head: ``struct plist_head *``
    :param type: Entry type.
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(head.node_list.next, type, member + ".node_list")


def plist_last_entry(head: Object, type: Union[str, Type], member: str) -> Object:
    """
    Return the last (lowest priority) entry in a plist.

    The list is assumed to be non-empty.

    :param head: ``struct plist_head *``
    :param type: Entry type.
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(head.node_list.prev, type, member + ".node_list")


def plist_for_each(head: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in a plist.

    :param head: ``struct plist_head *``
    :return: Iterator of ``struct plist_node *`` objects.
    """
    return list_for_each_entry(
        "struct plist_node", head.node_list.address_of_(), "node_list"
    )


def plist_for_each_entry(
    type: Union[str, Type], head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a plist.

    :param type: Entry type.
    :param head: ``struct plist_head *``
    :param member: Name of plist node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    return list_for_each_entry(
        type, head.node_list.address_of_(), member + ".node_list"
    )
