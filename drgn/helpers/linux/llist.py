# Copyright (c) 2022, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Lockless Lists
--------------

The ``drgn.helpers.linux.llist`` module provides helpers for working with the
lockless, ``NULL``-terminated, singly-linked list implementation in
:linux:`include/linux/llist.h` (``struct llist_head`` and ``struct
llist_node``).
"""

from typing import Iterator, Union

from drgn import NULL, Object, Type, container_of

__all__ = (
    "llist_empty",
    "llist_first_entry",
    "llist_first_entry_or_null",
    "llist_for_each",
    "llist_for_each_entry",
    "llist_is_singular",
    "llist_next_entry",
)


def llist_empty(head: Object) -> bool:
    """
    Return whether an llist is empty.

    :param head: ``struct llist_head *``
    """
    return not head.first


def llist_is_singular(head: Object) -> bool:
    """
    Return whether an llist has only one element.

    :param head: ``struct llist_head *``
    """
    first = head.first.read_()
    return bool(first) and not first.next


def llist_first_entry(head: Object, type: Union[str, Type], member: str) -> Object:
    """
    Return the first entry in an llist.

    The list is assumed to be non-empty.

    See also :func:`llist_first_entry_or_null()`.

    :param head: ``struct llist_head *``
    :param type: Entry type.
    :param member: Name of ``struct llist_node`` member in entry type.
    :return: ``type *``
    """
    return container_of(head.first, type, member)


def llist_first_entry_or_null(
    head: Object, type: Union[str, Type], member: str
) -> Object:
    """
    Return the first entry in an llist or ``NULL`` if the llist is empty.

    See also :func:`llist_first_entry()`.

    :param head: ``struct llist_head *``
    :param type: Entry type.
    :param member: Name of ``struct llist_node`` member in entry type.
    :return: ``type *``
    """
    first = head.first.read_()
    if first:
        return container_of(first, type, member)
    else:
        return NULL(head.prog_, head.prog_.pointer_type(head.prog_.type(type)))


def llist_next_entry(pos: Object, member: str) -> Object:
    """
    Return the next entry in an llist.

    :param pos: ``type *``
    :param member: Name of ``struct llist_node`` member in entry type.
    :return: ``type *``
    """
    return container_of(pos.member_(member).next, pos.type_.type, member)


def llist_for_each(node: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in an llist starting from a given node.

    :param node: ``struct llist_node *``
    :return: Iterator of ``struct llist_node *`` objects.
    """
    pos = node.read_()
    while pos:
        yield pos
        pos = pos.next.read_()


def llist_for_each_entry(
    type: Union[str, Type], node: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in an llist starting from a given node.

    :param type: Entry type.
    :param node: ``struct llist_node *``
    :param member: Name of ``struct llist_node`` member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    type = node.prog_.type(type)
    for pos in llist_for_each(node):
        yield container_of(pos, type, member)
