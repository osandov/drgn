# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Linked Lists
------------

The ``drgn.helpers.linux.list`` module provides helpers for working with the
doubly-linked list implementations (``struct list_head`` and ``struct
hlist_head``) in :linux:`include/linux/list.h`.
"""

from typing import Iterator, Union

from drgn import NULL, Object, Type, container_of

__all__ = (
    "hlist_empty",
    "hlist_for_each",
    "hlist_for_each_entry",
    "list_empty",
    "list_first_entry",
    "list_first_entry_or_null",
    "list_for_each",
    "list_for_each_entry",
    "list_for_each_entry_reverse",
    "list_for_each_reverse",
    "list_is_singular",
    "list_last_entry",
    "list_next_entry",
    "list_prev_entry",
)


def list_empty(head: Object) -> bool:
    """
    Return whether a list is empty.

    :param head: ``struct list_head *``
    """
    head = head.read_()
    return head.next == head


def list_is_singular(head: Object) -> bool:
    """
    Return whether a list has only one element.

    :param head: ``struct list_head *``
    """
    head = head.read_()
    next = head.next
    return next != head and next == head.prev


def list_first_entry(head: Object, type: Union[str, Type], member: str) -> Object:
    """
    Return the first entry in a list.

    The list is assumed to be non-empty.

    See also :func:`list_first_entry_or_null()`.

    :param head: ``struct list_head *``
    :param type: Entry type.
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(head.next, type, member)


def list_first_entry_or_null(
    head: Object, type: Union[str, Type], member: str
) -> Object:
    """
    Return the first entry in a list or ``NULL`` if the list is empty.

    See also :func:`list_first_entry()`.

    :param head: ``struct list_head *``
    :param type: Entry type.
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    head = head.read_()
    pos = head.next.read_()
    if pos == head:
        if isinstance(type, str):
            type = head.prog_.type(type)
        return NULL(head.prog_, head.prog_.pointer_type(type))
    else:
        return container_of(pos, type, member)


def list_last_entry(head: Object, type: Union[str, Type], member: str) -> Object:
    """
    Return the last entry in a list.

    The list is assumed to be non-empty.

    :param head: ``struct list_head *``
    :param type: Entry type.
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(head.prev, type, member)


def list_next_entry(pos: Object, member: str) -> Object:
    """
    Return the next entry in a list.

    :param pos: ``type*``
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(getattr(pos, member).next, pos.type_.type, member)


def list_prev_entry(pos: Object, member: str) -> Object:
    """
    Return the previous entry in a list.

    :param pos: ``type*``
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(getattr(pos, member).prev, pos.type_.type, member)


def list_for_each(head: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in a list.

    :param head: ``struct list_head *``
    :return: Iterator of ``struct list_head *`` objects.
    """
    head = head.read_()
    pos = head.next.read_()
    while pos != head:
        yield pos
        pos = pos.next.read_()


def list_for_each_reverse(head: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in a list in reverse order.

    :param head: ``struct list_head *``
    :return: Iterator of ``struct list_head *`` objects.
    """
    head = head.read_()
    pos = head.prev.read_()
    while pos != head:
        yield pos
        pos = pos.prev.read_()


def list_for_each_entry(type: str, head: Object, member: str) -> Iterator[Object]:
    """
    Iterate over all of the entries in a list.

    :param type: Entry type.
    :param head: ``struct list_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for pos in list_for_each(head):
        yield container_of(pos, type, member)


def list_for_each_entry_reverse(
    type: str, head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a list in reverse order.

    :param type: Entry type.
    :param head: ``struct list_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for pos in list_for_each_reverse(head):
        yield container_of(pos, type, member)


def hlist_empty(head: Object) -> bool:
    """
    Return whether a hash list is empty.

    :param head: ``struct hlist_head *``
    """
    return not head.first


def hlist_for_each(head: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in a hash list.

    :param head: ``struct hlist_head *``
    :return: Iterator of ``struct hlist_node *`` objects.
    """
    pos = head.first.read_()
    while pos:
        yield pos
        pos = pos.next.read_()


def hlist_for_each_entry(type: str, head: Object, member: str) -> Iterator[Object]:
    """
    Iterate over all of the entries in a hash list.

    :param type: Entry type.
    :param head: ``struct hlist_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for pos in hlist_for_each(head):
        yield container_of(pos, type, member)
