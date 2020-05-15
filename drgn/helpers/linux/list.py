# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Linked Lists
------------

The ``drgn.helpers.linux.list`` module provides helpers for working with the
doubly-linked list implementations (``struct list_head`` and ``struct
hlist_head``) in :linux:`include/linux/list.h`.
"""

from drgn import NULL, container_of


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


def list_empty(head):
    """
    .. c:function:: bool list_empty(struct list_head *head)

    Return whether a list is empty.
    """
    head = head.read_()
    return head.next == head


def list_is_singular(head):
    """
    .. c:function:: bool list_is_singular(struct list_head *head)

    Return whether a list has only one element.
    """
    head = head.read_()
    next = head.next
    return next != head and next == head.prev


def list_first_entry(head, type, member):
    """
    .. c:function:: type *list_first_entry(struct list_head *head, type, member)

    Return the first entry in a list.

    The list is assumed to be non-empty.

    See also :func:`list_first_entry_or_null()`.
    """
    return container_of(head.next, type, member)


def list_first_entry_or_null(head, type, member):
    """
    .. c:function:: type *list_first_entry_or_null(struct list_head *head, type, member)

    Return the first entry in a list or ``NULL`` if the list is empty.

    See also :func:`list_first_entry()`.
    """
    head = head.read_()
    pos = head.next.read_()
    if pos == head:
        return NULL(head.prog_, head.prog_.pointer_type(type))
    else:
        return container_of(pos, type, member)


def list_last_entry(head, type, member):
    """
    .. c:function:: type *list_last_entry(struct list_head *head, type, member)

    Return the last entry in a list.

    The list is assumed to be non-empty.
    """
    return container_of(head.prev, type, member)


def list_next_entry(pos, member):
    """
    .. c:function:: type *list_next_entry(type *pos, member)

    Return the next entry in a list.
    """
    return container_of(getattr(pos, member).next, pos.type_.type, member)


def list_prev_entry(pos, member):
    """
    .. c:function:: type *list_prev_entry(type *pos, member)

    Return the previous entry in a list.
    """
    return container_of(getattr(pos, member).prev, pos.type_.type, member)


def list_for_each(head):
    """
    .. c:function:: list_for_each(struct list_head *head)

    Iterate over all of the nodes in a list.

    :return: Iterator of ``struct list_head *`` objects.
    """
    head = head.read_()
    pos = head.next.read_()
    while pos != head:
        yield pos
        pos = pos.next.read_()


def list_for_each_reverse(head):
    """
    .. c:function:: list_for_each_reverse(struct list_head *head)

    Iterate over all of the nodes in a list in reverse order.

    :return: Iterator of ``struct list_head *`` objects.
    """
    head = head.read_()
    pos = head.prev.read_()
    while pos != head:
        yield pos
        pos = pos.prev.read_()


def list_for_each_entry(type, head, member):
    """
    .. c:function:: list_for_each_entry(type, struct list_head *head, member)

    Iterate over all of the entries in a list, given the type of the entry and
    the ``struct list_head`` member in that type.

    :return: Iterator of ``type *`` objects.
    """
    for pos in list_for_each(head):
        yield container_of(pos, type, member)


def list_for_each_entry_reverse(type, head, member):
    """
    .. c:function:: list_for_each_entry_reverse(type, struct list_head *head, member)

    Iterate over all of the entries in a list in reverse order, given the type
    of the entry and the ``struct list_head`` member in that type.

    :return: Iterator of ``type *`` objects.
    """
    for pos in list_for_each_reverse(head):
        yield container_of(pos, type, member)


def hlist_empty(head):
    """
    .. c:function:: bool hlist_empty(struct hlist_head *head)

    Return whether a hash list is empty.
    """
    return not head.first


def hlist_for_each(head):
    """
    .. c:function:: hlist_for_each(struct hlist_head *head)

    Iterate over all of the nodes in a hash list.

    :return: Iterator of ``struct hlist_node *`` objects.
    """
    pos = head.first.read_()
    while pos:
        yield pos
        pos = pos.next.read_()


def hlist_for_each_entry(type, head, member):
    """
    .. c:function:: hlist_for_each_entry(type, struct hlist_head *head, member)

    Iterate over all of the entries in a has list, given the type of the entry
    and the ``struct hlist_node`` member in that type.

    :return: Iterator of ``type *`` objects.
    """
    for pos in hlist_for_each(head):
        yield container_of(pos, type, member)
