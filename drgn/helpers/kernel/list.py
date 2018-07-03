# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel linked list helpers

This module provides helpers for working with the doubly-linked list
implementations in "linux/list.h".
"""

__all__ = [
    'list_empty',
    'list_is_singular',
    'list_for_each',
    'list_for_each_reverse',
    'list_for_each_entry',
    'list_for_each_entry_reverse',
    'hlist_empty',
    'hlist_for_each',
    'hlist_for_each_entry',
]


def list_empty(head):
    """
    bool list_empty(struct list_head *)

    Return whether a list is empty.
    """
    head = head.read_once_()
    return head.next == head


def list_is_singular(head):
    """
    bool list_is_singular(struct list_head *)

    Return whether a list has only one element.
    """
    head = head.read_once_()
    next = head.next
    return next != head and next == head.prev


def list_for_each(head):
    """
    list_for_each(struct list_head *)

    Return an iterator over all of the nodes in a list.
    """
    head = head.read_once_()
    pos = head.next.read_once_()
    while pos != head:
        yield pos
        pos = pos.next.read_once_()


def list_for_each_reverse(head):
    """
    list_for_each_reverse(struct list_head *)

    Return an iterator over all of the nodes in a list in reverse order.
    """
    head = head.read_once_()
    pos = head.prev.read_once_()
    while pos != head:
        yield pos
        pos = pos.prev.read_once_()


def list_for_each_entry(type, head, member):
    """
    list_for_each_entry(type, struct list_head *, member)

    Return an iterator over all of the entries in a list, given the type of the
    entry and the struct list_head member in that type.
    """
    for pos in list_for_each(head):
        yield pos.container_of_(type, member)


def list_for_each_entry_reverse(type, head, member):
    """
    list_for_each_entry_reverse(type, struct list_head *, member)

    Return an iterator over all of the entries in a list in reverse order,
    given the type of the entry and the struct list_head member in that type.
    """
    for pos in list_for_each_reverse(head):
        yield pos.container_of_(type, member)


def hlist_empty(head):
    """
    bool hlist_empty(struct hlist_head *)

    Return whether a hash list is empty.
    """
    return not head.first


def hlist_for_each(head):
    """
    hlist_for_each(struct hlist_head *)

    Return an iterator over all of the nodes in a hash list.
    """
    pos = head.first.read_once_()
    while pos:
        yield pos
        pos = pos.next.read_once_()


def hlist_for_each_entry(type, head, member):
    """
    hlist_for_each_entry(type, struct hlist_head *, member)

    Return an iterator over all of the entries in a has list, given the type of
    the entry and the struct hlist_node member in that type.
    """
    for pos in hlist_for_each(head):
        yield pos.container_of_(type, member)
