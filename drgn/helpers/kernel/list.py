# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel linked list helpers

This module provides helpers for working with the doubly-linked list
implementations in "linux/list.h".
"""

from drgn import container_of, read_once


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
    head = read_once(head)
    return head.next == head


def list_is_singular(head):
    """
    bool list_is_singular(struct list_head *)

    Return whether a list has only one element.
    """
    head = read_once(head)
    next = head.next
    return next != head and next == head.prev


def list_for_each(head):
    """
    list_for_each(struct list_head *)

    Return an iterator over all of the nodes in a list.
    """
    head = read_once(head)
    pos = read_once(head.next)
    while pos != head:
        yield pos
        pos = read_once(pos.next)


def list_for_each_reverse(head):
    """
    list_for_each_reverse(struct list_head *)

    Return an iterator over all of the nodes in a list in reverse order.
    """
    head = read_once(head)
    pos = read_once(head.prev)
    while pos != head:
        yield pos
        pos = read_once(pos.prev)


def list_for_each_entry(type, head, member):
    """
    list_for_each_entry(type, struct list_head *, member)

    Return an iterator over all of the entries in a list, given the type of the
    entry and the struct list_head member in that type.
    """
    for pos in list_for_each(head):
        yield container_of(pos, type, member)


def list_for_each_entry_reverse(type, head, member):
    """
    list_for_each_entry_reverse(type, struct list_head *, member)

    Return an iterator over all of the entries in a list in reverse order,
    given the type of the entry and the struct list_head member in that type.
    """
    for pos in list_for_each_reverse(head):
        yield container_of(pos, type, member)


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
    pos = read_once(head.first)
    while pos:
        yield pos
        pos = read_once(pos.next)


def hlist_for_each_entry(type, head, member):
    """
    hlist_for_each_entry(type, struct hlist_head *, member)

    Return an iterator over all of the entries in a has list, given the type of
    the entry and the struct hlist_node member in that type.
    """
    for pos in hlist_for_each(head):
        yield container_of(pos, type, member)
