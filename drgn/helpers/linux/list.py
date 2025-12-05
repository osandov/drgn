# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Linked Lists
------------

The ``drgn.helpers.linux.list`` module provides helpers for working with the
doubly-linked list implementations (``struct list_head`` and ``struct
hlist_head``) in :linux:`include/linux/list.h`.
"""

from typing import Iterator, Union

from drgn import NULL, Object, Type, container_of
from drgn.helpers import ValidationError

__all__ = (
    "hlist_empty",
    "hlist_for_each",
    "hlist_for_each_entry",
    "list_count_nodes",
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
    "validate_list",
    "validate_list_count_nodes",
    "validate_list_for_each",
    "validate_list_for_each_entry",
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


def list_count_nodes(head: Object) -> int:
    """
    Return the number of nodes in a list.

    :param head: ``struct list_head *``
    """
    return sum(1 for _ in list_for_each(head))


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
        return NULL(head.prog_, head.prog_.pointer_type(head.prog_.type(type)))
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

    :param pos: ``type *``
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(pos.member_(member).next, pos.type_.type, member)


def list_prev_entry(pos: Object, member: str) -> Object:
    """
    Return the previous entry in a list.

    :param pos: ``type *``
    :param member: Name of list node member in entry type.
    :return: ``type *``
    """
    return container_of(pos.member_(member).prev, pos.type_.type, member)


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


def list_for_each_entry(
    type: Union[str, Type], head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a list.

    :param type: Entry type.
    :param head: ``struct list_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    type = head.prog_.type(type)
    for pos in list_for_each(head):
        yield container_of(pos, type, member)


def list_for_each_entry_reverse(
    type: Union[str, Type], head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a list in reverse order.

    :param type: Entry type.
    :param head: ``struct list_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    type = head.prog_.type(type)
    for pos in list_for_each_reverse(head):
        yield container_of(pos, type, member)


def validate_list(head: Object) -> None:
    """
    Validate that the ``next`` and ``prev`` pointers in a list are consistent.

    >>> validate_list(prog["my_list"].address_of_())
    drgn.helpers.ValidationError: (struct list_head *)0xffffffffc029e460 next 0xffffffffc029e000 has prev 0xffffffffc029e450

    :param head: ``struct list_head *``
    :raises ValidationError: if the list is invalid
    """
    for _ in validate_list_for_each(head):
        pass


def validate_list_count_nodes(head: Object) -> int:
    """
    Like :func:`list_count_nodes()`, but validates the list like
    :func:`validate_list()` while iterating.

    :param head: ``struct list_head *``
    """
    return sum(1 for _ in validate_list_for_each(head))


def validate_list_for_each(head: Object) -> Iterator[Object]:
    """
    Like :func:`list_for_each()`, but validates the list like
    :func:`validate_list()` while iterating.

    :param head: ``struct list_head *``
    :raises ValidationError: if the list is invalid
    """
    head = head.read_()
    pos = head.next.read_()
    while pos != head:
        yield pos
        next = pos.next.read_()
        next_prev = next.prev.read_()
        if next_prev != pos:
            raise ValidationError(
                f"{pos.format_(dereference=False, symbolize=False)}"
                f" next {next.format_(dereference=False, symbolize=False, type_name=False)}"
                f" has prev {next_prev.format_(dereference=False, symbolize=False, type_name=False)}"
            )
        pos = next


def validate_list_for_each_entry(
    type: Union[str, Type], head: Object, member: str
) -> Iterator[Object]:
    """
    Like :func:`list_for_each_entry()`, but validates the list like
    :func:`validate_list()` while iterating.

    .. code-block:: python3

       def validate_my_list(prog):
            for entry in validate_list_for_each_entry(
                "struct my_entry",
                prog["my_list"].address_of_(),
                "list",
            ):
                if entry.value < 0:
                    raise ValidationError("list contains negative entry")

    :param type: Entry type.
    :param head: ``struct list_head *``
    :param member: Name of list node member in entry type.
    :raises ValidationError: if the list is invalid
    """
    type = head.prog_.type(type)
    for pos in validate_list_for_each(head):
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


def hlist_for_each_entry(
    type: Union[str, Type], head: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a hash list.

    :param type: Entry type.
    :param head: ``struct hlist_head *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    type = head.prog_.type(type)
    for pos in hlist_for_each(head):
        yield container_of(pos, type, member)
