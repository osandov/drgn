# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
XArrays
-------

The ``drgn.helpers.linux.xarray`` module provides helpers for working with the
`XArray <https://docs.kernel.org/core-api/xarray.html>`_ data structure from
:linux:`include/linux/xarray.h`.

.. note::

    XArrays were introduced in Linux 4.20 as a replacement for `radix trees`_.
    To make it easier to work with data structures that were changed from a
    radix tree to an XArray (like ``struct address_space::i_pages``), drgn
    treats XArrays and radix trees interchangeably in some cases.

    Specifically, :func:`~drgn.helpers.linux.xarray.xa_load()` is equivalent to
    :func:`~drgn.helpers.linux.radixtree.radix_tree_lookup()`, and
    :func:`~drgn.helpers.linux.xarray.xa_for_each()` is equivalent to
    :func:`~drgn.helpers.linux.radixtree.radix_tree_for_each()`, except that
    the radix tree helpers assume ``advanced=False``. (Therefore,
    :func:`~drgn.helpers.linux.xarray.xa_load()` and
    :func:`~drgn.helpers.linux.xarray.xa_for_each()` also accept a ``struct
    radix_tree_root *``, and
    :func:`~drgn.helpers.linux.radixtree.radix_tree_lookup()` and
    :func:`~drgn.helpers.linux.radixtree.radix_tree_for_each()` also accept a
    ``struct xarray *``.)
"""

from typing import Iterator, Optional, Tuple

from _drgn import _linux_helper_xa_load
from drgn import NULL, IntegerLike, Object, cast

__all__ = (
    "xa_for_each",
    "xa_is_value",
    "xa_is_zero",
    "xa_load",
    "xa_to_value",
)


_XA_ZERO_ENTRY = 1030  # xa_mk_internal(257)


def _xa_is_node(entry_value: int) -> bool:
    return (entry_value & 3) == 2 and entry_value > 4096


def xa_load(xa: Object, index: IntegerLike, *, advanced: bool = False) -> Object:
    """
    Look up the entry at a given index in an XArray.

    >>> entry = xa_load(inode.i_mapping.i_pages.address_of_(), 2)
    >>> cast("struct page *", entry)
    *(struct page *)0xffffed6980306f40 = {
        ...
    }

    :param xa: ``struct xarray *``
    :param index: Entry index.
    :param advanced: Whether to return nodes only visible to the XArray
        advanced API. If ``False``, zero entries (see :func:`xa_is_zero()`)
        will be returned as ``NULL``.
    :return: ``void *`` found entry, or ``NULL`` if not found.
    """
    entry = _linux_helper_xa_load(xa, index)
    if not advanced and entry.value_() == _XA_ZERO_ENTRY:
        return NULL(xa.prog_, "void *")
    return entry


class _XAIteratorNode:
    def __init__(self, node: Object, index: int) -> None:
        self.slots = node.slots
        self.shift = node.shift.value_()
        self.index = index
        self.next_slot = 0


def xa_for_each(xa: Object, *, advanced: bool = False) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the entries in an XArray.

    >>> for index, entry in xa_for_each(inode.i_mapping.i_pages.address_of_()):
    ...     print(index, entry)
    ...
    0 (void *)0xffffed6980356140
    1 (void *)0xffffed6980306f80
    2 (void *)0xffffed6980306f40
    3 (void *)0xffffed6980355b40

    :param xa: ``struct xarray *``
    :param advanced: Whether to return nodes only visible to the XArray
        advanced API. If ``False``, zero entries (see :func:`xa_is_zero()`)
        will be skipped.
    :return: Iterator of (index, ``void *``) tuples.
    """
    prog = xa.prog_

    def should_yield(entry_value: int) -> bool:
        return entry_value != 0

    # This handles three cases:
    #
    # 1. XArrays.
    # 2. Radix trees since Linux kernel commit f8d5d0cc145c ("xarray: Add
    #    definition of struct xarray") (in v4.20) redefined them in terms of
    #    XArrays. These reuse the XArray structures and are close enough to
    #    case 1 that the same code handles both.
    # 3. Radix trees before that commit. These are similar to cases 1 and 2,
    #    but they have different type and member names, use different flags in
    #    the lower bits (see Linux kernel commit 3159f943aafd ("xarray: Replace
    #    exceptional entries") (in v4.20)), and represent sibling entries
    #    differently (see Linux kernel commit 02c02bf12c5d ("xarray: Change
    #    definition of sibling entries") (in v4.20)).
    try:
        entry = xa.xa_head.read_()
    except AttributeError:
        entry = xa.rnode
        node_type = entry.type_
        entry = cast("void *", entry)

        # Return > 0 if radix_tree_is_internal_node(), < 0 if
        # is_sibling_entry(), and 0 otherwise.
        def is_internal(slots: Optional[Object], entry_value: int) -> int:
            if (entry_value & 3) == 1:
                # slots must be a reference object, so address_ is never None.
                if slots is not None and (
                    slots.address_ <= entry_value < slots[len(slots)].address_  # type: ignore[operator]
                ):
                    return -1
                else:
                    return 1
            return 0

        # entry_to_node()
        def to_node(entry_value: int) -> Object:
            return Object(prog, node_type, entry_value - 1)

    else:
        node_type = prog.type("struct xa_node *")

        # Return > 0 if xa_is_node(), < 0 if xa_is_sibling(), and 0 otherwise.
        def is_internal(slots: Optional[Object], entry_value: int) -> int:
            if _xa_is_node(entry_value):
                return 1
            elif (entry_value & 3) == 2 and entry_value < 256:
                return -1
            else:
                return 0

        # xa_to_node()
        def to_node(entry_value: int) -> Object:
            return Object(prog, node_type, entry_value - 2)

        if not advanced:
            # We're intentionally redefining should_yield() for this case.
            def should_yield(entry_value: int) -> bool:  # noqa: F811
                return entry_value != 0 and entry_value != _XA_ZERO_ENTRY

    entry_value = entry.value_()
    internal = is_internal(None, entry_value)
    if internal > 0:
        stack = [_XAIteratorNode(to_node(entry_value), 0)]
    else:
        if internal == 0 and should_yield(entry_value):
            yield 0, entry
        return

    while stack:
        node = stack[-1]
        if node.next_slot >= len(node.slots):
            stack.pop()
            continue

        entry = node.slots[node.next_slot].read_()
        entry_value = entry.value_()

        index = node.index + (node.next_slot << node.shift)
        node.next_slot += 1

        internal = is_internal(node.slots, entry_value)
        if internal > 0:
            stack.append(_XAIteratorNode(to_node(entry_value), index))
        elif internal == 0 and should_yield(entry_value):
            yield index, entry


def xa_is_value(entry: Object) -> bool:
    """
    Return whether an XArray entry is a value.

    See :func:`xa_to_value()`.

    :param entry: ``void *``
    """
    return (entry.value_() & 1) != 0


def xa_to_value(entry: Object) -> Object:
    """
    Return the value in an XArray entry.

    In addition to pointers, XArrays can store integers between 0 and
    ``LONG_MAX``. If :func:`xa_is_value()` returns ``True``, use this to get
    the stored integer.

    >>> entry = xa_load(xa, 9)
    >>> entry
    (void *)0xc9
    >>> xa_is_value(entry)
    True
    >>> xa_to_value(entry)
    (unsigned long)100

    :param entry: ``void *``
    :return: ``unsigned long``
    """
    return cast("unsigned long", entry) >> 1


def xa_is_zero(entry: Object) -> bool:
    """
    Return whether an XArray entry is a "zero" entry.

    A zero entry is an entry that was reserved but is not present. These are
    only visible to the XArray advanced API, so they are only returned by
    :func:`xa_load()` and :func:`xa_for_each()` when ``advanced = True``.

    >>> entry = xa_load(xa, 10, advanced=True)
    >>> entry
    (void *)0x406
    >>> xa_is_zero(entry)
    True
    >>> xa_load(xa, 10)
    (void *)0

    :param entry: ``void *``
    """
    return entry.value_() == _XA_ZERO_ENTRY
