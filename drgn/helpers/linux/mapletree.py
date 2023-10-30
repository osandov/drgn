# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Maple Trees
-----------

The ``drgn.helpers.linux.mapletree`` module provides helpers for working with
maple trees from :linux:`include/linux/maple_tree.h`.

Maple trees were introduced in Linux 6.1.
"""

import collections
import operator
from typing import Iterator, Tuple

from drgn import NULL, IntegerLike, Object, Program, sizeof
from drgn.helpers.linux.xarray import _XA_ZERO_ENTRY, _xa_is_node, xa_is_zero

__all__ = (
    "mt_for_each",
    "mtree_load",
)


def _ulong_max(prog: Program) -> int:
    return (1 << (8 * sizeof(prog.type("unsigned long")))) - 1


# Combination of mte_to_node(), mte_node_type(), ma_data_end(), and
# ma_is_leaf().
def _mte_to_node(
    prog: Program, entry_value: int, max: int
) -> Tuple[Object, Object, Object, int, bool]:
    MAPLE_NODE_MASK = 255
    MAPLE_NODE_TYPE_MASK = 0xF
    MAPLE_NODE_TYPE_SHIFT = 0x3
    maple_leaf_64 = 1
    maple_range_64 = 2
    maple_arange_64 = 3

    node = Object(prog, "struct maple_node *", entry_value & ~MAPLE_NODE_MASK)
    type = (entry_value >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK
    if type == maple_arange_64:
        m = node.ma64
        pivots = m.pivot
        slots = m.slot
        end = m.meta.end.value_()
    elif type == maple_range_64 or type == maple_leaf_64:
        m = node.mr64
        pivots = m.pivot
        slots = m.slot
        pivot = pivots[len(pivots) - 1].value_()
        if not pivot:
            end = m.meta.end.value_()
        elif pivot == max:
            end = len(pivots) - 1
        else:
            end = len(pivots)
    else:
        raise NotImplementedError(f"unknown maple_type {type}")

    return node, pivots, slots, end, type < maple_range_64


def mtree_load(mt: Object, index: IntegerLike, *, advanced: bool = False) -> Object:
    """
    Look up the entry at a given index in a maple tree.

    >>> entry = mtree_load(task.mm.mm_mt.address_of_(), 0x55d65cfaa000)
    >>> cast("struct vm_area_struct *", entry)
    *(struct vm_area_struct *)0xffff97ad82bfc930 = {
        ...
    }

    :param mt: ``struct maple_tree *``
    :param index: Entry index.
    :param advanced: Whether to return nodes only visible to the maple tree
        advanced API. If ``False``, zero entries (see
        :func:`~drgn.helpers.linux.xarray.xa_is_zero()`) will be returned as
        ``NULL``.
    :return: ``void *`` found entry, or ``NULL`` if not found.
    """
    prog = mt.prog_
    index = operator.index(index)
    entry = mt.ma_root.read_()
    entry_value = entry.value_()
    if _xa_is_node(entry_value):
        max = _ulong_max(prog)
        while True:
            node, pivots, slots, end, leaf = _mte_to_node(prog, entry_value, max)

            for offset in range(end):
                pivot = pivots[offset].value_()
                if pivot >= index:
                    max = pivot
                    break
            else:
                offset = end

            entry_value = slots[offset].value_()
            if leaf:
                if not advanced and entry_value == _XA_ZERO_ENTRY:
                    return NULL(prog, "void *")
                return Object(prog, "void *", entry_value)
    elif entry_value and index == 0:
        return entry
    else:
        return NULL(prog, "void *")


def mt_for_each(
    mt: Object, *, advanced: bool = False
) -> Iterator[Tuple[int, int, Object]]:
    """
    Iterate over all of the entries and their ranges in a maple tree.

    >>> for first_index, last_index, entry in mt_for_each(task.mm.mm_mt.address_of_()):
    ...     print(hex(first_index), hex(last_index), entry)
    ...
    0x55d65cfaa000 0x55d65cfaafff (void *)0xffff97ad82bfc930
    0x55d65cfab000 0x55d65cfabfff (void *)0xffff97ad82bfc0a8
    0x55d65cfac000 0x55d65cfacfff (void *)0xffff97ad82bfc000
    0x55d65cfad000 0x55d65cfadfff (void *)0xffff97ad82bfcb28
    ...

    :param mt: ``struct maple_tree *``
    :param advanced: Whether to return nodes only visible to the maple tree
        advanced API. If ``False``, zero entries (see
        :func:`~drgn.helpers.linux.xarray.xa_is_zero()`) will be skipped.
    :return: Iterator of (first_index, last_index, ``void *``) tuples. Both
        indices are inclusive.
    """
    entry = mt.ma_root.read_()
    entry_value = entry.value_()
    if _xa_is_node(entry_value):
        prog = mt.prog_
        queue = collections.deque(((entry_value, 0, _ulong_max(prog)),))
        while queue:
            entry_value, min, max = queue.popleft()
            node, pivots, slots, end, leaf = _mte_to_node(prog, entry_value, max)

            if leaf:
                prev = min
                for offset in range(end):
                    pivot = pivots[offset].value_()
                    slot = slots[offset].read_()
                    if slot and (advanced or not xa_is_zero(slot)):
                        yield (prev, pivot, slot)
                    prev = pivot + 1
                slot = slots[end].read_()
                if slot and (advanced or not xa_is_zero(slot)):
                    yield (prev, max, slot)
            else:
                prev = min
                for offset in range(end):
                    pivot = pivots[offset].value_()
                    queue.append((slots[offset].value_(), prev, pivot))
                    prev = pivot + 1
                queue.append((slots[end].value_(), prev, max))
    elif entry_value:
        yield (0, 0, entry)
