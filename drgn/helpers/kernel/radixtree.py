# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel radix tree helpers

This module provides helpers for working with radix trees from
"linux/radix-tree.h". Note that it does not support multiorder radix trees yet.
"""

__all__ = [
    'radix_tree_lookup',
    'radix_tree_for_each',
]

_RADIX_TREE_ENTRY_MASK = 3
_RADIX_TREE_INTERNAL_NODE = 1


def _is_internal_node(node):
    return (node.value_() & _RADIX_TREE_ENTRY_MASK) == _RADIX_TREE_INTERNAL_NODE


def _internal_node(node):
    return node.prog_.object(node.type_,
                             value=node.value_() & ~_RADIX_TREE_INTERNAL_NODE)


def radix_tree_lookup(root, index):
    """
    void *radix_tree_lookup(struct radix_tree_root *, unsigned long index)

    Look up the entry at a given index in a radix tree. If it is not found,
    this returns a NULL object.
    """
    node = root.rnode.read_once_()
    RADIX_TREE_MAP_MASK = node.type_.type.typeof('slots').size - 1
    while True:
        if not _is_internal_node(node):
            break
        parent = _internal_node(node)
        offset = (index >> parent.shift) & RADIX_TREE_MAP_MASK
        node = parent.slots[offset].cast_(parent.type_).read_once_()
    return node.cast_('void *')


def radix_tree_for_each(root):
    """
    radix_tree_for_each(struct radix_tree_root *)

    Return an iterator over all of the entries in a radix tree. The generated
    values are (index, entry) tuples.
    """
    def aux(node, index):
        if _is_internal_node(node):
            parent = _internal_node(node)
            for i, slot in enumerate(parent.slots):
                yield from aux(slot.cast_(parent.type_).read_once_(),
                               index + (i << parent.shift.value_()))
        elif node:
            yield index, node.cast_('void *')
    yield from aux(root.rnode.read_once_(), 0)
