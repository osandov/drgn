# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel radix tree helpers

This module provides helpers for working with radix trees from
"linux/radix-tree.h".
"""

from drgn import cast, Object


__all__ = [
    'radix_tree_lookup',
    'radix_tree_for_each',
]

_RADIX_TREE_ENTRY_MASK = 3


def _is_internal_node(node, internal_node):
    return (node.value_() & _RADIX_TREE_ENTRY_MASK) == internal_node


def _entry_to_node(node, internal_node):
    return Object(node.prog_, node.type_, value=node.value_() & ~internal_node)


def _radix_tree_root_node(root):
    try:
        node = root.xa_head
    except AttributeError:
        return root.rnode.read_once_(), 1
    else:
        return cast('struct xa_node *', node).read_once_(), 2


def radix_tree_lookup(root, index):
    """
    void *radix_tree_lookup(struct radix_tree_root *, unsigned long index)

    Look up the entry at a given index in a radix tree. If it is not found,
    this returns a NULL object.
    """
    node, RADIX_TREE_INTERNAL_NODE = _radix_tree_root_node(root)
    RADIX_TREE_MAP_MASK = node.type_.type.typeof('slots').size - 1
    while True:
        if not _is_internal_node(node, RADIX_TREE_INTERNAL_NODE):
            break
        parent = _entry_to_node(node, RADIX_TREE_INTERNAL_NODE)
        offset = (index >> parent.shift) & RADIX_TREE_MAP_MASK
        node = cast(parent.type_, parent.slots[offset]).read_once_()
    return cast('void *', node)


def radix_tree_for_each(root):
    """
    radix_tree_for_each(struct radix_tree_root *)

    Return an iterator over all of the entries in a radix tree. The generated
    values are (index, entry) tuples.
    """
    node, RADIX_TREE_INTERNAL_NODE = _radix_tree_root_node(root)
    def aux(node, index):
        if _is_internal_node(node, RADIX_TREE_INTERNAL_NODE):
            parent = _entry_to_node(node, RADIX_TREE_INTERNAL_NODE)
            for i, slot in enumerate(parent.slots):
                yield from aux(cast(parent.type_, slot).read_once_(),
                               index + (i << parent.shift.value_()))
        elif node:
            yield index, cast('void *', node)
    yield from aux(node, 0)
