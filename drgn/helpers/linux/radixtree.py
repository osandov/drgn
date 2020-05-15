# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Radix Trees
-----------

The ``drgn.helpers.linux.radixtree`` module provides helpers for working with
radix trees from :linux:`include/linux/radix-tree.h`.
"""

from drgn import Object, cast
from _drgn import _linux_helper_radix_tree_lookup


__all__ = (
    "radix_tree_for_each",
    "radix_tree_lookup",
)

_RADIX_TREE_ENTRY_MASK = 3


def _is_internal_node(node, internal_node):
    return (node.value_() & _RADIX_TREE_ENTRY_MASK) == internal_node


def _entry_to_node(node, internal_node):
    return Object(node.prog_, node.type_, value=node.value_() & ~internal_node)


def _radix_tree_root_node(root):
    try:
        node = root.xa_head
    except AttributeError:
        return root.rnode.read_(), 1
    else:
        return cast("struct xa_node *", node).read_(), 2


def radix_tree_lookup(root, index):
    """
    .. c:function:: void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)

    Look up the entry at a given index in a radix tree. If it is not found,
    this returns a ``NULL`` object.
    """
    return _linux_helper_radix_tree_lookup(root, index)


def radix_tree_for_each(root):
    """
    .. c:function:: radix_tree_for_each(struct radix_tree_root *root)

    Iterate over all of the entries in a radix tree.

    :return: Iterator of (index, ``void *``) tuples.
    :rtype: Iterator[tuple[int, Object]]
    """
    node, RADIX_TREE_INTERNAL_NODE = _radix_tree_root_node(root)

    def aux(node, index):
        if _is_internal_node(node, RADIX_TREE_INTERNAL_NODE):
            parent = _entry_to_node(node, RADIX_TREE_INTERNAL_NODE)
            for i, slot in enumerate(parent.slots):
                yield from aux(
                    cast(parent.type_, slot).read_(),
                    index + (i << parent.shift.value_()),
                )
        elif node:
            yield index, cast("void *", node)

    yield from aux(node, 0)
