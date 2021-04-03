# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Red-Black Trees
---------------

The ``drgn.helpers.linux.rbtree`` module provides helpers for working with
red-black trees from :linux:`include/linux/rbtree.h`.
"""

from typing import Callable, Iterator, TypeVar

from drgn import NULL, Object, container_of

__all__ = (
    "RB_EMPTY_NODE",
    "rb_find",
    "rb_first",
    "rb_last",
    "rb_next",
    "rb_parent",
    "rb_prev",
    "rbtree_inorder_for_each",
    "rbtree_inorder_for_each_entry",
)


def RB_EMPTY_NODE(node: Object) -> bool:
    """
    Return whether a red-black tree node is empty, i.e., not inserted in a
    tree.

    :param node: ``struct rb_node *``
    """
    return node.__rb_parent_color.value_() == node.value_()


def rb_parent(node: Object) -> Object:
    """
    Return the parent node of a red-black tree node.

    :param node: ``struct rb_node *``
    :return: ``struct rb_node *``
    """
    return Object(node.prog_, node.type_, value=node.__rb_parent_color.value_() & ~3)


def rb_first(root: Object) -> Object:
    """
    Return the first node (in sort order) in a red-black tree, or ``NULL`` if
    the tree is empty.

    :param root: ``struct rb_root *``
    :return: ``struct rb_node *``
    """
    node = root.rb_node.read_()
    if not node:
        return node
    while True:
        next = node.rb_left.read_()
        if not next:
            return node
        node = next


def rb_last(root: Object) -> Object:
    """
    Return the last node (in sort order) in a red-black tree, or ``NULL`` if
    the tree is empty.

    :param root: ``struct rb_root *``
    :return: ``struct rb_node *``
    """
    node = root.rb_node.read_()
    if not node:
        return node
    while True:
        next = node.rb_right.read_()
        if not next:
            return node
        node = next


def rb_next(node: Object) -> Object:
    """
    Return the next node (in sort order) after a red-black node, or ``NULL`` if
    the node is the last node in the tree or is empty.

    :param node: ``struct rb_node *``
    :return: ``struct rb_node *``
    """
    node = node.read_()

    if RB_EMPTY_NODE(node):
        return NULL(node.prog_, node.type_)

    next = node.rb_right.read_()
    if next:
        node = next
        while True:
            next = node.rb_left.read_()
            if not next:
                return node
            node = next

    parent = rb_parent(node).read_()
    while parent and node == parent.rb_right:
        node = parent
        parent = rb_parent(node).read_()
    return parent


def rb_prev(node: Object) -> Object:
    """
    Return the previous node (in sort order) before a red-black node, or
    ``NULL`` if the node is the first node in the tree or is empty.

    :param node: ``struct rb_node *``
    :return: ``struct rb_node *``
    """
    node = node.read_()

    if RB_EMPTY_NODE(node):
        return NULL(node.prog_, node.type_)

    next = node.rb_left.read_()
    if next:
        node = next
        while True:
            next = node.rb_right.read_()
            if not next:
                return node
            node = next

    parent = rb_parent(node).read_()
    while parent and node == parent.rb_left:
        node = parent
        parent = rb_parent(node).read_()
    return parent


def rbtree_inorder_for_each(root: Object) -> Iterator[Object]:
    """
    Iterate over all of the nodes in a red-black tree, in sort order.

    :param root: ``struct rb_root *``
    :return: Iterator of ``struct rb_node *`` objects.
    """

    def aux(node: Object) -> Iterator[Object]:
        if node:
            yield from aux(node.rb_left.read_())
            yield node
            yield from aux(node.rb_right.read_())

    yield from aux(root.rb_node.read_())


def rbtree_inorder_for_each_entry(
    type: str, root: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a red-black tree in sorted order.

    :param type: Entry type.
    :param root: ``struct rb_root *``
    :param member: Name of red-black node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for node in rbtree_inorder_for_each(root):
        yield container_of(node, type, member)


KeyType = TypeVar("KeyType")


def rb_find(
    type: str,
    root: Object,
    member: str,
    key: KeyType,
    cmp: Callable[[KeyType, Object], int],
) -> Object:
    """
    Find an entry in a red-black tree given a key and a comparator function.

    Note that this function does not have an analogue in the Linux kernel
    source code, as tree searches are all open-coded.

    :param type: Entry type.
    :param root: ``struct rb_root *``
    :param member: Name of red-black node member in entry type.
    :param key: Key to find.
    :param cmp: Callback taking key and entry that returns < 0 if the key is
        less than the entry, > 0 if the key is greater than the entry, and 0 if
        the key matches the entry.
    :return: ``type *`` found entry, or ``NULL`` if not found.
    """
    node = root.rb_node.read_()
    while node:
        entry = container_of(node, type, member)
        ret = cmp(key, entry)
        if ret < 0:
            node = node.rb_left.read_()
        elif ret > 0:
            node = node.rb_right.read_()
        else:
            return entry
    return NULL(root.prog_, type)
