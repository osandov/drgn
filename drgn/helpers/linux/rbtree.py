# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Red-Black Trees
---------------

The ``drgn.helpers.linux.rbtree`` module provides helpers for working with
red-black trees from :linux:`include/linux/rbtree.h`.
"""

from drgn import Object, NULL, container_of


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


def RB_EMPTY_NODE(node):
    """
    .. c:function:: bool RB_EMPTY_NODE(struct rb_node *node)

    Return whether a red-black tree node is empty, i.e., not inserted in a
    tree.
    """
    return node.__rb_parent_color.value_() == node.value_()


def rb_parent(node):
    """
    .. c:function:: struct rb_node *rb_parent(struct rb_node *node)

    Return the parent node of a red-black tree node.
    """
    return Object(node.prog_, node.type_, value=node.__rb_parent_color.value_() & ~3)


def rb_first(root):
    """
    .. c:function:: struct rb_node *rb_first(struct rb_root *root)

    Return the first node (in sort order) in a red-black tree, or a ``NULL``
    object if the tree is empty.
    """
    node = root.rb_node.read_()
    if not node:
        return node
    while True:
        next = node.rb_left.read_()
        if not next:
            return node
        node = next


def rb_last(root):
    """
    .. c:function:: struct rb_node *rb_last(struct rb_root *root)

    Return the last node (in sort order) in a red-black tree, or a ``NULL``
    object if the tree is empty.
    """
    node = root.rb_node.read_()
    if not node:
        return node
    while True:
        next = node.rb_right.read_()
        if not next:
            return node
        node = next


def rb_next(node):
    """
    .. c:function:: struct rb_node *rb_next(struct rb_node *node)

    Return the next node (in sort order) after a red-black node, or a ``NULL``
    object if the node is the last node in the tree or is empty.
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


def rb_prev(node):
    """
    .. c:function:: struct rb_node *rb_prev(struct rb_node *node)

    Return the previous node (in sort order) before a red-black node, or a
    ``NULL`` object if the node is the first node in the tree or is empty.
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


def rbtree_inorder_for_each(root):
    """
    .. c:function:: rbtree_inorder_for_each(struct rb_root *root)

    Iterate over all of the nodes in a red-black tree, in sort order.

    :return: Iterator of ``struct rb_node *`` objects.
    """

    def aux(node):
        if node:
            yield from aux(node.rb_left.read_())
            yield node
            yield from aux(node.rb_right.read_())

    yield from aux(root.rb_node.read_())


def rbtree_inorder_for_each_entry(type, root, member):
    """
    .. c:function:: rbtree_inorder_for_each_entry(type, struct rb_root *root, member)

    Iterate over all of the entries in a red-black tree, given the type of the
    entry and the ``struct rb_node`` member in that type. The entries are
    returned in sort order.

    :return: Iterator of ``type *`` objects.
    """
    for node in rbtree_inorder_for_each(root):
        yield container_of(node, type, member)


def rb_find(type, root, member, key, cmp):
    """
    .. c:function:: type *rb_find(type, struct rb_root *root, member, key_type key, int (*cmp)(key_type, type *))

    Find an entry in a red-black tree, given a key and a comparator function
    which takes the key and an entry. The comparator should return < 0 if the
    key is less than the entry, > 0 if it is greater than the entry, or 0 if it
    matches the entry. This returns a ``NULL`` object if no entry matches the
    key.

    Note that this function does not have an analogue in the Linux kernel
    source code, as tree searches are all open-coded.
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
    return node
