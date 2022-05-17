# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Red-Black Trees
---------------

The ``drgn.helpers.linux.rbtree`` module provides helpers for working with
red-black trees from :linux:`include/linux/rbtree.h`.
"""

from typing import Callable, Generator, Iterator, Tuple, TypeVar, Union

from drgn import NULL, Object, Type, container_of
from drgn.helpers import ValidationError

__all__ = (
    "RB_EMPTY_ROOT",
    "RB_EMPTY_NODE",
    "rb_find",
    "rb_first",
    "rb_last",
    "rb_next",
    "rb_parent",
    "rb_prev",
    "rbtree_inorder_for_each",
    "rbtree_inorder_for_each_entry",
    "validate_rbtree",
    "validate_rbtree_inorder_for_each_entry",
)


def RB_EMPTY_ROOT(root: Object) -> bool:
    """
    Return whether a red-black tree is empty.

    :param node: ``struct rb_root *``
    """
    return not root.rb_node


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


# Return parent node and whether the node is black.
def _rb_parent_color(node: Object) -> Tuple[Object, bool]:
    value = node.__rb_parent_color.value_()
    return Object(node.prog_, node.type_, value=value & ~3), (value & 1) != 0


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
    type: Union[str, Type], root: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a red-black tree in sorted order.

    :param type: Entry type.
    :param root: ``struct rb_root *``
    :param member: Name of red-black node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    type = root.prog_.type(type)
    for node in rbtree_inorder_for_each(root):
        yield container_of(node, type, member)


KeyType = TypeVar("KeyType")


def rb_find(
    type: Union[str, Type],
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
    prog = root.prog_
    type = prog.type(type)
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
    return NULL(prog, prog.pointer_type(type))


def validate_rbtree(
    type: Union[str, Type],
    root: Object,
    member: str,
    cmp: Callable[[Object, Object], int],
    allow_equal: bool,
) -> None:
    """
    Validate a red-black tree.

    This checks that:

    1. The tree is a valid binary search tree ordered according to *cmp*.
    2. If *allow_equal* is ``False``, there are no nodes that compare equal
       according to *cmp*.
    3. The ``rb_parent`` pointers are consistent.
    4. The red-black tree requirements are satisfied: the root node is black,
       no red node has a red child, and every path from any node to any of its
       descendant leaf nodes goes through the same number of black nodes.
    """
    for _ in validate_rbtree_inorder_for_each_entry(
        type, root, member, cmp, allow_equal
    ):
        pass


def validate_rbtree_inorder_for_each_entry(
    type: Union[str, Type],
    root: Object,
    member: str,
    cmp: Callable[[Object, Object], int],
    allow_equal: bool,
) -> Iterator[Object]:
    prog = root.prog_
    type = prog.type(type)

    def visit(
        node: Object,
        parent_node: Object,
        parent_entry: Object,
        parent_is_red: bool,
        is_left: bool,
    ) -> Generator[Object, None, int]:
        if node:
            node_rb_parent, black = _rb_parent_color(node)
            if node_rb_parent != parent_node:
                raise ValidationError(
                    f"{parent_node.format_(dereference=False, symbolize=False)}"
                    f" rb_{'left' if is_left else 'right'}"
                    f" {node.format_(dereference=False, symbolize=False, type_name=False)}"
                    f" has rb_parent {node_rb_parent.format_(dereference=False, symbolize=False, type_name=False)}"
                )

            if parent_is_red and not black:
                raise ValidationError(
                    f"red node {parent_node.format_(dereference=False, symbolize=False)}"
                    f" has red child {node.format_(dereference=False, symbolize=False, type_name=False)}"
                )

            entry = container_of(node, type, member)
            r = cmp(entry, parent_entry)
            if r > 0:
                if is_left:
                    raise ValidationError(
                        f"{parent_entry.format_(dereference=False, symbolize=False)}"
                        f" left child {entry.format_(dereference=False, symbolize=False, type_name=False)}"
                        " compares greater than it"
                    )
            elif r < 0:
                if not is_left:
                    raise ValidationError(
                        f"{parent_entry.format_(dereference=False, symbolize=False)}"
                        f" right child {entry.format_(dereference=False, symbolize=False, type_name=False)}"
                        " compares less than it"
                    )
            elif not allow_equal:
                raise ValidationError(
                    f"{parent_entry.format_(dereference=False, symbolize=False)}"
                    f" {'left' if is_left else 'right'}"
                    f" child {entry.format_(dereference=False, symbolize=False, type_name=False)}"
                    " compares equal to it"
                )

            return (yield from descend(node, entry, black))
        else:
            return 0

    def descend(
        node: Object, entry: Object, black: bool
    ) -> Generator[Object, None, int]:
        left_black_height = yield from visit(
            node.rb_left.read_(), node, entry, parent_is_red=not black, is_left=True
        )
        yield entry
        right_black_height = yield from visit(
            node.rb_right.read_(), node, entry, parent_is_red=not black, is_left=False
        )
        if left_black_height != right_black_height:
            raise ValidationError(
                f"left and right subtrees of {node.format_(dereference=False, symbolize=False)}"
                f" have unequal black heights ({left_black_height} != {right_black_height})"
            )
        return left_black_height + black

    root_node = root.rb_node.read_()
    if root_node:
        parent, black = _rb_parent_color(root_node)
        if parent:
            raise ValidationError(
                f"root node {root_node.format_(dereference=False, symbolize=False)}"
                f" has parent {parent.format_(dereference=False, symbolize=False, type_name=False)}"
            )
        if not black:
            raise ValidationError(
                f"root node {root_node.format_(dereference=False, symbolize=False)} is red"
            )
        yield from descend(root_node, container_of(root_node, type, member), black)
