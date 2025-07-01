# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Kernfs
------

The ``drgn.helpers.linux.kernfs`` module provides helpers for working with the
kernfs pseudo filesystem interface in :linux:`include/linux/kernfs.h`.
"""

import os
from typing import Iterator, Optional

from drgn import NULL, Object, Path
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

__all__ = (
    "kernfs_name",
    "kernfs_parent",
    "kernfs_path",
    "kernfs_root",
    "kernfs_walk",
    "kernfs_children",
)


def kernfs_root(kn: Object) -> Object:
    """
    Get the kernfs root that the given kernfs node belongs to.

    :param kn: ``struct kernfs_node *``
    :return: ``struct kernfs_root *``
    """
    knp = kernfs_parent(kn)
    if knp:
        kn = knp
    return kn.dir.root.read_()


def kernfs_parent(kn: Object) -> Object:
    """
    Get the parent of the given kernfs node.

    :param kn: ``struct kernfs_node *``
    :return: ``struct kernfs_node *``
    """
    # Linux kernel commit 633488947ef6 ("kernfs: Use RCU to access
    # kernfs_node::parent.") (in v6.15) renamed the parent member.
    try:
        return kn.__parent.read_()
    except AttributeError:
        return kn.parent.read_()


def kernfs_name(kn: Object) -> bytes:
    """
    Get the name of the given kernfs node.

    :param kn: ``struct kernfs_node *``
    """
    if not kn:
        return b"(null)"
    return kn.name.string_() if kernfs_parent(kn) else b"/"


def kernfs_path(kn: Object) -> bytes:
    """
    Get full path of the given kernfs node.

    :param kn: ``struct kernfs_node *``
    """
    if not kn:
        return b"(null)"

    root_kn = kernfs_root(kn).kn
    if kn == root_kn:
        return b"/"

    names = []
    while kn != root_kn:
        names.append(kn.name.string_())
        kn = kernfs_parent(kn)
    names.append(root_kn.name.string_())
    names.reverse()

    return b"/".join(names)


def _kernfs_node_type(kn: Object, node_type: str) -> bool:
    KERNFS_TYPE_MASK = 0x000F
    return kn.flags & KERNFS_TYPE_MASK == kn.prog_.constant(node_type)


def _kernfs_follow_symlink(parent: Object) -> Object:
    while _kernfs_node_type(parent, "KERNFS_LINK"):
        parent = parent.symlink.target_kn
    return parent


def kernfs_walk(parent: Object, path: Path, follow_symlinks: bool = True) -> Object:
    """
    Find the kernfs node with the given path from the given parent kernfs node.

    :param parent: ``struct kernfs_node *``
    :param path: Path name.
    :param follow_symlinks: If True (default), all symbolic links encountered
        in the path, including the final component, are followed and the
        function returns the target node. If False, all intermediate symlinks
        are still followed, but if the final component is a symlink, the
        function returns the symlink node itself rather than its target.
    :return: ``struct kernfs_node *`` (``NULL`` if not found)
    """
    kernfs_nodep_type = parent.type_
    kernfs_node_type = kernfs_nodep_type.type
    for name in os.fsencode(path).split(b"/"):
        if not name:
            continue

        parent = _kernfs_follow_symlink(parent)

        for parent in rbtree_inorder_for_each_entry(
            kernfs_node_type, parent.dir.children.address_of_(), "rb"
        ):
            if (
                parent.name.string_() == name
                and not parent.ns  # For now, we don't bother with namespaced kernfs nodes.
            ):
                break
        else:
            return NULL(parent.prog_, kernfs_nodep_type)

    if follow_symlinks:
        parent = _kernfs_follow_symlink(parent)

    return parent


def kernfs_children(kn: Object) -> Optional[Iterator[Object]]:
    """
    Get an iterator over the children of the given kernfs node if the node
    represents a directory.

    :param kn: ``struct kernfs_node *``
    :return: Iterator of ``struct kernfs_node *`` objects.
    """
    if not _kernfs_node_type(kn, "KERNFS_DIR"):
        raise ValueError("not a directory")

    return rbtree_inorder_for_each_entry(
        "struct kernfs_node", kn.dir.children.address_of_(), "rb"
    )
