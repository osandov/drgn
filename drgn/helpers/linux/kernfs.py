# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Kernfs
------

The ``drgn.helpers.linux.kernfs`` module provides helpers for working with the
kernfs pseudo filesystem interface in :linux:`include/linux/kernfs.h`.
"""

import os
from typing import Iterator

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


def kernfs_walk(parent: Object, path: Path, follow_symlinks: bool = False) -> Object:
    """
    Find the kernfs node with the given path from the given parent kernfs node.

    :param parent: ``struct kernfs_node *``
    :param path: Path name.
    :param follow_symlinks: If follow_symlinks is ``False``, and the
        last component of a path is a symlink, the function will
        return ``struct kernfs_node *`` of the symbolic link.
    :return: ``struct kernfs_node *`` (``NULL`` if not found)
    """
    kernfs_nodep_type = parent.type_
    link_flag = parent.prog_.constant("KERNFS_LINK")
    for name in os.fsencode(path).split(b"/"):
        if not name:
            continue

        for parent in kernfs_children(parent):
            if (
                parent.name.string_() == name
                and not parent.ns  # For now, we don't bother with namespaced kernfs nodes.
            ):
                break
        else:
            return NULL(parent.prog_, kernfs_nodep_type)
    if parent.flags & link_flag and follow_symlinks:
        parent = parent.symlink.target_kn
    return parent


def kernfs_children(kn: Object) -> Iterator[Object]:
    """
    Iterate over the children of a directory in kernfs.

    :param parent: ``struct kernfs_node *``
    :return: Iterator of ``struct kernfs_node *``.
    """
    for child in rbtree_inorder_for_each_entry(
        "struct kernfs_node", kn.dir.children.address_of_(), "rb"
    ):
        yield child
