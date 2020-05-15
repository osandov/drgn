# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Kernfs
------

The ``drgn.helpers.linux.kernfs`` module provides helpers for working with the
kernfs pseudo filesystem interface in :linux:`include/linux/kernfs.h`.
"""

__all__ = (
    "kernfs_name",
    "kernfs_path",
)


def kernfs_name(kn):
    """
    .. c:function:: char *kernfs_name(struct kernfs_node *kn)

    Get the name of the given kernfs node.

    :rtype: bytes
    """
    if not kn:
        return b"(null)"
    return kn.name.string_() if kn.parent else b"/"


def _kernfs_root(kn):
    if kn.parent:
        kn = kn.parent
    return kn.dir.root


def kernfs_path(kn):
    """
    .. c:function:: char *kernfs_path(struct kernfs_node *kn)

    Get full path of the given kernfs node.

    :rtype: bytes
    """
    if not kn:
        return b"(null)"

    root_kn = _kernfs_root(kn).kn
    if kn == root_kn:
        return b"/"

    names = []
    while kn != root_kn:
        names.append(kn.name.string_())
        kn = kn.parent
    names.append(root_kn.name.string_())
    names.reverse()

    return b"/".join(names)
