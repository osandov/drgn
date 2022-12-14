# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Radix Trees
-----------

The ``drgn.helpers.linux.radixtree`` module provides helpers for working with
radix trees from :linux:`include/linux/radix-tree.h`.

.. seealso::

    `XArrays`_, which were introduced in Linux 4.20 as a replacement for radix
    trees.
"""

from typing import Iterator, Tuple

from drgn import IntegerLike, Object
from drgn.helpers.linux.xarray import xa_for_each, xa_load

__all__ = (
    "radix_tree_for_each",
    "radix_tree_lookup",
)


def radix_tree_lookup(root: Object, index: IntegerLike) -> Object:
    """
    Look up the entry at a given index in a radix tree.

    :param root: ``struct radix_tree_root *``
    :param index: Entry index.
    :return: ``void *`` found entry, or ``NULL`` if not found.
    """
    return xa_load(root, index)


def radix_tree_for_each(root: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the entries in a radix tree.

    :param root: ``struct radix_tree_root *``
    :return: Iterator of (index, ``void *``) tuples.
    """
    return xa_for_each(root)
