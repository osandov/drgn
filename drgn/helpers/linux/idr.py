# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
IDR
---

The ``drgn.helpers.linux.idr`` module provides helpers for working with the IDR
data structure in :linux:`include/linux/idr.h`. An IDR provides a mapping from
an ID to a pointer. This currently only supports Linux v4.11+; before this,
IDRs were not based on radix trees.
"""

from typing import Iterator, Tuple

from _drgn import _linux_helper_idr_find as idr_find
from drgn import Object
from drgn.helpers.linux.radixtree import radix_tree_for_each, radix_tree_lookup

__all__ = (
    "idr_find",
    "idr_for_each",
)


def idr_for_each(idr: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the entries in an IDR.

    :param idr: ``struct idr *``
    :return: Iterator of (index, ``void *``) tuples.
    """
    try:
        base = idr.idr_base.value_()
    except AttributeError:
        base = 0
    for index, entry in radix_tree_for_each(idr.idr_rt.address_of_()):
        yield index + base, entry
