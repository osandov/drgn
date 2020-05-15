# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
IDR
---

The ``drgn.helpers.linux.idr`` module provides helpers for working with the IDR
data structure in :linux:`include/linux/idr.h`. An IDR provides a mapping from
an ID to a pointer. This currently only supports Linux v4.11+; before this,
IDRs were not based on radix trees.
"""

from drgn.helpers.linux.radixtree import radix_tree_for_each, radix_tree_lookup
from _drgn import _linux_helper_idr_find


__all__ = (
    "idr_find",
    "idr_for_each",
)


def idr_find(idr, id):
    """
    .. c:function:: void *idr_find(struct idr *idr, unsigned long id)

    Look up the entry with the given id in an IDR. If it is not found, this
    returns a ``NULL`` object.
    """
    return _linux_helper_idr_find(idr, id)


def idr_for_each(idr):
    """
    .. c:function:: idr_for_each(struct idr *idr)

    Iterate over all of the entries in an IDR.

    :return: Iterator of (index, ``void *``) tuples.
    :rtype: Iterator[tuple[int, Object]]
    """
    try:
        base = idr.idr_base.value_()
    except AttributeError:
        base = 0
    for index, entry in radix_tree_for_each(idr.idr_rt.address_of_()):
        yield index + base, entry
