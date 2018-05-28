# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel IDR helpers

This module provides helpers for working with the IDR data structure in
"linux/idr.h". An IDR provides a mapping from an ID to a pointer. This
currently only supports Linux v4.11+; before this, IDRs were not based on radix
trees.
"""

from drgn.helpers.kernel.radixtree import radix_tree_for_each, radix_tree_lookup


__all__ = [
    'idr_find',
    'idr_for_each',
]


def idr_find(idr, id):
    """
    void *idr_find(struct idr *, unsigned long id)

    Look up the entry with the given id in an IDR. If it is not found, this
    returns a NULL object.
    """
    # idr_base was added in v4.16.
    try:
        id -= idr.idr_base
    except AttributeError:
        pass
    return radix_tree_lookup(idr.idr_rt, id)


def idr_for_each(idr):
    """
    idr_for_each(struct idr *)

    Return an iterator over all of the entries in an IDR. The generated values
    are (index, entry) tuples.
    """
    try:
        base = idr.idr_base.value_()
    except AttributeError:
        base = 0
    for index, entry in radix_tree_for_each(idr.idr_rt):
        yield index + base, entry
