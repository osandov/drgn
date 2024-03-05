# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
IDR
---

The ``drgn.helpers.linux.idr`` module provides helpers for working with the IDR
data structure in :linux:`include/linux/idr.h`. An IDR provides a mapping from
an ID to a pointer.
"""

import operator
from typing import Iterator, Tuple, Union

from _drgn import _linux_helper_idr_find
from drgn import NULL, IntegerLike, Object, Type, cast, sizeof
from drgn.helpers.linux.radixtree import radix_tree_for_each

__all__ = (
    "idr_find",
    "idr_for_each",
    "idr_for_each_entry",
)

_IDR_BITS = 8
_IDR_MASK = (1 << _IDR_BITS) - 1


def idr_find(idr: Object, id: IntegerLike) -> Object:
    """
    Look up the entry with the given ID in an IDR.

    :param idr: ``struct idr *``
    :param id: Entry ID.
    :return: ``void *`` found entry, or ``NULL`` if not found.
    """
    # Since Linux kernel commit 0a835c4f090a ("Reimplement IDR and IDA using
    # the radix tree") (in v4.11), IDRs are backed by radix trees. Before that,
    # they are a separate data structure. The helper in libdrgn only handles
    # the radix tree version.
    if hasattr(idr, "idr_rt"):
        return _linux_helper_idr_find(idr, id)
    else:
        prog = idr.prog_
        id = operator.index(id)

        if id < 0:
            return NULL(prog, "void *")

        p = idr.top.read_()
        if not p:
            return NULL(prog, "void *")

        n = (p.layer.value_() + 1) * _IDR_BITS
        MAX_IDR_SHIFT = sizeof(prog.type("int")) * 8 - 1
        # Equivalent to id > idr_max(p->layer + 1) in the kernel.
        if id >= (1 << min(n, MAX_IDR_SHIFT)):
            return NULL(prog, "void *")

        while n > 0 and p:
            n -= _IDR_BITS
            p = p.ary[(id >> n) & _IDR_MASK].read_()

        return cast("void *", p)


def idr_for_each(idr: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the pointers in an IDR.

    :param idr: ``struct idr *``
    :return: Iterator of (index, ``void *``) tuples.
    """
    # Since Linux kernel commit 0a835c4f090a ("Reimplement IDR and IDA using
    # the radix tree") (in v4.11), IDRs are backed by radix trees.
    try:
        idr_rt = idr.idr_rt
    except AttributeError:
        voidp_type = idr.prog_.type("void *")

        def aux(p: Object, id: int, n: int) -> Iterator[Tuple[int, Object]]:
            p = p.read_()
            if p:
                if n == 0:
                    yield id, cast(voidp_type, p)
                else:
                    n -= _IDR_BITS
                    for child in p.ary:
                        yield from aux(child, id, n)
                        id += 1 << n

        yield from aux(idr.top, 0, idr.layers.value_() * _IDR_BITS)
    else:
        try:
            base = idr.idr_base.value_()
        except AttributeError:
            base = 0
        for index, entry in radix_tree_for_each(idr_rt.address_of_()):
            yield index + base, entry


def idr_for_each_entry(
    idr: Object, type: Union[str, Type]
) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the entries with the given type in an IDR.

    :param idr: ``struct idr *``
    :param type: Entry type.
    :return: Iterator of (index, ``type *``) tuples.
    """
    prog = idr.prog_
    type = prog.pointer_type(prog.type(type))
    for index, entry in idr_for_each(idr):
        yield index, cast(type, entry)
