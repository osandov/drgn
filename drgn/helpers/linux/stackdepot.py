# Copyright (c) Google LLC
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Stack Depot
-----------

The ``drgn.helpers.linux.stackdepot`` module provides helpers for working with
the stack trace storage from :linux:`include/linux/stackdepot.h` used by KASAN
and other kernel debugging tools.
"""

from typing import Optional

from drgn import Object, StackTrace, cast, reinterpret

__all__ = ("stack_depot_fetch",)


def stack_depot_fetch(handle: Object) -> Optional[StackTrace]:
    """
    Returns a stack trace for the given stack handle.

    :param handle: ``depot_stack_handle_t``
    :return: The stack trace, or ``None`` if not available.
    """
    prog = handle.prog_
    handle_parts = reinterpret("union handle_parts", handle)

    # Renamed in Linux kernel commit 961c949b012f ("lib/stackdepot: rename slab
    # to pool") (in v6.3).
    try:
        stack_pools = prog["stack_pools"]
    except KeyError:
        pool = prog["stack_slabs"][handle_parts.slabindex]
    else:
        # Linux kernel commit 3ee34eabac2a ("lib/stackdepot: fix first entry
        # having a 0-handle") (in v6.9-rc1) changed the meaning of pool_index.
        # Linux kernel commit a6c1d9cb9a68 ("stackdepot: rename pool_index to
        # pool_index_plus_1") (in v6.9-rc3) renamed pool_index to reflect the
        # new meaning. This will therefore be wrong for v6.9-rc[1-2] and
        # v6.8.[3-4].
        try:
            pool_index = handle_parts.pool_index_plus_1 - 1
        except AttributeError:
            pool_index = handle_parts.pool_index
        pool = stack_pools[pool_index]

    if not pool:
        return None

    # This has remained the same since the stack depot was introduced in Linux
    # kernel commit cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable
    # stackdepot for SLAB") (in v4.6), when it was known as STACK_ALLOC_ALIGN.
    DEPOT_STACK_ALIGN = 4

    record = cast(
        "struct stack_record *", pool + (handle_parts.offset << DEPOT_STACK_ALIGN)
    )
    return prog.stack_trace_from_pcs([record.entries[x] for x in range(record.size)])
