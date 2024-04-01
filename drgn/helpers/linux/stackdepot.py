# Copyright (c) Google LLC
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Stack Depot
-----------

The ``drgn.helpers.linux.stackdepot`` module provides helpers for working with
the stack trace storage from :linux:`include/linux/stackdepot.h` used by KASAN
and other kernel debugging tools.
"""

from typing import Optional, Tuple

from drgn import Object, StackTrace, cast, reinterpret

__all__ = ("stack_depot_fetch",)


def stack_depot_fetch(handle: Object) -> Optional[StackTrace]:
    """
    Returns a stack trace for the given stack handle.

    :param handle: ``depot_stack_handle_t``
    :return: The stack trace, or ``None`` if not available.
    """
    prog = handle.prog_
    handle = handle.read_()
    handle_parts = reinterpret("union handle_parts", handle)

    # Renamed in Linux kernel commit 961c949b012f ("lib/stackdepot: rename slab
    # to pool") (in v6.3).
    try:
        pools = prog["stack_pools"]
    except KeyError:
        pools = prog["stack_slabs"]
        pool_index = handle_parts.slabindex.value_()
        try_offsets: Tuple[int, ...] = (0,)
        offset_cached = True
    else:
        pool_index = handle_parts.pool_index.value_()
        # Linux kernel commit 3ee34eabac2a ("lib/stackdepot: fix first entry
        # having a 0-handle") (in v6.9), which was also backported to some
        # stable branches, changed pool_index to mean the actual index + 1. The
        # only way to tell is to try both pool_index - 1 and pool_index (as
        # long as they're in bounds). Once we find a match, we can cache the
        # correct offset.
        try:
            try_offsets = (prog.cache["stack_depot_pool_index_offset"],)
            offset_cached = True
        except KeyError:
            if pool_index == 0:
                try_offsets = (0,)
            elif pool_index == prog["pools_num"].value_():
                try_offsets = (-1,)
            else:
                try_offsets = (-1, 0)
            offset_cached = False

    # This has remained the same since the stack depot was introduced in Linux
    # kernel commit cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable
    # stackdepot for SLAB") (in v4.6), when it was known as STACK_ALLOC_ALIGN.
    DEPOT_STACK_ALIGN = 4

    for offset in try_offsets:
        pool = pools[pool_index + offset].read_()
        if pool:
            record = cast(
                "struct stack_record *",
                pool + (handle_parts.offset << DEPOT_STACK_ALIGN),
            )
            # If there are other offsets to try, make sure that this is the
            # correct record.
            if offset != try_offsets[-1] and record.handle.handle != handle:
                continue
            if not offset_cached:
                prog.cache["stack_depot_pool_index_offset"] = offset
            return prog.stack_trace_from_pcs(
                [record.entries[x] for x in range(record.size)]
            )
    return None
