# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Optional acceleration of drgn helper loops via libbpfwalk.

A helper that enumerates a kernel data structure can offer its traversal to an
in-kernel bpfwalk walker: the whole walk runs kernel-side and returns addresses
in O(1) user<->kernel crossings, instead of one read per element. This is only
attempted on a live, local Linux kernel with BPF privilege; everywhere else
(core dumps, remote, no library, unsupported kernel) ``bpfwalk_objects``
returns None and the caller uses its existing implementation unchanged.

Every offloaded helper routes through ``bpfwalk_objects`` -- adding a new one is
a new walker on the bpfwalk side plus a short guard in the helper.
"""

import os
from typing import Iterator, Optional

from drgn import Object, Program, ProgramFlags
from drgn.helpers.linux._bpfwalk import BpfwalkSession

_REQUIRED = (
    ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
)


def _session(prog: Program) -> "Optional[BpfwalkSession]":
    """Return the per-program libbpfwalk session, or None (cached once)."""
    try:
        return prog.cache["bpfwalk"]
    except KeyError:
        session: "Optional[BpfwalkSession]" = None
        # BPFWALK_DISABLE=1 forces the fallback paths everywhere.
        if not os.environ.get("BPFWALK_DISABLE") and (
            prog.flags & _REQUIRED
        ) == _REQUIRED:
            session = BpfwalkSession.open()
        prog.cache["bpfwalk"] = session
        return session


def bpfwalk_objects(
    prog: Program, walker: str, ptr_type: str, args: bytes = b""
) -> "Optional[Iterator[Object]]":
    """
    Enumerate ``ptr_type`` objects via the named bpfwalk walker.

    :return: An iterator of ``ptr_type`` objects, or None if bpfwalk cannot
        serve this walk here (caller should fall back to its own loop).
    """
    session = _session(prog)
    if session is None or not session.has(walker):
        return None
    return (Object(prog, ptr_type, value=addr) for addr in session.walk(walker, args))
