# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Panic
-----

The ``drgn.helpers.linux.panic`` module provides helpers for getting kernel
panic information.
"""

import re
from typing import Optional

from drgn import NULL, Object, ObjectNotFoundError, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.printk import get_dmesg

__all__ = (
    "panic_message",
    "panic_task",
    "tainted",
)


@takes_program_or_default
def panic_task(prog: Program) -> Object:
    """
    Return the task that panicked.

    This is equivalent to:

    .. code-block:: python3

        from drgn import NULL


        try:
            task = prog.crashed_thread().object
        except ValueError:
            task = NULL(prog, "struct task_struct *")

    :return: ``struct task_struct *`` (``NULL`` if the kernel has not panicked)
    """
    try:
        return prog.crashed_thread().object
    except ValueError:
        return NULL(prog, "struct task_struct *")


# Patterns matching a panic, ranked from most preferred to least preferred.
_PANIC_PATTERNS = (
    rb"Kernel panic -.*",
    # Various architecture faults.
    rb"BUG: (?:kernel NULL pointer dereference|unable to handle).*|Unable to handle kernel.*",
    # BUG_ON() and co.
    rb"[Kk]ernel BUG at.*",
    rb"Oops: .*",
)

_PANIC_PATTERN = b"|".join([b"(%s)" % pattern for pattern in _PANIC_PATTERNS])


def _panic_message(dmesg: bytes) -> Optional[bytes]:
    best_match = None
    best_index = None
    for match in re.finditer(_PANIC_PATTERN, dmesg):
        if best_index is None or match.lastindex < best_index:
            best_match = match.group()
            best_index = match.lastindex
    return best_match


@takes_program_or_default
def panic_message(prog: Program) -> Optional[bytes]:
    """
    Get the kernel message logged during a panic.

    >>> panic_message()
    b'Oops: Oops: 0002 [#1] SMP NOPTI'

    Note that this returns :class:`bytes`. The recommended way to get a
    :class:`str` is with :meth:`bytes.decode(errors="replace") <bytes.decode>`:

    .. code-block:: python3

        message = panic_message()
        if message is not None:
            message = message.decode(errors="replace")

    :return: Message, or ``None`` if the kernel has not panicked or no message
        was found
    """
    return _panic_message(get_dmesg(prog, timestamps=False))


@takes_program_or_default
def tainted(prog: Program) -> str:
    """
    Get the kernel's tainted flags as a string.

    If the kernel is not tainted, then this returns an empty string:

    >>> tainted()
    ''

    Otherwise, it returns the flags as letters:

    >>> tainted()
    'G           O       '

    See the `kernel documentation
    <https://docs.kernel.org/admin-guide/tainted-kernels.html>`_ for an
    explanation of the flags.
    """
    mask = prog["tainted_mask"].value_()
    if not mask:
        return ""

    parts = []
    try:
        taint_flags = prog["taint_flags"]
    except ObjectNotFoundError:
        # Before Linux kernel commit 7fd8329ba502 ("taint/module: Clean up
        # global and module taint flags handling") (in v4.10), the array and
        # members had different names and the bit number was a member.
        for t in prog["tnts"]:
            parts.append(chr(t.true if (mask & (1 << t.bit.value_())) else t.false))  # type: ignore[arg-type]  # python/typeshed#13494
    else:
        for i, t in enumerate(taint_flags):
            parts.append(chr(t.c_true if (mask & (1 << i)) else t.c_false))  # type: ignore[arg-type]  # python/typeshed#13494
    return "".join(parts)
