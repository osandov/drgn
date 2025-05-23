# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Timekeeping
-----------

The ``drgn.helpers.linux.timekeeping`` module provides helpers for timestamps.

.. note::

    In core dumps, it is only possible to recover coarse timestamps, which are
    only updated once per tick (~1-10 ms). Therefore, only the
    ``ktime_get_seconds()`` and ``ktime_get_coarse_ns()`` families of functions
    are provided.
"""

from drgn import Object, Program, cast
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "ktime_get_boottime_seconds",
    "ktime_get_clocktai_seconds",
    "ktime_get_coarse_boottime_ns",
    "ktime_get_coarse_clocktai_ns",
    "ktime_get_coarse_ns",
    "ktime_get_coarse_real_ns",
    "ktime_get_real_seconds",
    "ktime_get_seconds",
    "uptime",
    "uptime_pretty",
)


@takes_program_or_default
def ktime_get_seconds(prog: Program) -> Object:
    """
    Get the seconds component of the monotonic time
    (``CLOCK_MONOTONIC_COARSE``).

    :return: ``time64_t``
    """
    return cast("time64_t", prog["tk_core"].timekeeper.ktime_sec)


@takes_program_or_default
def ktime_get_coarse_ns(prog: Program) -> Object:
    """
    Get the coarse monotonic time in nanoseconds (``CLOCK_MONOTONIC_COARSE``).

    :return: ``u64``
    """
    tk = prog["tk_core"].timekeeper
    # Since Linux kernel commit 2456e8553544 ("ktime: Get rid of the union")
    # (in v4.10), ktime_t is a typedef of s64. Before that, it was a dummy
    # union wrapping an s64.
    try:
        base = cast("u64", tk.tkr_mono.base)
    except TypeError:
        base = cast("u64", tk.tkr_mono.base.tv64)
    # Since Linux kernel commit b71f9804f66c ("timekeeping: Prevent coarse
    # clocks going backwards") (in v6.15), the nanoseconds part is directly in
    # struct timekeeper::coarse_nsec. Before that, it is computed from
    # struct timekeeper::tkr_mono.
    try:
        nsecs = tk.coarse_nsec
    except AttributeError:
        nsecs = tk.tkr_mono.xtime_nsec >> tk.tkr_mono.shift
    return base + nsecs


def _ktime_get_coarse_ns_with_offset(prog: Program, offs_name: str) -> Object:
    ns = ktime_get_coarse_ns(prog)
    offset = prog.variable("offsets", "timekeeping.c")[prog[offs_name]]
    # Handle old union ktime. See the comment in ktime_get_coarse_ns().
    try:
        return ns + offset[0]
    except TypeError:
        return ns + offset.tv64


@takes_program_or_default
def ktime_get_real_seconds(prog: Program) -> Object:
    """
    Get the seconds component of the real (wall) time
    (``CLOCK_REALTIME_COARSE``).

    :return: ``time64_t``
    """
    return cast("time64_t", prog["tk_core"].timekeeper.xtime_sec)


@takes_program_or_default
def ktime_get_coarse_real_ns(prog: Program) -> Object:
    """
    Get the coarse real (wall) time in nanoseconds (``CLOCK_REALTIME_COARSE``).

    :return: ``u64``
    """
    return _ktime_get_coarse_ns_with_offset(prog, "TK_OFFS_REAL")


@takes_program_or_default
def ktime_get_boottime_seconds(prog: Program) -> Object:
    """
    Get the seconds component of the monotonic time since boot (coarse version
    of ``CLOCK_BOOTTIME``).

    :return: ``time64_t``
    """
    return cast("time64_t", ktime_get_coarse_boottime_ns(prog) / 1000000000)


@takes_program_or_default
def ktime_get_coarse_boottime_ns(prog: Program) -> Object:
    """
    Get the the coarse monotonic time since boot in nanoseconds (coarse version
    of ``CLOCK_BOOTTIME``).

    :return: ``u64``
    """
    return _ktime_get_coarse_ns_with_offset(prog, "TK_OFFS_BOOT")


@takes_program_or_default
def ktime_get_clocktai_seconds(prog: Program) -> Object:
    """
    Get the seconds component of the International Atomic Time (coarse version
    of ``CLOCK_TAI``).

    :return: ``time64_t``
    """
    return cast("time64_t", ktime_get_coarse_clocktai_ns(prog) / 1000000000)


@takes_program_or_default
def ktime_get_coarse_clocktai_ns(prog: Program) -> Object:
    """
    Get the coarse International Atomic Time in nanoseconds (coarse version of ``CLOCK_TAI``).

    :return: ``u64``
    """
    return _ktime_get_coarse_ns_with_offset(prog, "TK_OFFS_TAI")


@takes_program_or_default
def uptime(prog: Program) -> float:
    """Get the system uptime (as of the last tick) in fractional seconds."""
    return ktime_get_coarse_boottime_ns(prog).value_() / 1e9


@takes_program_or_default
def uptime_pretty(prog: Program) -> str:
    """
    Get the system uptime as a human-readable string.

    >>> uptime_pretty()
    '1 day, 6 hours, 56 minutes, 40 seconds'
    """
    seconds = ktime_get_boottime_seconds(prog).value_()

    parts = []
    for unit, seconds_in_unit in (
        ("year", 365 * 24 * 60 * 60),
        ("week", 7 * 24 * 60 * 60),
        ("day", 24 * 60 * 60),
        ("hour", 60 * 60),
        ("minute", 60),
    ):
        if seconds >= seconds_in_unit:
            units = seconds // seconds_in_unit
            seconds -= units * seconds_in_unit
            s = "" if units == 1 else "s"
            parts.append(f"{units} {unit}{s}")
    if seconds or not parts:
        s = "" if seconds == 1 else "s"
        parts.append(f"{seconds} second{s}")
    return ", ".join(parts)
