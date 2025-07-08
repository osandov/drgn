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
    are provided. These functions can also race with timekeeping updates and
    return a value with an error of up to 1 second.
"""

import functools
import logging
import re
from typing import Optional

from drgn import Object, Program, ProgramFlags, cast, sizeof
from drgn.helpers.common.prog import takes_program_or_default

logger = logging.getLogger("drgn")

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


def _ktime_get_coarse_ns(prog: Program, offs_name: Optional[str]) -> Object:
    # The timekeeper is updated every tick, so we're very likely to catch it in
    # the middle of an update. To make that less likely, we take a "snapshot"
    # of the relevant timekeeper memory, check whether the seqcount was
    # write-locked during our snapshot, and retry (if live) or warn if so. The
    # snapshot isn't atomic, so it's still possible to race, but the window is
    # narrow.
    #
    # An alternative that fully avoids the race would be simulating a
    # read_seqlock operation, but that requires multiple reads and would likely
    # never succeed on, for example, slow remote connections.
    #
    # We cache the address and size to read and functions for extracting
    # members.
    try:
        address, size, from_snapshot = prog.cache["timekeeper_snapshot"]
    except KeyError:
        tk_core = prog["tk_core"]
        tk = tk_core.timekeeper
        members = {
            "base": tk.tkr_mono.base,
            "offs_real": tk.offs_real,
            "offs_boot": tk.offs_boot,
            "offs_tai": tk.offs_tai,
        }

        # Since Linux kernel commit 025e82bcbc34 ("timekeeping: Use sequence
        # counter with associated raw spinlock") (in v5.9), struct tk_data::seq
        # is a seqcount_raw_spinlock_t. Before that, it is a seqcount_t.
        try:
            members["seq"] = tk_core.seq.seqcount.sequence
        except AttributeError:
            members["seq"] = tk_core.seq.sequence

        # Since Linux kernel commit b71f9804f66c ("timekeeping: Prevent coarse
        # clocks going backwards") (in v6.15), the nanoseconds part is directly
        # in struct timekeeper::coarse_nsec. Before that, it is computed from
        # struct timekeeper::tkr_mono.
        try:
            members["coarse_nsec"] = tk.coarse_nsec
        except AttributeError:
            members["xtime_nsec"] = tk.tkr_mono.xtime_nsec
            members["shift"] = tk.tkr_mono.shift

        address = min(  # type: ignore[type-var]  # member.address_ can't be None
            member.address_ for member in members.values()
        )
        size = (
            max(
                member.address_ + sizeof(member)  # type: ignore[operator]  # member.address_ can't be None.
                for member in members.values()
            )
            - address
        )
        assert size <= 1024

        from_snapshot = {}
        for name, member in members.items():
            member_type = member.type_
            # Since Linux kernel commit 2456e8553544 ("ktime: Get rid of the
            # union") (in v4.10), ktime_t is a typedef of s64. Before that, it
            # was a dummy union wrapping an s64. In both cases, we actually
            # want a u64.
            if member_type.type_name() == "ktime_t":
                member_type = prog.type("u64")
            from_snapshot[name] = functools.partial(
                Object.from_bytes_,
                prog,
                member_type,
                bit_offset=(member.address_ - address) * 8,
            )

        prog.cache["timekeeper_snapshot"] = address, size, from_snapshot

    # On live kernels, we retry a limited number of times, then warn and move
    # on.
    for _ in range(1000):
        snapshot = prog.read(address, size)
        seq = from_snapshot["seq"](snapshot)
        if seq & 1:
            if prog.flags & ProgramFlags.IS_LIVE:
                continue
            else:
                # For core dumps, the best we can do is warn.
                logger.warning("timekeeper was write-locked; ktime may be inconsistent")
                break
        break
    else:
        logger.warning(
            "couldn't get unlocked snapshot of timekeeper; ktime may be inconsistent"
        )

    ns = from_snapshot["base"](snapshot)
    try:
        ns += from_snapshot["coarse_nsec"](snapshot)
    except KeyError:
        ns += from_snapshot["xtime_nsec"](snapshot) >> from_snapshot["shift"](snapshot)
    if offs_name is not None:
        ns += from_snapshot[offs_name](snapshot)
    return ns


@takes_program_or_default
def ktime_get_coarse_ns(prog: Program) -> Object:
    """
    Get the coarse monotonic time in nanoseconds (``CLOCK_MONOTONIC_COARSE``).

    :return: ``u64``
    """
    return _ktime_get_coarse_ns(prog, None)


@takes_program_or_default
def ktime_get_real_seconds(prog: Program) -> Object:
    """
    Get the seconds component of the real (wall) time
    (``CLOCK_REALTIME_COARSE``).

    :return: ``time64_t``
    """
    match = re.search(
        b"^CRASHTIME=([0-9]+)$", prog["VMCOREINFO"].string_(), flags=re.MULTILINE
    )
    if match:
        try:
            time_type = prog.type("time64_t")
        except LookupError:
            # We want this to work even without any debugging information, so
            # fall back to long long.
            time_type = prog.type("long long")
        return Object(prog, time_type, int(match.group(1)))
    return cast("time64_t", prog["tk_core"].timekeeper.xtime_sec)


@takes_program_or_default
def ktime_get_coarse_real_ns(prog: Program) -> Object:
    """
    Get the coarse real (wall) time in nanoseconds (``CLOCK_REALTIME_COARSE``).

    :return: ``u64``
    """
    return _ktime_get_coarse_ns(prog, "offs_real")


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
    return _ktime_get_coarse_ns(prog, "offs_boot")


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
    return _ktime_get_coarse_ns(prog, "offs_tai")


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
