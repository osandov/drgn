# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
CPU Masks
---------

The ``drgn.helpers.linux.cpumask`` module provides helpers for working with CPU
masks from :linux:`include/linux/cpumask.h`.
"""

from typing import Iterator

from drgn import Object, Program
from drgn.helpers.linux.bitops import for_each_set_bit

__all__ = (
    "cpumask_to_cpulist",
    "for_each_cpu",
    "for_each_online_cpu",
    "for_each_possible_cpu",
    "for_each_present_cpu",
)


def for_each_cpu(mask: Object) -> Iterator[int]:
    """
    Iterate over all of the CPUs in the given mask.

    :param mask: ``struct cpumask``
    """
    try:
        nr_cpu_ids = mask.prog_["nr_cpu_ids"].value_()
    except KeyError:
        nr_cpu_ids = 1
    return for_each_set_bit(mask.bits, nr_cpu_ids)


def _for_each_cpu_mask(prog: Program, name: str) -> Iterator[int]:
    try:
        mask = prog[name]
    except KeyError:
        # Before Linux kernel commit c4c54dd1caf1 ("kernel/cpu.c: change type
        # of cpu_possible_bits and friends") (in v4.5), the CPU masks are
        # struct cpumask *cpu_foo_mask instead of
        # struct cpumask __cpu_foo_mask.
        mask = prog[name[2:]][0]
    return for_each_cpu(mask)


def for_each_online_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all online CPUs."""
    return _for_each_cpu_mask(prog, "__cpu_online_mask")


def for_each_possible_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all possible CPUs."""
    return _for_each_cpu_mask(prog, "__cpu_possible_mask")


def for_each_present_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all present CPUs."""
    return _for_each_cpu_mask(prog, "__cpu_present_mask")


def cpumask_to_cpulist(mask: Object) -> str:
    """
    Return a CPU mask as a CPU list string.

    >>> cpumask_to_cpulist(mask)
    0-3,8-11

    :param mask: ``struct cpumask *``
    :return: String in the `CPU list format
        <https://man7.org/linux/man-pages/man7/cpuset.7.html#FORMATS>`_.
    """
    start = end = -2
    parts = []
    for cpu in for_each_cpu(mask):
        if cpu == end + 1:
            end = cpu
        else:
            if start >= 0:
                parts.append(str(start) if start == end else f"{start}-{end}")
            start = end = cpu
    if start >= 0:
        parts.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(parts)
