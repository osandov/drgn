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
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.bitops import for_each_set_bit

__all__ = (
    "cpu_online_mask",
    "cpu_possible_mask",
    "cpu_present_mask",
    "cpumask_to_cpulist",
    "for_each_cpu",
    "for_each_online_cpu",
    "for_each_possible_cpu",
    "for_each_present_cpu",
)


# Before Linux kernel commit c4c54dd1caf1 ("kernel/cpu.c: change type of
# cpu_possible_bits and friends") (in v4.5), the CPU masks are struct cpumask
# *cpu_foo_mask instead of struct cpumask __cpu_foo_mask.
@takes_program_or_default
def cpu_online_mask(prog: Program) -> Object:
    """
    Return the mask of online CPUs.

    :return: ``struct cpumask *``
    """
    try:
        return prog["__cpu_online_mask"].address_of_()
    except KeyError:
        return prog["cpu_online_mask"]


@takes_program_or_default
def cpu_possible_mask(prog: Program) -> Object:
    """
    Return the mask of possible CPUs.

    :return: ``struct cpumask *``
    """
    try:
        return prog["__cpu_possible_mask"].address_of_()
    except KeyError:
        return prog["cpu_possible_mask"]


@takes_program_or_default
def cpu_present_mask(prog: Program) -> Object:
    """
    Return the mask of present CPUs.

    :return: ``struct cpumask *``
    """
    try:
        return prog["__cpu_present_mask"].address_of_()
    except KeyError:
        return prog["cpu_present_mask"]


def for_each_cpu(mask: Object) -> Iterator[int]:
    """
    Iterate over all of the CPUs in the given mask.

    :param mask: ``struct cpumask *``
    """
    try:
        nr_cpu_ids = mask.prog_["nr_cpu_ids"].value_()
    except KeyError:
        nr_cpu_ids = 1
    return for_each_set_bit(mask.bits, nr_cpu_ids)


@takes_program_or_default
def for_each_online_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all online CPUs."""
    return for_each_cpu(cpu_online_mask(prog))


@takes_program_or_default
def for_each_possible_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all possible CPUs."""
    return for_each_cpu(cpu_possible_mask(prog))


@takes_program_or_default
def for_each_present_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all present CPUs."""
    return for_each_cpu(cpu_present_mask(prog))


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
