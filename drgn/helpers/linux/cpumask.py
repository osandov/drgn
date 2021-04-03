# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CPU Masks
---------

The ``drgn.helpers.linux.cpumask`` module provides helpers for working with CPU
masks from :linux:`include/linux/cpumask.h`.
"""

from typing import Iterator

from drgn import Object, Program, sizeof

__all__ = (
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
    bits = mask.bits
    word_bits = 8 * sizeof(bits.type_.type)
    for i in range(bits.type_.length):  # type: ignore
        word = bits[i].value_()
        for j in range(word_bits):
            if word & (1 << j):
                yield (word_bits * i) + j


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
