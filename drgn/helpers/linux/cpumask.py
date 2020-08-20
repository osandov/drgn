# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

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


def for_each_possible_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all possible CPUs."""
    return for_each_cpu(prog["__cpu_possible_mask"])


def for_each_online_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all online CPUs."""
    return for_each_cpu(prog["__cpu_online_mask"])


def for_each_present_cpu(prog: Program) -> Iterator[int]:
    """Iterate over all present CPUs."""
    return for_each_cpu(prog["__cpu_present_mask"])
