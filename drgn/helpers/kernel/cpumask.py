# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel CPU mask helpers

This module provides helpers for working with CPU masks from "linux/cpumask.h".
"""

__all__ = [
    'for_each_cpu',
    'for_each_possible_cpu',
    'for_each_online_cpu',
    'for_each_present_cpu',
]


def for_each_cpu(mask):
    """
    for_each_cpu(struct cpumask)

    Return an iterator over all of the CPUs in the given mask, as ints.
    """
    bits = mask.bits
    word_bits = 8 * bits.type_.type.sizeof()
    for i in range(bits.type_.size):
        word = bits[i].value_()
        for j in range(word_bits):
            if word & (1 << j):
                yield (word_bits * i) + j


def for_each_possible_cpu(prog):
    """
    for_each_possible_cpu()

    Return an iterator over all possible CPUs, as ints.
    """
    return for_each_cpu(prog['__cpu_possible_mask'])


def for_each_online_cpu(prog):
    """
    for_each_online_cpu()

    Return an iterator over all online CPUs, as ints.
    """
    return for_each_cpu(prog['__cpu_online_mask'])


def for_each_present_cpu(prog):
    """
    for_each_present_cpu()

    Return an iterator over all present CPUs, as ints.
    """
    return for_each_cpu(prog['__cpu_present_mask'])
