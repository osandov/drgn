# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel per-CPU helpers

This module provides helpers for working with per-CPU allocations from
"linux/percpu.h" and per-CPU counters from "linux/percpu_counter.h".
"""

from drgn.helpers.kernel.cpumask import for_each_online_cpu


__all__ = [
    'per_cpu_ptr',
    'percpu_counter_sum',
]


def per_cpu_ptr(ptr, cpu):
    """
    type *per_cpu_ptr(type __percpu *ptr, int cpu)

    Return the per-CPU pointer for a given CPU.
    """
    offset = ptr.prog_['__per_cpu_offset'][cpu].value_()
    return ptr.prog_.object(ptr.type_, value=ptr.value_() + offset)


def percpu_counter_sum(fbc):
    """
    s64 percpu_counter_sum(struct percpu_counter *fbc)

    Return the sum of a per-CPU counter.
    """
    ret = fbc.count.value_()
    ptr = fbc.counters
    for cpu in for_each_online_cpu(fbc.prog_):
        ret += per_cpu_ptr(ptr, cpu)[0].value_()
    return ret
