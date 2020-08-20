# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Per-CPU
-------

The ``drgn.helpers.linux.percpu`` module provides helpers for working with
per-CPU allocations from :linux:`include/linux/percpu.h` and per-CPU counters
from :linux:`include/linux/percpu_counter.h`.
"""

from drgn import IntegerLike, Object
from drgn.helpers.linux.cpumask import for_each_online_cpu

__all__ = (
    "per_cpu_ptr",
    "percpu_counter_sum",
)


def per_cpu_ptr(ptr: Object, cpu: IntegerLike) -> Object:
    """
    Return the per-CPU pointer for a given CPU.

    :param ptr: ``type __percpu *``
    :param cpu: CPU number.
    :return: ``type *``
    """
    offset = ptr.prog_["__per_cpu_offset"][cpu].value_()
    return Object(ptr.prog_, ptr.type_, value=ptr.value_() + offset)


def percpu_counter_sum(fbc: Object) -> int:
    """
    Return the sum of a per-CPU counter.

    :param fbc: ``struct percpu_counter *``
    """
    ret = fbc.count.value_()
    ptr = fbc.counters
    for cpu in for_each_online_cpu(fbc.prog_):
        ret += per_cpu_ptr(ptr, cpu)[0].value_()
    return ret
