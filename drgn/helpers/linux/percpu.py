# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Per-CPU
-------

The ``drgn.helpers.linux.percpu`` module provides helpers for working with
per-CPU allocations from :linux:`include/linux/percpu.h` and per-CPU counters
from :linux:`include/linux/percpu_counter.h`.
"""

from _drgn import _linux_helper_per_cpu_ptr as per_cpu_ptr
from drgn import IntegerLike, Object
from drgn.helpers.linux.cpumask import for_each_online_cpu

__all__ = (
    "per_cpu",
    "per_cpu_ptr",
    "percpu_counter_sum",
)


def per_cpu(var: Object, cpu: IntegerLike) -> Object:
    """
    Return the per-CPU variable for a given CPU.

    >>> print(repr(prog["runqueues"]))
    Object(prog, 'struct rq', address=0x278c0)
    >>> per_cpu(prog["runqueues"], 6).curr.comm
    (char [16])"python3"

    :param var: Per-CPU variable, i.e., ``type __percpu`` (not a pointer; use
        :func:`per_cpu_ptr()` for that).
    :param cpu: CPU number.
    :return: ``type`` object.
    """
    return per_cpu_ptr(var.address_of_(), cpu)[0]


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
