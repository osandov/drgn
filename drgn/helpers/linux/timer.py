# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Timers
------

The ``drgn.helpers.linux.timer`` module provides helpers for kernel timers,
including the timer wheel and high-resolution timers ("hrtimers").
"""

from typing import Iterator, Sequence

from drgn import Object, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

__all__ = (
    "hrtimer_clock_base_for_each",
    "timer_base_for_each",
    "timer_base_names",
)


@takes_program_or_default
def timer_base_names(prog: Program) -> Sequence[str]:
    """
    Get the names of the timer wheel bases used on this kernel.

    This depends on the kernel version and configuration. For example:

    >>> timer_base_names()
    ('BASE_LOCAL', 'BASE_GLOBAL', 'BASE_DEF')

    means that each CPU has 3 timer bases: ``BASE_LOCAL`` (0), ``BASE_GLOBAL``
    (1), and ``BASE_DEF`` (2).
    """
    try:
        return prog.cache["timer_base_names"]
    except KeyError:
        pass
    nr_bases = len(prog["timer_bases"])
    if nr_bases == 3:
        # Since Linux kernel commit 83a665dc99a7 ("timers: Keep the pinned
        # timers separate from the others") (in v6.9) with
        # CONFIG_NO_HZ_COMMON=y.
        base_names: Sequence[str] = ("BASE_LOCAL", "BASE_GLOBAL", "BASE_DEF")
    elif nr_bases == 2:
        # Before that commit with CONFIG_NO_HZ_COMMON=y.
        base_names = ("BASE_STD", "BASE_DEF")
    elif nr_bases == 1:
        # CONFIG_NO_HZ_COMMON=n. We can't directly detect the above commit in
        # this case, so we have to differentiate based on the next commit,
        # 21927fc89e5f ("timers: Retrieve next expiry of pinned/non-pinned
        # timers separately"), which added the struct timer_events type.
        try:
            prog.type("struct timer_events")
            base_names = ("BASE_LOCAL",)
        except LookupError:
            base_names = ("BASE_STD",)
    else:
        raise NotImplementedError(f"unknown NR_BASES {nr_bases}")
    prog.cache["timer_base_names"] = base_names
    return base_names


def timer_base_for_each(base: Object) -> Iterator[Object]:
    """
    Iterate over every timer on a timer base.

    .. code-block:: python3

        for cpu in for_each_online_cpu():
            for base in per_cpu(prog["timer_bases"], cpu):
                for timer in timer_base_for_each(base.address_of_()):
                    ...

    :param base: ``struct timer_base *``
    :return: Iterator of ``struct timer_list *`` objects.
    """
    for head in base.vectors:
        yield from hlist_for_each_entry(
            "struct timer_list", head.address_of_(), "entry"
        )


def hrtimer_clock_base_for_each(clock_base: Object) -> Iterator[Object]:
    """
    Iterate over every high-resolution timer on an hrtimer clock base.

    .. code-block:: python3

        for cpu in for_each_online_cpu():
            for cpu_base in per_cpu(prog["hrtimer_bases"], cpu):
                for clock_base in cpu_base.clock_base:
                    for hrtimer in hrtimer_clock_base_for_each(clock_base.address_of_()):
                        ...

    :param clock_base: ``struct hrtimer_clock_base *``
    :return: Iterator of ``struct hrtimer *`` objects.
    """
    return rbtree_inorder_for_each_entry(
        "struct hrtimer", clock_base.active.rb_root.rb_root.address_of_(), "node.node"
    )
