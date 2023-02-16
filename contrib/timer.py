#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List system timers   """

from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.kconfig import get_kconfig
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

hrtimer_base = prog["hrtimer_bases"]
jiffies = int(prog["jiffies"])
hz = int(get_kconfig(prog)['CONFIG_HZ'])
adjusted_jiffies = jiffies - (0x100000000 - 300 * hz)


def get_fname(function):
    try:
        return "<" + prog.symbol(function).name + ">"
    except LookupError:
        return ""


print("=== timers ===")
print(f"Jiffies: {int(jiffies)}\n")

for cpu in for_each_online_cpu(prog):
    print(f"CPU {cpu}")
    timer_bases = per_cpu(prog["timer_bases"], cpu)

    for i in range(timer_bases.type_.length):
        print(f"TIMER_BASES[{i}]")
        print(f"  {'Expires':>16} {'TTE':>16} Function")
        for j in range(timer_bases[i].vectors.type_.length):
            timers = list(hlist_for_each_entry("struct timer_list", timer_bases[i].vectors[j], "entry"))
            for item in timers:
                expires = int(item.expires)
                print(f"  {expires:>16} {expires - jiffies:>16} {get_fname(item.function)}")
    print()

print("=== hrtimers ===")

for cpu in for_each_online_cpu(prog):
    print(f"CPU {cpu}")

    clock_base = per_cpu(hrtimer_base, cpu).clock_base
    for clockid in range(clock_base.type_.length):
        clock = clock_base[clockid]
        now = adjusted_jiffies * 1000000000 // hz + int(clock.offset)
        print(f"  Clock: {clockid} (current: {now:>22}) {hex(clock.get_time)} "
              f"{get_fname(clock.get_time)}")
        timer_tree = clock.active.rb_root.rb_root
        try:
            # Use list(...) instead of the lazy iteration as the data structure is very volatile
            # and changing quite ofter.
            timers = list(rbtree_inorder_for_each_entry("struct hrtimer", timer_tree, "node"))
            if timers:
                print(f"    {'Softexpires':>22} {'Expires':>22} {'TTE':>22}  Function")
                for timer in timers:
                    fname = get_fname(timer.function)
                    tte = int(timer.node.expires) - now
                    print(f"    {int(timer._softexpires):>22} {int(timer.node.expires):>22} "
                          f"{tte:>22}  {hex(timer.function)} {fname}")
                print()
        except Exception as e:
            print(f"    [skipped: {e}]")
    print()
