#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""A simplified implementation of ps(1) using drgn"""

from drgn.helpers.common.format import number_in_binary_units
from drgn.helpers.linux.mm import totalram_pages
from drgn.helpers.linux.percpu import percpu_counter_sum
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import task_cpu, task_state_to_char


PAGE_SIZE = prog["PAGE_SIZE"].value_()


def get_task_memory_info(task):
    """
    Return RSS (Resident Set Size) memory and VMS (Virtual Memory Size)
    for a given task. Return None if the task is a kernel thread.
    """
    if not task.mm:
        return None

    vms = PAGE_SIZE * task.mm.total_vm.value_()

    # Since Linux kernel commit f1a7941243c102a44e ("mm: convert mm's rss
    # stats into percpu_counter") (in v6.2), rss_stat is percpu counter.
    try:
        rss = PAGE_SIZE * sum([percpu_counter_sum(x) for x in task.mm.rss_stat])
    except (AttributeError, TypeError):
        rss = PAGE_SIZE * sum([x.counter for x in task.mm.rss_stat.count]).value_()

    return (vms, rss)


totalram = PAGE_SIZE * totalram_pages(prog)

print("PID     PPID    CPU  ST    VMS     RSS  MEM%  COMM")
for task in sorted(for_each_task(prog), key=lambda t: t.pid):
    pid = task.pid.value_()
    ppid = task.parent.pid.value_() if task.parent else 0

    comm = task.comm.string_().decode()
    # Distinguish kernel and user-space threads
    memory_info = get_task_memory_info(task)
    if memory_info:
        vms, rss = memory_info
        memp = 100 * rss / totalram
    else:
        vms, rss, memp = 0, 0, 0
        comm = f"[{comm}]"

    cpu = task_cpu(task)
    state = task_state_to_char(task)

    print(f"{pid:<7} {ppid:<7} {cpu:<4} {state} {number_in_binary_units(vms):>7} "
          f"{number_in_binary_units(rss):>7} {memp:5.1f} {comm}")
