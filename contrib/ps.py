#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""A simplified implementation of ps(1) using drgn"""

from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import task_cpu, task_state_to_char


def is_kthread(task):
    """
    Make a guess if task_struct is a kernel thread.
    """

    return not task.mm


print("PID     PPID    CPU  ST COMM")
for task in for_each_task(prog):
    pid = task.pid.value_()
    ppid = task.parent.pid.value_() if task.parent else 0

    comm = task.comm.string_().decode()
    # Distinguish kernel and user-space threads
    if is_kthread(task):
        comm = f"[{comm}]"

    cpu = task_cpu(task)
    state = task_state_to_char(task)

    print(f"{pid:<7} {ppid:<7} {cpu:<4} {state}  {comm}")
