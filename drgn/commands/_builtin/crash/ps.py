# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Implements the crash "ps" command for drgn.

This command displays process status for selected, or all, processes
in the system.
"""

import argparse
from typing import Any, Iterable, Optional, Tuple

from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import escape_ascii_string, print_table
from drgn.helpers.linux.kthread import task_is_kthread
from drgn.helpers.linux.mm import get_task_rss_info, task_vsize, totalram_pages
from drgn.helpers.linux.pid import find_task, for_each_task, is_group_leader
from drgn.helpers.linux.sched import (
    task_cpu,
    task_since_last_arrival_ns,
    task_state_to_char,
)

ByteToKB = 1024


# Linux kernel commit 06eb61844d84("sched/debug: Add explicit
# TASK_IDLE printing") (in v4.14) introduced printing of TASKs in idle
# state and hence changed size of task_state_array. Further Linux kernel
# commit 8ef9925b02c2("sched/debug: Add explicit TASK_PARKED printing)
# (in v4.14) introduced printing of parked tasks and further changed
# the size of task_state_array. This change also changed values of
# some states.
# Since size of task_state_array and value of some task states changed
# in same (v4.14) kernel, we can also use length of task_state_array
# to distnguish between old and new values of task states, whose values
# changed.
# Lastly since newer kernels add new task states without changing the
# values of pre-existing task states, we can safely assume that the task
# state values given below are valid for newer kernels as well, even though
# the newer kernels may have added some task states of their own.


# The following task states have same values in
# all currently supported kernel versions.

_NSECS_TO_SECS = 1000000000


def get_task_arrival_time(task: Object) -> int:
    """
    Get a task's arrival time on cpu

    A task's arrival time is only updated when the task is put ON a cpu via
    context_switch.

    :param task: ``struct task_struct *``
    :returns: arrival time instance in ns granularity
    """

    arrival_time = task.sched_info.last_arrival.value_()
    return arrival_time


def format_nanosecond_duration(nanosecs: int) -> str:
    """
    :returns: conversion of nanoseconds to [dd hh:mm:ss.ms] format
    """
    secs = nanosecs / _NSECS_TO_SECS
    dd, rem = divmod(secs, 86400)
    hh, rem = divmod(rem, 3600)
    mm, secs = divmod(rem, 60)
    return "%02ld %02ld:%02ld:%06.3f" % (dd, hh, mm, secs)


def show_tasks_last_runtime(tasks: Iterable[Object]) -> None:
    """
    Display task information in their last arrival order.
    """
    tasks = list(tasks)
    tasks.sort(key=task_since_last_arrival_ns)
    for t in tasks:
        cpu = str(task_cpu(t))
        pid = str(t.pid.value_())
        state = task_state_to_char(t)
        command = escape_ascii_string(t.comm.string_())
        time_nanosec = task_since_last_arrival_ns(t)
        last_arrival = format_nanosecond_duration(time_nanosec)
        print(
            f'[{last_arrival}] [{state}]  PID: {pid:<8} TASK: {t.value_()}  CPU: {cpu:<2}  COMMAND: "{command}"'
        )


def show_tasks_last_runtime_timestamp(tasks: Iterable[Object]) -> None:
    """
    Display task information sorted by last_run/timestamp/last_arrival, showing the raw timestamp.
    """
    tasks = list(tasks)
    tasks.sort(key=get_task_arrival_time)
    for t in tasks:
        cpu = str(task_cpu(t))
        pid = str(t.pid.value_())
        state = task_state_to_char(t)
        command = escape_ascii_string(t.comm.string_())
        last_arrival = str(get_task_arrival_time(t))
        print(
            f'[{last_arrival}] [{state}]  PID: {pid:<8} TASK: {t.value_()}  CPU: {cpu:<2}  COMMAND: "{command}"'
        )


def show_taskinfo(prog: Program, tasks: Iterable[Object]) -> None:
    """
    Display task information.
    """
    rows = [["PID", "PPID", "CPU", "TASK", "ST", "%MEM", "VSZ", "RSS", "COMM"]]
    tasks = list(tasks)
    tasks.sort(key=lambda t: t.pid.value_())
    page_size = int(prog["PAGE_SIZE"])
    total_mem = int(totalram_pages(prog))
    for t in tasks:
        task_rss = get_task_rss_info(prog, t)
        rss_kb = task_rss.total * page_size // ByteToKB
        pct_mem: float = task_rss.total * 100 / total_mem
        rows.append(
            [
                str(t.pid.value_()),
                str(t.parent.pid.value_()),
                str(task_cpu(t)),
                hex(t.value_()),
                task_state_to_char(t),
                str("%.1f" % pct_mem),
                str(task_vsize(t) // ByteToKB),
                str(rss_kb),
                (
                    f"[{escape_ascii_string(t.comm.string_())}]"
                    if task_is_kthread(t)
                    else f"{escape_ascii_string(t.comm.string_())}"
                ),
            ]
        )
    print_table(rows)


def check_arg_type(arg: Optional[str]) -> Tuple[str, Any]:
    """
    Check the filter type of the argument
    """
    if arg is not None:
        try:
            return ("pid", int(arg, 10))
        except ValueError:
            pass
        try:
            return ("task", int(arg, 16))
        except ValueError:
            return ("comm", str(arg))
    else:
        return ("none", None)


@crash_command(
    description="process information",
    long_description="display process status information",
    arguments=(
        argument(
            "-u",
            dest="user",
            action="store_true",
            default=False,
            help="display only user threads information",
        ),
        argument(
            "-k",
            dest="kernel",
            action="store_true",
            default=False,
            help="display only kernel threads information",
        ),
        argument(
            "-G",
            dest="group_leader",
            action="store_true",
            default=False,
            help="display only the thread group leader in a thread group",
        ),
        argument(
            "-m",
            dest="last_run",
            action="store_true",
            default=False,
            help="show last run information",
        ),
        argument(
            "-l",
            dest="last_run_timestamp",
            action="store_true",
            default=False,
            help="show last run information (raw timestamp)",
        ),
        argument(
            "arg",
            nargs="?",
            type=check_arg_type,
            metavar="pid | task | command",
            help="pid is a process PID. task is hexadecimal task_struct pointer. command is a command name.",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ps(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        print(
            """
        from drgn.helpers.linux.pid import for_each_task
        from drgn.helpers.common.format import escape_ascii_string
        from drgn.helpers.linux.mm import task_vsize

        total_mem = int(totalram_pages(prog))
        page_size = prog["PAGE_SIZE"].value_()
        for task in for_each_task(prog):
            state = task_state_to_char(task)
            task_rss = get_task_rss_info(task)
            total_rss = task_rss.total
            pct_mem = total_rss * 100 / total_mem
            vmem = task_vsize(task)
            command = escape_ascii_string(task.comm.string_())
        """
        )
        return
    tasks = for_each_task(prog)
    if args.arg is not None:
        if args.arg[0] == "pid":
            task = find_task(prog, args.arg[1])
            tasks = iter([task]) if task is not None else iter([])
        elif args.arg[0] == "task":
            tasks = iter([Object(prog, "struct task_struct *", value=args.arg[1])])
        elif args.arg[0] == "comm":
            tasks = (
                t for t in tasks if escape_ascii_string(t.comm.string_()) == args.arg[1]
            )

    if args.user:
        tasks = filter(lambda t: not task_is_kthread(t), tasks)
    elif args.kernel:
        tasks = filter(task_is_kthread, tasks)
    if args.group_leader:
        tasks = filter(is_group_leader, tasks)
    if args.last_run:
        show_tasks_last_runtime(tasks)
    elif args.last_run_timestamp:
        show_tasks_last_runtime_timestamp(tasks)
    else:
        show_taskinfo(prog, tasks)
