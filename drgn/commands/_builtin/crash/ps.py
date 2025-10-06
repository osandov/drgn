# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Implements the crash "ps" command for drgn.

This command displays process status for selected, or all, processes
in the system.
"""

import argparse
from typing import Any, List, Optional, Sequence, Tuple

from drgn import Object, Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import (
    CellFormat,
    double_quote_ascii_string,
    escape_ascii_string,
    print_table,
)
from drgn.helpers.linux.kthread import task_is_kthread
from drgn.helpers.linux.mm import get_task_rss_info, task_vsize, totalram_pages
from drgn.helpers.linux.pid import find_task, for_each_task
from drgn.helpers.linux.sched import (
    task_cpu,
    task_since_last_arrival_ns,
    task_state_to_char,
    thread_group_leader,
)

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


def show_tasks_last_runtime(tasks: List[Object]) -> None:
    """
    Display task information in their last arrival order.
    """
    tasks.sort(key=task_since_last_arrival_ns)
    for t in tasks:
        cpu = task_cpu(t)
        pid = t.pid.value_()
        state = task_state_to_char(t)
        command = double_quote_ascii_string(t.comm.string_())
        time_nanosec = task_since_last_arrival_ns(t)
        last_arrival = format_nanosecond_duration(time_nanosec)
        print(
            f"[{last_arrival:>14}] [{state}]  PID: {pid:<8} TASK: {t.value_():x}   CPU: {cpu:<2}  COMMAND: {command}"
        )


def show_tasks_last_runtime_timestamp(tasks: List[Object]) -> None:
    """
    Display task information sorted by last_run/timestamp/last_arrival, showing the raw timestamp.
    """
    tasks.sort(key=get_task_arrival_time, reverse=True)
    for t in tasks:
        cpu = task_cpu(t)
        pid = t.pid.value_()
        state = task_state_to_char(t)
        command = double_quote_ascii_string(t.comm.string_())
        last_arrival = get_task_arrival_time(t)
        print(
            f"[{last_arrival:>14}] [{state}]  PID: {pid:<8} TASK: {t.value_():x}   CPU: {cpu:<2}  COMMAND: {command}"
        )


def show_taskinfo(prog: Program, tasks: List[Object]) -> None:
    """
    Display tasks informations.
    """
    rows: List[Sequence[Any]] = [
        (
            CellFormat("PID", ">"),
            CellFormat("PPID", ">"),
            CellFormat("CPU", "^"),
            CellFormat("TASK", "^"),
            CellFormat("ST", ">"),
            CellFormat("%MEM", ">"),
            CellFormat("%VSZ", ">"),
            CellFormat("RSS", ">"),
            CellFormat("COMM", "<"),
        )
    ]
    tasks.sort(key=lambda t: t.pid.value_())
    page_size = int(prog["PAGE_SIZE"])
    total_mem = totalram_pages(prog)
    for t in tasks:
        task_rss = get_task_rss_info(prog, t)
        rss_kb = task_rss.total * page_size // 1024
        pct_mem: float = task_rss.total / total_mem
        rows.append(
            [
                t.pid.value_(),
                t.parent.pid.value_(),
                CellFormat(task_cpu(t), "^"),
                CellFormat(t.value_(), "^x"),
                task_state_to_char(t),
                CellFormat(pct_mem, ".1%"),
                task_vsize(t) // 1024,
                rss_kb,
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
            return ("comm", arg)
    else:
        return ("none", None)


@crash_command(
    description="process information",
    long_description="display process status information",
    arguments=(
        mutually_exclusive_group(
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
        ),
        mutually_exclusive_group(
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
        ),
        argument(
            "-G",
            dest="group_leader",
            action="store_true",
            default=False,
            help="display only the thread group leader in a thread group",
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
        builder = CrashDrgnCodeBuilder(prog)
        builder.add_from_import("drgn.helpers.linux.pid", "for_each_task")
        builder.add_from_import("drgn.helpers.common.format", "escape_ascii_string")
        builder.add_from_import(
            "drgn.helpers.linux.mm",
            "task_vsize",
            "get_task_rss_info",
            "totalram_pages",
        )
        builder.add_from_import(
            "drgn.helpers.linux.sched", "task_state_to_char", "task_cpu"
        )
        if args.last_run or args.last_run_timestamp:
            builder.add_from_import(
                "drgn.helpers.linux.sched", "task_since_last_arrival_ns"
            )
            builder.add_import("datetime")

        builder.append("total_mem = int(totalram_pages(prog))\n")
        builder.append("page_size = prog['PAGE_SIZE'].value_()\n")

        if args.user or args.kernel:
            builder.add_from_import("drgn.helpers.linux.kthread", "is_kthread")
            if args.user:
                builder.append(
                    "tasks = filter(lambda t: not task_is_kthread(t), for_each_task(prog))\n"
                )
            elif args.kernel:
                builder.append("tasks = filter(task_is_kthread, for_each_task(prog))\n")
        else:
            builder.append("tasks = for_each_task(prog)\n")

        if args.group_leader:
            builder.add_from_import(
                "drgn.helpers.linux.sched",
                "thread_group_leader",
            )
            builder.append("tasks = filter(thread_group_leader, tasks)\n")

        builder.append("for task in tasks:\n")
        builder.append("    cpu = task_cpu(task)\n")
        builder.append("    state = task_state_to_char(task)\n")
        builder.append("    task_rss = get_task_rss_info(task)\n")
        builder.append("    total_rss = task_rss.total\n")
        builder.append("    pct_mem = total_rss * 100 / total_mem\n")
        builder.append("    vmem = task_vsize(task)\n")
        builder.append("    command = escape_ascii_string(task.comm.string_())\n")

        if args.last_run:
            builder.append("    time_nanosec = task_since_last_arrival_ns(task)\n")
            builder.append(
                "    last_arrival = format_nanosecond_duration(time_nanosec)\n"
            )
        elif args.last_run_timestamp:
            builder.append("    last_arrival = task_since_last_arrival_ns(task)\n")

        builder.print()
        return
    tasks = list(for_each_task(prog))
    if args.arg is not None:
        if args.arg[0] == "pid":
            task = find_task(prog, args.arg[1])
            tasks = [task] if task is not None else []
        elif args.arg[0] == "task":
            tasks = [Object(prog, "struct task_struct *", value=args.arg[1])]
        elif args.arg[0] == "comm":
            tasks = [
                t for t in tasks if escape_ascii_string(t.comm.string_()) == args.arg[1]
            ]
    if args.user:
        tasks = sorted(filter(lambda t: not task_is_kthread(t), tasks))
    elif args.kernel:
        tasks = sorted(filter(task_is_kthread, tasks))
    if args.group_leader:
        tasks = list(filter(thread_group_leader, tasks))
    if args.last_run:
        show_tasks_last_runtime(tasks)
    elif args.last_run_timestamp:
        show_tasks_last_runtime_timestamp(tasks)
    else:
        show_taskinfo(prog, tasks)
