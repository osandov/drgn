# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""An implementation of ps(crash command) using drgn"""

import argparse
from typing import Any, Iterable, Optional, Tuple

import drgn
from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import print_table
from drgn.helpers.linux.mm import get_task_rss_info, get_task_vmem, totalram_pages
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import (
    find_task,
    for_each_task,
    get_command,
    is_group_leader,
    is_kthread,
    is_user,
)
from drgn.helpers.linux.sched import cpu_curr, task_cpu, task_state_to_char

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


def nanosecs_to_secs(nanosecs: int) -> float:
    """
    Convert from nanosecs to secs

    :param nanosecs: time duration in nano secs
    :returns: time duration in secs
    """
    val = nanosecs // 1000000
    return val / 1000


def get_task_arrival_time(task: Object) -> int:
    """
    Get a task's arrival time on cpu

    A task's arrival time is only updated when the task is put ON a cpu via
    context_switch.

    :param task: ``struct task_struct *``
    :returns: arrival time instance in ns granularity
    """

    try:
        arrival_time = task.last_run.value_()
    except AttributeError:
        try:
            arrival_time = task.timestamp.value_()
        except AttributeError:
            arrival_time = task.sched_info.last_arrival.value_()
    return arrival_time


def get_current_run_time(prog: drgn.Program, cpu: int) -> int:
    """
    Get running duration of the current task on some cpu

    :param prog: drgn program
    :param cpu: cpu index
    :returns: duration in ns granularity
    """
    return task_lastrun2now(cpu_curr(prog, cpu))


def runq_clock(prog: drgn.Program, cpu: int) -> int:
    """
    Get clock of cpu runqueue ``struct rq``

    :param prog: drgn program
    :param cpu: cpu index
    :returns: cpu runqueue clock in ns granularity
    """
    rq = per_cpu(prog["runqueues"], cpu)
    return rq.clock.value_()


def task_lastrun2now(task: drgn.Object) -> int:
    """
    Get the duration from task last run timestamp to now

    The return duration will cover task's last run time on cpu and also
    the time staying in current status, usually the time slice for task
    on cpu will be short, so this can roughly tell how long this task
    has been staying in current status.
    For task status in "RU" status, if it's still on cpu, then this return
    the duration time this task has been running, otherwise it roughly tell
    how long this task has been staying in runqueue.

    :param prog: drgn program
    :param task: ``struct task_struct *``
    :returns: duration in ns granularity
    """
    prog = task.prog_
    arrival_time = get_task_arrival_time(task)
    rq_clock = runq_clock(prog, task_cpu(task))

    return rq_clock - arrival_time


def format_nanosecond_duration(nanosecs: int) -> str:
    """
    :returns: conversion of nanoseconds to [dd hh:mm:ss.ms] format
    """
    secs = nanosecs_to_secs(nanosecs)
    dd, rem = divmod(secs, 86400)
    hh, rem = divmod(rem, 3600)
    mm, secs = divmod(rem, 60)
    return "%02ld %02ld:%02ld:%06.3f" % (dd, hh, mm, secs)


def show_tasks_last_runtime(tasks: Iterable[Object]) -> None:
    """
    Display task information in their last arrival order.
    """
    tasks = list(tasks)
    tasks.sort(key=task_lastrun2now)
    for t in tasks:
        cpu = str(task_cpu(t))
        pid = str(t.pid.value_())
        state = task_state_to_char(t)
        command = get_command(t)
        time_nanosec = task_lastrun2now(t)
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
        command = get_command(t)
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
                str(get_task_vmem(t)),
                str(rss_kb),
                f"[{get_command(t)}]",
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
        from drgn.helpers.linux.pid import for_each_task, get_command
        from drgn.helpers.linux.percpu import percpu_counter_sum
        from drgn.helpers.common.format import escape_ascii_string
        from drgn.helpers.mm import get_task_vmem

        for task in for_each_task(prog):
            total_mem = int(totalram_pages(prog))
            page_size = prog["PAGE_SIZE"].value_()
            pid = task.pid.value_()
            ppid = task.parent.pid.value_()
            cpu = task.cpu.value_()
            task = hex(task.value_())
            state = task_state_to_char(task)
            task_rss = get_task_rss_info(t)
            total_rss = task_rss.total
            pct_mem = total_rss * 100 / total_mem
            vmem = get_task_vmem(task)
            command = get_command(task)
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
            tasks = (t for t in tasks if get_command(t) == args.arg[1])

    if args.user:
        tasks = filter(is_user, tasks)
    elif args.kernel:
        tasks = filter(is_kthread, tasks)
    if args.group_leader:
        tasks = filter(is_group_leader, tasks)
    if args.last_run:
        show_tasks_last_runtime(tasks)
    elif args.last_run_timestamp:
        show_tasks_last_runtime_timestamp(tasks)
    else:
        show_taskinfo(prog, tasks)
