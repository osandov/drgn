# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
crash runq - Display the tasks on the run queues of each cpu.

Implements the crash "runq" command for drgn
"""

import argparse
from typing import Any, Set

from drgn import Object, Program, cast, container_of
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu


def has_member(obj: Object, name: str) -> bool:
    """
    Return true if a given object has a member with the given name.
    :param obj: Drgn object to check
    :param name: string member name to check
    :returns: whether the object has a member by that name
    """
    try:
        obj.member_(name)
        return True
    except LookupError:
        return False


def task_thread_info(task: Object) -> Object:
    """
    Return a task's ``thread_info``

    This is an equivalent to the kernel function / inline / macro
    ``task_thread_info()``, but it must cover a wide variety of versions and
    configurations.

    :param task: Object of type ``struct task_struct *``
    :returns: The ``struct thread_info *`` for this task
    """
    if has_member(task, "thread_info"):
        return task.thread_info.address_of_()
    return cast("struct thread_info *", task.stack)


def task_cpu(task: Object) -> int:
    """
    Return the CPU on which a task is running.

    This is an equivalent to the kernel function ``task_cpu()``, but it covers
    a wide variety of variations in kernel version and configuration. It would
    be a bit impractical to spell out all the variants, but essentially, if
    there's a "cpu" field in ``struct task_struct``, then we can just use that.
    Otherwise, we need to get it from the ``thread_info``.

    :param task: Object of type ``struct task_struct *``
    :retruns: The cpu as a Python int
    """
    if has_member(task, "cpu"):
        return task.cpu.value_()
    return task_thread_info(task).cpu.value_()


def runq_clock(prog: Program, cpu: int) -> int:
    """
    Get clock of cpu runqueue ``struct rq``

    :param prog: drgn program
    :param cpu: cpu index
    :returns: cpu runqueue clock in ns granularity
    """
    rq = per_cpu(prog["runqueues"], cpu)
    return rq.clock.value_()


def get_task_arrival_time(task: Object) -> int:
    """
    Get a task's arrival time on cpu

    A task's arrival time is only updated when the task is put ON a cpu via
    context_switch.

    :param task: ``struct task_struct *``
    :returns: arrival time instance in ns granularity
    """

    if has_member(task, "last_run"):
        arrival_time = task.last_run.value_()
    elif has_member(task, "timestamp"):
        arrival_time = task.timestamp.value_()
    else:
        arrival_time = task.sched_info.last_arrival.value_()

    return arrival_time


def task_lastrun2now(task: Object) -> int:
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


def _parse_cpus_arg(cpus_arg: str, max_cpu: int) -> Set[int]:
    """
    Parse argument to -c for cpu restriction (e.g. '1,3,5-8').

    :param cpus_arg: str
    :param  max_cpu: int
    :returns: a set of specified cpus
    """
    cpus = set()
    for part in cpus_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            for cpu in range(int(start), int(end) + 1):
                if 0 <= cpu < max_cpu:
                    cpus.add(cpu)
        elif part:
            cpu = int(part)
            if 0 <= cpu < max_cpu:
                cpus.add(cpu)
    return cpus


def _get_runqueue_timestamps(runqueue: Object) -> int:
    """
    Get runqueue clock timestamp.

    :param runque: Object
    :returns: rq timestamp
    """
    # Try common fields in order; not all will exist on all kernels
    rq_ts = 0
    for name in ("clock", "most_recent_timestamp", "timestamp_last_tick"):
        if has_member(runqueue, name):
            try:
                rq_ts = getattr(runqueue, name).value_()
                break
            except Exception:
                pass
    return rq_ts


def dump_rt_runq(runqueue: Object) -> None:
    """
    Dump runq in rt scheduler

    :param runque: Object
    """
    count = 0
    prio_array = (
        hex(runqueue.rt.active.address_ - 16) if runqueue.rt.active.address_ else 0
    )
    print("  RT PRIO_ARRAY:", prio_array)
    rt_prio_array = runqueue.rt.active.queue
    for que in rt_prio_array:
        for t in list_for_each_entry(
            "struct sched_rt_entity", que.address_of_(), "run_list"
        ):
            tsk = container_of(t, "struct task_struct", "rt")
            if tsk == runqueue.curr:
                continue
            count += 1
            print(
                " " * 4,
                '[{:3d}] PID: {:<6d} TASK: {} COMMAND: "{}"'.format(
                    tsk.prio.value_(),
                    tsk.pid.value_(),
                    hex(tsk),
                    escape_ascii_string(tsk.comm.string_()),
                ),
            )
    if count == 0:
        print("     [no tasks queued]")


def dump_cfs_runq(runqueue: Object, task_group: bool = False) -> None:
    """
    Dump runq in cfs scheduler

    :param runque: Object
    """
    cfs_root = hex(runqueue.cfs.tasks_timeline.address_of_().value_())
    if not task_group:
        print("  CFS RB_ROOT:", cfs_root)
    count = 0
    runq = runqueue.address_of_()
    for t in list_for_each_entry(
        "struct task_struct", runq.cfs_tasks.address_of_(), "se.group_node"
    ):
        if t == runqueue.curr:
            continue
        count += 1
        print(
            " " * 4,
            '[{:3d}] PID: {:<6d} TASK: {}  COMMAND: "{}"'.format(
                t.prio.value_(),
                t.pid.value_(),
                hex(t),
                escape_ascii_string(t.comm.string_()),
            ),
        )
    if count == 0:
        print("     [no tasks queued]")


def timestamp_str(ns: int) -> str:
    """Convert timestamp int to formatted str"""
    value = ns // 1000000
    ms = value % 1000
    value = value // 1000
    secs = value % 60
    value = value // 60
    mins = value % 60
    value = value // 60
    hours = value % 24
    days = value // 24
    return "%d %02d:%02d:%02d.%03d" % (days, hours, mins, secs, ms)


def run_queue(prog: Program, args: argparse.Namespace) -> None:
    """
    Print runqueue with detailed info.

    :param prog: drgn program
    :param args: argparse Namespace
    """
    online_cpus = list(for_each_online_cpu(prog))
    max_cpu = max(online_cpus) + 1 if online_cpus else 0

    if args.cpus:
        selected_cpus = _parse_cpus_arg(args.cpus, max_cpu)
        cpus = [cpu for cpu in online_cpus if cpu in selected_cpus]
    else:
        cpus = online_cpus
    table_format = False
    if args.show_timestamps or args.show_lag or args.pretty_runtime:
        table_format = True
    table = []
    runq_clocks = {}
    for cpu, i in enumerate(cpus):
        runqueue = per_cpu(prog["runqueues"], cpu)
        curr_task_addr = runqueue.curr.value_()
        curr_task = runqueue.curr[0]
        run_time = task_lastrun2now(curr_task)
        if args.show_lag:
            runq_clocks[cpu] = runq_clock(prog, cpu)
            if i == len(cpus) - 1:
                max_clock = max(runq_clocks.values())
                lags = {
                    cpu: max_clock - runq_clock
                    for cpu, runq_clock in runq_clocks.items()
                }
                sorted_lags = dict(sorted(lags.items(), key=lambda item: item[1]))
                [
                    print(f"CPU {cpu}: {lag/1e9:.2f} secs")
                    for cpu, lag in sorted_lags.items()
                ]
                return
            else:
                continue
        comm = escape_ascii_string(curr_task.comm.string_())
        pid = curr_task.pid.value_()
        prio = curr_task.prio.value_()

        if table_format:
            row = [
                CellFormat(cpu, ">"),
                CellFormat(pid, ">"),
                CellFormat(curr_task_addr, "x"),
                CellFormat(prio, ">"),
                CellFormat(comm, "<"),
            ]
            if args.pretty_runtime:
                row.append(CellFormat(timestamp_str(run_time), ">"))

            if args.show_timestamps:
                rq_ts = _get_runqueue_timestamps(runqueue)
                task_ts = get_task_arrival_time(curr_task)
                # newest_rq_ts = max(rq_timestamps.values()) if rq_timestamps and args.show_lag else None

                row += [
                    CellFormat(f"{rq_ts:013d}", ">"),
                    CellFormat(f"{task_ts:013d}", "<"),
                ]

            table.append(row)
        else:
            print(f"CPU {cpu} RUNQUEUE: {hex(runqueue.address_of_().value_())}")
            print(
                f"  CURRENT:   PID: {pid:<6d}  TASK: {hex(curr_task_addr)}  PRIO: {prio}"
                f'  COMMAND: "{comm}"'
                # f"  RUNTIME: {timestamp_str(run_time)}",
            )
            root_task_group_addr = prog["root_task_group"].address_of_().value_()
            if args.group:
                print(f"  ROOT_TASK_GROUP: {hex(root_task_group_addr)}")
                print(
                    " " * 4,
                    '[{:3d}] PID: {:<6d} TASK: {}  COMMAND: "{}" [CURRENT]'.format(
                        prio,
                        pid,
                        hex(curr_task_addr),
                        comm,
                    ),
                )

            else:
                # RT PRIO_ARRAY
                dump_rt_runq(runqueue)
            # CFS RB_ROOT
            dump_cfs_runq(runqueue, args.group)
            print()
            continue
        headers = [
            CellFormat("CPU", "<"),
            CellFormat("PID", "<"),
            CellFormat("TASK", "<"),
            CellFormat("PRIO", "<"),
            CellFormat("COMMAND", "<"),
        ]
        if args.show_timestamps:
            headers += [
                CellFormat("RQ_TIMESTAMP", "<"),
                CellFormat("TASK_TIMESTAMP", "<"),
            ]
        if args.pretty_runtime:
            headers.append(CellFormat("RUNTIME", "<"))
    if table_format:
        print_table([headers] + table)


@crash_command(
    description="Display the tasks on the run queues of each cpu.",
    arguments=(
        argument("-t", action="store_true", dest="show_timestamps"),
        argument("-T", action="store_true", dest="show_lag"),
        argument("-m", action="store_true", dest="pretty_runtime"),
        argument("-g", action="store_true", dest="group"),
        argument("-c", type=str, default="", dest="cpus"),
        drgn_argument,
    ),
)
def _crash_cmd_runq(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    run_queue(prog, args)
