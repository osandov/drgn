# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
crash runq - Display the tasks on the run queues of each cpu.

Implements the crash "runq" command for drgn
"""
import argparse
from typing import Any, Dict, List

from drgn import Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands.crash import crash_command, parse_cpuspec
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.runqueue import (
    get_cfs_runq_tasks,
    get_rq_per_cpu,
    get_rt_runq_tasks,
)
from drgn.helpers.linux.sched import task_rq, task_since_last_arrival_ns


def timestamp_str(ns: int) -> str:
    """Convert nanoseconds to 'days HH:MM:SS.mmm' string."""
    ms_total = ns // 1000000
    secs_total, ms = divmod(ms_total, 1000)
    mins_total, secs = divmod(secs_total, 60)
    hours_total, mins = divmod(mins_total, 60)
    days, hours = divmod(hours_total, 24)

    return f"{days} {hours:02}:{mins:02}:{secs:02}.{ms:03}"


def dump_run_queue(prog: Program, args: argparse.Namespace) -> None:
    """
    Print runqueue with detailed info.
    """
    table_format = args.show_timestamps or args.show_lag or args.pretty_runtime
    table: List[List[Any]] = []
    headers: List[Any] = []

    runq_clocks: Dict[int, int] = {}
    cpus = parse_cpuspec(args.cpus).cpus(prog)
    for i, (cpu, runqueue) in enumerate(get_rq_per_cpu(prog, cpus)):
        curr_task = runqueue.curr[0]
        curr_task_addr = runqueue.curr.value_()
        comm = escape_ascii_string(curr_task.comm.string_())
        pid = curr_task.pid.value_()
        prio = curr_task.prio.value_()
        run_time = task_since_last_arrival_ns(curr_task)

        # Show lag (skip formatting if not last CPU)
        if args.show_lag:
            runq_clocks[cpu] = task_rq(curr_task).clock.value_()
            if i == len(cpus) - 1:
                max_clock = max(runq_clocks.values())
                lags = {
                    c: max_clock - runq_clock for c, runq_clock in runq_clocks.items()
                }
                sorted_lags = sorted(lags.items(), key=lambda item: item[1])
                for c, lag in sorted_lags:
                    print(f"CPU {c}: {lag / 1e9:.2f} secs")
                return
            else:
                continue

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
                rq_ts = runqueue.clock.value_()
                task_ts = curr_task.sched_info.last_arrival.value_()
                row += [
                    CellFormat(f"{rq_ts:013d}", ">"),
                    CellFormat(f"{task_ts:013d}", "<"),
                ]
            table.append(row)
        else:
            print(f"CPU {cpu} RUNQUEUE: {hex(runqueue.address_of_().value_())}")
            print(
                f'  CURRENT:   PID: {pid:<6d}  TASK: {hex(curr_task_addr)}  PRIO: {prio}  COMMAND: "{comm}"'
            )

            if args.group:
                root_task_group_addr = prog["root_task_group"].address_of_().value_()
                print(f"  ROOT_TASK_GROUP: {hex(root_task_group_addr)}")
                print(
                    " " * 4,
                    f'[{prio:3d}] PID: {pid:<6d} TASK: {hex(curr_task_addr)}  COMMAND: "{comm}" [CURRENT]',
                )
            else:
                # RT runqueue
                prio_array = runqueue.rt.active.address_
                print(f"  RT PRIO_ARRAY: {hex(prio_array - 16) if prio_array else 0}")
                rt_tasks = list(get_rt_runq_tasks(runqueue))
                if rt_tasks:
                    for task in rt_tasks:
                        if task == runqueue.curr:
                            continue
                        print(
                            " " * 4,
                            f"[{task.prio.value_():3d}] PID: {task.pid.value_():<6d} TASK: {hex(int(task))}  "
                            f'COMMAND: "{escape_ascii_string(task.comm.string_())}"',
                        )
                else:
                    print("     [no tasks queued]")

                # CFS runqueue
                cfs_root = runqueue.cfs.tasks_timeline.address_of_().value_()
                print(f"  CFS RB_ROOT: {hex(cfs_root)}")
                cfs_tasks = list(get_cfs_runq_tasks(runqueue))
                if cfs_tasks:
                    for task in cfs_tasks:
                        print(
                            " " * 4,
                            f"[{task.prio.value_():3d}] PID: {task.pid.value_():<6d} TASK: {hex(int(task))}  "
                            f'COMMAND: "{escape_ascii_string(task.comm.string_())}"',
                        )
                else:
                    print("     [no tasks queued]")
            print()

    if table_format:
        headers = [
            CellFormat("CPU", "<"),
            CellFormat("PID", "<"),
            CellFormat("TASK", "<"),
            CellFormat("PRIO", "<"),
            CellFormat("COMMAND", "<"),
        ]
        if args.pretty_runtime:
            headers.append(CellFormat("RUNTIME", "<"))
        if args.show_timestamps:
            headers += [
                CellFormat("RQ_TIMESTAMP", "<"),
                CellFormat("TASK_TIMESTAMP", "<"),
            ]
        print_table([headers] + table)


@crash_command(
    description="Display the tasks on the run queues of each cpu.",
    arguments=(
        mutually_exclusive_group(
            argument("-t", action="store_true", dest="show_timestamps"),
            argument("-T", action="store_true", dest="show_lag"),
            argument("-m", action="store_true", dest="pretty_runtime"),
            argument("-g", action="store_true", dest="group"),
        ),
        argument("-c", type=str, default="", dest="cpus"),
        drgn_argument,
    ),
)
def _crash_cmd_runq(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    dump_run_queue(prog, args)
