# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any, List, Sequence

from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    crash_command,
    crash_get_context,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.mm import for_each_vma, task_rss, vma_name


# Generate DRGN code mode output
def _generate_drgn_code(prog: Program, args: argparse.Namespace) -> None:
    code = CrashDrgnCodeBuilder(prog)
    code.add_from_import("drgn", "Object")
    code.add_from_import(
        "drgn.helpers.linux.mm", "for_each_vma", "task_rss", "vma_name"
    )
    code.add_from_import("drgn.helpers.linux.sched", "task_cpu")
    code.add_from_import("drgn.helpers.linux.pid", "find_task")

    # Build task list
    code.append("tasks = []\n")
    # Handle the case where no arguments are provided
    if not args.pids_or_tasks:
        code.append_crash_context(None)
        code.append("tasks.append(task)\n")
    else:
        # Iterate over provided arguments and handle invalid inputs gracefully
        for pid_or_task in args.pids_or_tasks:
            code.append_crash_context(pid_or_task)
            code.append("tasks.append(task)\n")

    # Add processing logic
    code.append(
        """\
for task in tasks:
"""
    )
    code.append_task_header(indent="    ")
    code.append(
        """\
    mm = task.mm.read_()
    if mm:
        # Get memory statistics
        pgd = mm.pgd
        rss = task_rss(task).total
        total_vm = mm.total_vm * prog["PAGE_SIZE"]
        # Get VMA info
        for vma in for_each_vma(mm):
            vma_addr = vma
            vm_start = vma.vm_start
            vm_end = vma.vm_end
            vm_flags = vma.vm_flags

            # Get file path
            file_path = vma_name(vma)
"""
    )
    code.print()


# Print virtual memory info for a single task
def _print_task_vm_info(prog: Program, task: Object) -> None:
    print_task_header(task)

    mm = task.mm.read_()
    if not mm:
        kernel_stats_rows = [["MM", "PGD", "RSS", "TOTAL_VM"], ["0", "0", "0k", "0k"]]
        print_table(kernel_stats_rows)
        return

    # Show memory statistics
    rss_info = task_rss(task)
    total_vm_kb = mm.total_vm.value_() * prog["PAGE_SIZE"].value_() // 1024

    stats_rows: List[List[CellFormat]] = [
        [
            CellFormat("MM", "^"),
            CellFormat("PGD", "^"),
            CellFormat("RSS", "^"),
            CellFormat("TOTAL_VM", "^"),
        ],
        [
            CellFormat(mm.value_(), "^x"),
            CellFormat(mm.pgd.value_(), "^x"),
            CellFormat(f"{rss_info.total}k", "^"),
            CellFormat(f"{total_vm_kb}k", "^"),
        ],
    ]
    print_table(stats_rows)
    # Show detailed VMA info
    rows: List[Sequence[Any]] = [
        [
            CellFormat("VMA", "^"),
            CellFormat("START", "^"),
            CellFormat("END", "^"),
            CellFormat("FLAGS", "<"),
            CellFormat("FILE", "<"),
        ]
    ]
    for vma in for_each_vma(mm):
        file_path = vma_name(vma)
        rows.append(
            [
                CellFormat(vma.value_(), "^x"),
                CellFormat(vma.vm_start.value_(), "^x"),
                CellFormat(vma.vm_end.value_(), "^x"),
                CellFormat(vma.vm_flags.value_(), "<x"),
                file_path,
            ]
        )

    print_table(rows)


@crash_command(
    description="virtual memory",
    long_description="""This command displays basic virtual memory information of a context,
consisting of a pointer to its mm_struct and page directory, its RSS and
total virtual memory size; and a list of pointers to each vm_area_struct,
its starting and ending address, vm_flags value, and file pathname. If no
arguments are entered, the current context is used.
""",
    arguments=(
        argument(
            "pids_or_tasks",
            metavar="pid|task",
            nargs="*",
            type="pid_or_task",
            help="one or more process PIDs or hexadecimal task_struct pointers",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_vm(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:

    if args.drgn:
        _generate_drgn_code(prog, args)
        return

    if not args.pids_or_tasks:
        args.pids_or_tasks.append(None)

    for task_arg in args.pids_or_tasks:
        try:
            task = crash_get_context(prog, task_arg)
        except Exception as e:
            print("vm:", e)
        else:
            _print_task_vm_info(prog, task)
        print()
