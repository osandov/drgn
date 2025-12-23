# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _TaskSelector,
    crash_command,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.mm import for_each_vma, task_rss, vma_name


@_crash_foreach_subcommand(
    arguments=(drgn_argument,),
)
def _crash_foreach_vm(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import(
                "drgn.helpers.linux.mm", "for_each_vma", "task_rss", "vma_name"
            )
            code.append(
                """\

mm = task.mm.read_()
if mm:
    pgd = mm.pgd
    rss = task_rss(task)
    total_vm = mm.total_vm

    for vma in for_each_vma(mm):
        start = vma.vm_start
        end = vma.vm_end
        flags = vma.vm_flags
        file = vma_name(vma)
"""
            )
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()
        print_task_header(task)

        mm = task.mm.read_()
        if mm:
            pgd_value = mm.pgd.value_()
            rss_total = task_rss(task).total
            total_vm = mm.total_vm.value_()
        else:
            pgd_value = rss_total = total_vm = 0
        page_size = prog["PAGE_SIZE"].value_()
        print_table(
            (
                (
                    CellFormat("MM", "^"),
                    CellFormat("PGD", "^"),
                    CellFormat("RSS", "^"),
                    CellFormat("TOTAL_VM", "^"),
                ),
                (
                    CellFormat(mm.value_(), "^x"),
                    CellFormat(pgd_value, "^x"),
                    CellFormat(f"{rss_total * page_size // 1024}k", "^"),
                    CellFormat(f"{total_vm * page_size // 1024}k", "^"),
                ),
            )
        )
        if not mm:
            return

        rows: List[Sequence[Any]] = [
            (
                CellFormat("VMA", "^"),
                CellFormat("START", "^"),
                CellFormat("END", "^"),
                CellFormat("FLAGS", "<"),
                CellFormat("FILE", "<"),
            )
        ]
        for vma in for_each_vma(mm):
            rows.append(
                (
                    CellFormat(vma.value_(), "^x"),
                    CellFormat(vma.vm_start.value_(), "^x"),
                    CellFormat(vma.vm_end.value_(), "^x"),
                    CellFormat(vma.vm_flags.value_(), "<x"),
                    vma_name(vma),
                )
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
            "tasks",
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
    if not args.tasks:
        args.tasks.append(None)
    return _crash_foreach_vm(_TaskSelector(prog, args.tasks), args)
