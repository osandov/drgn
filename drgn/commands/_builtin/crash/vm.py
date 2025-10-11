# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any, List

from drgn import Object, Program
from drgn.commands import CommandArgumentError, argument, drgn_argument
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _pid_or_task,
    crash_command,
    crash_get_context,
)
from drgn.helpers.common.format import print_table
from drgn.helpers.linux.fs import inode_path
from drgn.helpers.linux.mm import for_each_vma, get_task_rss_info
from drgn.helpers.linux.sched import task_cpu


def _get_file_path(vma: Object, mm: Object) -> str:
    """Get the file path name corresponding to the VMA"""
    if vma.vm_file:
        try:
            path_bytes = inode_path(vma.vm_file.f_inode)
            if path_bytes is None:
                return "<unknown>"
            file_path = path_bytes.decode()
            return file_path if file_path.startswith("/") else f"/{file_path}"
        except Exception:
            return "<unknown>"

    # Handle special memory regions
    start = vma.vm_start.value_()
    end = vma.vm_end.value_()

    if mm.start_brk.value_() <= start and end <= mm.brk.value_():
        return "[heap]"
    elif start <= mm.start_stack.value_() < end:
        return "[stack]"
    elif (
        hasattr(mm.context, "vdso")
        and mm.context.vdso
        and mm.context.vdso.value_() >= start
        and mm.context.vdso.value_() < end
    ):
        return "[vdso]"

    return "[anon]"


def _get_tasks_from_args(prog: Program, pids_or_tasks: List[str]) -> List[Object]:
    """Get task list from command line arguments"""
    if not pids_or_tasks:
        return [crash_get_context(prog, None)]

    tasks = []
    for arg in pids_or_tasks:
        try:
            task = crash_get_context(prog, _pid_or_task(arg))
            tasks.append(task)
        except Exception:
            print(f"vm: invalid task or pid value: {arg!r}")
            continue

    return tasks


def _generate_drgn_code(prog: Program, args: argparse.Namespace) -> None:
    """Generate DRGN code mode output"""
    code = CrashDrgnCodeBuilder(prog)
    code.add_from_import("drgn", "Object")
    code.add_from_import("drgn.helpers.linux.mm", "for_each_vma, get_task_rss_info")
    code.add_from_import("drgn.helpers.linux.sched", "task_cpu")
    code.add_from_import("drgn.helpers.linux.fs", "inode_path")
    code.add_from_import("drgn.helpers.common.format", "print_table")
    code.add_from_import("drgn.helpers.linux.pid", "find_task")

    # Build task list
    code.append("tasks = [\n")
    if not args.pids_or_tasks:
        ctx = crash_get_context(prog, None)
        code.append(f"    {ctx!r},\n")
    else:
        pid_list = []
        task_list = []
        invalid_args = []
        for arg in args.pids_or_tasks:
            try:
                typ, val = _pid_or_task(arg)
                if typ == "pid":
                    pid_list.append(val)
                elif typ == "task":
                    task_list.append(val)
            except (ValueError, CommandArgumentError):
                invalid_args.append(arg)
        for pid in pid_list:
            code.append(f"    find_task(prog, {pid}),\n")
        for addr in task_list:
            code.append(f'    Object(prog, "struct task_struct *", value={addr:#x}),\n')

        for arg in invalid_args:
            code.append(f"    # vm: invalid task or pid value: {arg}\n")
    code.append("]\n\n")

    # Add processing logic
    code.append(
        """\
for task in tasks:
    # Get basic task info
    pid = int(task.pid)
    task_addr = task.value_()
    cpu = task_cpu(task)
    command = task.comm.string_().decode()

    mm=task.mm
    if mm:
        # Get memory statistics
        mm_addr = mm.value_()
        pgd = mm.pgd.value_()
        rss_info = get_task_rss_info(task)
        rss = rss_info.total
        total_vm = mm.total_vm.value_() * prog['PAGE_SIZE'].value_()
        # Get VMA info
        for vma in for_each_vma(mm):
            vma_addr = vma.value_()
            vm_start = vma.vm_start.value_()
            vm_end = vma.vm_end.value_()
            vm_flags = vma.vm_flags.value_()

            # Get file path
            if vma.vm_file:
                try:
                    file_path = inode_path(vma.vm_file.f_inode).decode()
                    if not file_path.startswith("/"):
                        file_path = "/" + file_path
                except Exception:
                    file_path = "<unknown>"
            else:
                file_path = "[anon]"
    else:
        # No memory mapping
        mm_addr = 0
        pgd = 0
        rss = 0
        total_vm = 0
"""
    )
    code.print()


def _print_task_vm_info(prog: Program, task: Object) -> None:
    """Print virtual memory info for a single task"""
    pid = int(task.pid)
    cpu = task_cpu(task)
    command = task.comm.string_().decode()
    task_addr = task.value_()

    print(f'PID: {pid}\tTASK: {task_addr:#x}\tCPU: {cpu}\tCOMMAND: "{command}"')

    mm = task.mm
    if not mm:
        stats_rows = [["MM", "PGD", "RSS", "TOTAL_VM"], ["0", "0", "0k", "0k"]]
        print_table(stats_rows)
        print()
        return

    # Show memory statistics
    rss_info = get_task_rss_info(task)
    total_vm_kb = mm.total_vm.value_() * prog["PAGE_SIZE"].value_() // 1024

    stats_rows = [
        ["MM", "PGD", "RSS", "TOTAL_VM"],
        [
            f"{mm.value_():#x}",
            f"{mm.pgd.value_():#x}",
            f"{rss_info.total}k",
            f"{total_vm_kb}k",
        ],
    ]
    print_table(stats_rows)

    # Show detailed VMA info
    rows = [["VMA", "START", "END", "FLAGS", "FILE"]]
    for vma in for_each_vma(mm):
        file_path = _get_file_path(vma, mm)
        rows.append(
            [
                f"{vma.value_():#x}",
                f"{vma.vm_start.value_():#x}",
                f"{vma.vm_end.value_():#x}",
                f"{vma.vm_flags.value_():#x}",
                file_path,
            ]
        )

    print_table(rows)
    print()


@crash_command(
    description="virtual memory",
    long_description="""This command displays basic virtual memory information of a context,
consisting of a pointer to its mm_struct and page directory, its RSS and
total virtual memory size; and a list of pointers to each vm_area_struct,
its starting and ending address, vm_flags value, and file pathname. If no
arguments are entered, the current context is used.
""",
    usage="**vm** [*pids* | *tasks*]... [**--drgn**]",
    arguments=(
        argument(
            "pids_or_tasks",
            metavar="pids | tasks",
            nargs="*",
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

    # Non-drgn mode
    tasks = _get_tasks_from_args(prog, args.pids_or_tasks)

    for task in tasks:
        if task:  # Add null check
            _print_task_vm_info(prog, task)
