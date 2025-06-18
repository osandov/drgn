# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Filesystem-related commands.

import argparse
from typing import Any

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command, crash_get_context
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.fs import for_each_mount, mount_dst, mount_fstype, mount_src


@crash_command(
    description="mounted filesystems",
    long_description="List mounted filesystems.",
    arguments=(
        argument(
            "-n",
            dest="task",
            metavar="pid|task",
            type="pid_or_task",
            help="list mounted filesystems in the namespace of a task, "
            "given as either a decimal process ID "
            "or a hexadecimal ``task_struct`` address. "
            "Defaults to the mount namespace of the current context",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_mount(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        if args.task is not None and args.task[0] == "task":
            print("from drgn import Object")
        print(
            "from drgn.helpers.linux.fs import for_each_mount, mount_dst, mount_fstype, mount_src"
        )
        if args.task is not None and args.task[0] == "pid":
            print("from drgn.helpers.linux.pid import find_task")
        print()

        if args.task is None:
            print("for mnt in for_each_mount():")
        else:
            if args.task[0] == "pid":
                print(f"task = find_task({args.task[1]})")
            else:
                print(
                    f'task = Object(prog, "struct task_struct *", {hex(args.task[1])})'
                )
            print("mnt_ns = task.nsproxy.mnt_ns")
            print("for mnt in for_each_mount(mnt_ns):")
        print(
            """\
    superblock = mnt.mnt.mnt_sb
    fstype = mount_fstype(mnt)
    devname = mount_src(mnt)
    dirname = mount_dst(mnt)"""
        )
        return

    task = crash_get_context(prog, args.task)
    rows = [
        (
            CellFormat("MOUNT", "^"),
            CellFormat("SUPERBLK", "^"),
            "TYPE",
            "DEVNAME",
            "DIRNAME",
        )
    ]
    for mnt in for_each_mount(task.nsproxy.mnt_ns):
        rows.append(
            (
                CellFormat(mnt.value_(), "^x"),
                CellFormat(mnt.mnt.mnt_sb.value_(), "^x"),
                escape_ascii_string(mount_fstype(mnt), escape_backslash=True),
                escape_ascii_string(mount_src(mnt), escape_backslash=True),
                escape_ascii_string(mount_dst(mnt), escape_backslash=True),
            )
        )
    print_table(rows)
