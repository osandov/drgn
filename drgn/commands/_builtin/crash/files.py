# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Commands for displaying open file descriptors and file-related information for processes."""

import argparse
from typing import Any, Optional

from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command, crash_get_context
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import d_path, for_each_file
from drgn.helpers.linux.pid import find_task


def mode_to_type(mode: int) -> Optional[str]:
    type_bits = mode & 0xF000
    return {
        0x2000: "CHR",
        0x4000: "DIR",
        0x6000: "BLK",
        0x8000: "REG",
        0xA000: "LNK",
        0xC000: "SOCK",
        0x1000: "FIFO",
    }.get(type_bits)


def pretty_print_header(task: Object) -> None:
    root_path = d_path(task.fs.root)
    cwd_path = d_path(task.fs.pwd)
    print(
        f'PID: {task.pid.value_():<8} TASK: {task.value_():#018x}  CPU: {task.cpu.value_():<3}  COMMAND: "{task.comm.string_().decode()}"'
    )
    print(
        f"ROOT: {root_path.decode(errors='replace'):6} CWD: {cwd_path.decode(errors='replace')}"
    )
    print(f"{'FD':>3} {'FILE':<16} {'DENTRY':<16} {'INODE':<16} {'TYPE':<4} PATH")


def print_task_files(task: Object) -> None:
    for fd, file in for_each_file(task):
        dentry = file.f_path.dentry
        inode = dentry.d_inode
        path = d_path(file.f_path)
        f_type = mode_to_type(inode.i_mode.value_())
        escaped_path = escape_ascii_string(path, escape_backslash=True)
        print(
            f"{fd:>3} {file.value_():016x} {dentry.value_():016x} {inode.value_():016x} {f_type:4} {escaped_path:16}"
        )


@crash_command(
    description="file descriptor information",
    long_description="display open file descriptors for processes",
    arguments=(
        argument(
            "-d",
            dest="dentry",
            metavar="DENTRY",
            type=str,
            help="given a hexadecimal dentry address, display its inode, super block, file type, and full pathname.",
        ),
        argument(
            "-p",
            dest="inode",
            metavar="INODE",
            type=str,
            help="given a hexadecimal inode address, dump all of its pages that are in the page cache.",
        ),
        argument(
            "-c",
            dest="cache",
            action="store_true",
            default=False,
            help="for each open file descriptor, print inode pointer, i_mapping, page count, file type, and pathname.",
        ),
        argument(
            "-R",
            dest="reference",
            metavar="REFERENCE",
            type=str,
            help="search for references to this file descriptor number, filename, dentry, inode, address_space, or file structure address.",
        ),
        argument(
            "pid",
            nargs="?",
            type=int,
            help="a process PID.",
        ),
        argument(
            "taskp",
            nargs="?",
            type=str,
            help="a hexadecimal task_struct pointer.",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_files(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.pid:
        task = find_task(args.pid)
    else:
        task = crash_get_context(prog)
    pretty_print_header(task)
    print_task_files(task)
