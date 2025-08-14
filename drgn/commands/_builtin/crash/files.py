# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Commands for displaying open file descriptors and file-related information for processes."""

import argparse
from typing import Any

from drgn import NULL, Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command, crash_get_context
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import d_path, for_each_file, mode_to_type
from drgn.helpers.linux.pid import find_task


def pretty_print_header(task: Object) -> None:
    """
    Print a summary header for a given task, including PID, task address, CPU, command,
    root directory, and current working directory.

    :param task: struct task_struct *
    """

    root_path = d_path(task.fs.root)
    cwd_path = d_path(task.fs.pwd)
    print(
        f'PID: {task.pid.value_():<8} TASK: {task.value_():016x}  CPU: {task.cpu.value_():<3}  COMMAND: "{task.comm.string_().decode()}"'
    )
    print(
        f"ROOT: {root_path.decode(errors='replace'):<6} CWD: {cwd_path.decode(errors='replace')}"
    )


def print_task_files_cache(task: Object) -> None:
    """
    Print open file descriptors for a given task, showing inode, i_mapping,
    nrpages, type, and path (for -c/--cache option).
    """
    print(f"{'FD':>3} {'INODE':^16} {'I_MAPPING':^16} {'NRPAGES':^7} {'TYPE':^4} PATH")
    for fd, file in for_each_file(task):
        dentry = file.f_path.dentry
        inode = dentry.d_inode
        i_mapping = inode.i_mapping
        nrpages = i_mapping.nrpages.value_()
        f_type = mode_to_type(inode.i_mode.value_())
        path = d_path(file.f_path)
        escaped_path = escape_ascii_string(path, escape_backslash=True)
        print(
            f"{fd:3} {inode.value_():016x} {i_mapping.value_():016x} {nrpages:7} {f_type:4} {escaped_path:16}"
        )


def print_task_files(task: Object) -> None:
    """
    Print open file descriptors for a given task, showing file, dentry, inode,
    type, and path (default output).
    """

    rows = []
    for fd, file in for_each_file(task):
        dentry = file.f_path.dentry
        inode = dentry.d_inode
        f_type = mode_to_type(inode.i_mode.value_())
        path = d_path(file.f_path)
        escaped_path = escape_ascii_string(path, escape_backslash=True)
        rows.append(
            f"{fd:>3} {file.value_():016x} {dentry.value_():016x} {inode.value_():016x} {f_type:4} {escaped_path:16}"
        )
    if rows:
        print(f"{'FD':>3} {'FILE':<16} {'DENTRY':<16} {'INODE':<16} {'TYPE':<4} PATH")
        for row in rows:
            print(row)
    else:
        print("No open files")


def print_task_file_refs(task: Object, reference: str) -> None:
    """
    Print open files of a task that match the given reference.
    Reference can be a file descriptor number, filename, dentry, inode,
    address_space, or file structure address.

    :param task: struct task_struct *
    :param reference: Reference to search for (fd number, filename, or address as hex string)
    """

    try:
        ref_addr = int(reference, 16)
    except ValueError:
        ref_addr = None

    matches = []
    for fd, file in for_each_file(task):
        dentry = file.f_path.dentry
        inode = dentry.d_inode
        i_mapping = inode.i_mapping
        path = d_path(file.f_path).decode(errors="replace")
        if (
            (
                ref_addr is not None
                and (
                    file.value_() == ref_addr
                    or dentry.value_() == ref_addr
                    or inode.value_() == ref_addr
                    or i_mapping.value_() == ref_addr
                )
            )
            or reference == str(fd)
            or reference in path
        ):
            f_type = mode_to_type(inode.i_mode.value_())
            matches.append(
                (fd, file.value_(), dentry.value_(), inode.value_(), f_type, path)
            )

    if matches:
        pretty_print_header(task)
        print(f"{'FD':>3} {'FILE':<16} {'DENTRY':<16} {'INODE':<16} {'TYPE':<4} PATH")
        for fd, file_v, dentry_v, inode_v, f_type, path in matches:
            print(
                f"{fd:>3} {file_v:016x} {dentry_v:016x} {inode_v:016x} {f_type:4} {path:16}"
            )
    else:
        print("No references found.")


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
            "target",
            nargs="?",
            type=str,
            help="a process PID (decimal) or a hexadecimal task_struct pointer.",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_files(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        return
    if args.dentry:
        dentry_addr = int(args.dentry, 16)
        dentry = Object(prog, "struct dentry *", value=dentry_addr).read_()
        inode = dentry.d_inode
        sb = inode.i_sb
        ftype = mode_to_type(inode.i_mode.value_())
        path = d_path(dentry)
        print(f"{'DENTRY':<16} {'INODE':<16} {'SUPERBLK':<16} {'TYPE':<4} PATH")
        print(
            f"{dentry.value_():016x} {inode.value_():016x} {sb.value_():016x} {ftype:4} {path.decode(errors='replace')}"
        )
        return
    if args.inode:
        inode_addr = int(args.inode, 16)
        inode = Object(prog, "struct inode *", value=inode_addr).read_()
        nrpages = inode.i_mapping.nrpages.value_()
        print(f"{'INODE':^16} {'NRPAGES'}")
        print(f"{inode.value_():016x} {nrpages:>7}")
        return
    if args.target:
        try:
            pid = int(args.target, 10)
            task = find_task(pid)
            if task == NULL(prog, "struct task_struct *"):
                raise RuntimeError(f"invalid task or pid value: {args.target}")
        except ValueError:
            try:
                task_addr = int(args.target, 16)
                task = Object(prog, "struct task_struct *", value=task_addr).read_()
            except Exception:
                raise RuntimeError(f"invalid task or pid value: {args.target}")
    else:
        task = crash_get_context(prog)
    if args.reference:
        print_task_file_refs(task, args.reference)
        return
    pretty_print_header(task)
    if args.cache:
        print_task_files_cache(task)
        return
    print_task_files(task)
