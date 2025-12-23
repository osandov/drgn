# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Filesystem-related commands.

import argparse
import operator
import os
import sys
from typing import Any, List

from drgn import Object, Program
from drgn.commands import _repr_black, argument, drgn_argument, mutually_exclusive_group
from drgn.commands._builtin.crash._kmem import _print_pages_default_members
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _TaskSelector,
    crash_command,
    crash_get_context,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.fs import (
    address_space_for_each_page,
    d_path,
    decode_file_type,
    for_each_file,
    for_each_mount,
    mount_dst,
    mount_fstype,
    mount_src,
)


def _print_dentry(prog: Program, address: int, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            f"""\
from drgn import Object
from drgn.helpers.linux.fs import d_path, decode_file_type


dentry = Object(prog, "struct dentry *", {hex(address)})
inode = dentry.d_inode
sb = inode.i_sb
type = decode_file_type(inode.i_mode)
path = d_path(dentry)
"""
        )
        return

    dentry = Object(prog, "struct dentry *", address)
    inode = dentry.d_inode.read_()
    sb = inode.i_sb.read_()
    print_table(
        (
            (
                CellFormat("DENTRY", "^"),
                CellFormat("INODE", "^"),
                CellFormat("SUPERBLK", "^"),
                "TYPE",
                "PATH",
            ),
            (
                CellFormat(dentry.value_(), "^x"),
                CellFormat(inode.value_(), "^x"),
                CellFormat(sb.value_(), "^x"),
                decode_file_type(inode.i_mode),
                escape_ascii_string(d_path(dentry), escape_backslash=True),
            ),
        )
    )


def _print_inode(prog: Program, address: int, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn", "Object")
        code.add_from_import("drgn.helpers.linux.fs", "inode_for_each_page")
        code.add_from_import(
            "drgn.helpers.linux.mm",
            "decode_page_flags_value",
            "page_flags",
            "page_to_phys",
        )
        code.append(
            f"""\
inode = Object(prog, "struct inode *", {hex(address)})
i_mapping = inode.i_mapping
nrpages = i_mapping.nrpages

for index, page in inode_for_each_page(inode):
    physical = page_to_phys(page)
    cnt = page._refcount.counter
    flags = page_flags(page)
    decoded_flags = decode_page_flags_value(flags)
"""
        )
        return code.print()

    inode = Object(prog, "struct inode *", address)
    mapping = inode.i_mapping.read_()
    print_table(
        (
            (CellFormat("INODE", "^"), CellFormat("NRPAGES", ">")),
            (CellFormat(inode.value_(), "^x"), mapping.nrpages.value_()),
        )
    )

    print()
    mapping_value = mapping.value_()
    _print_pages_default_members(
        prog,
        address_space_for_each_page(mapping),
        get_page=operator.itemgetter(1),
        get_mapping=lambda _: mapping_value,
        get_index=operator.itemgetter(0),
    )


@_crash_foreach_subcommand(
    arguments=(
        argument(
            "-c",
            dest="cache",
            action="store_true",
        ),
        argument(
            "-R",
            dest="reference",
        ),
        drgn_argument,
    ),
)
def _crash_foreach_files(
    task_selector: _TaskSelector, args: argparse.Namespace
) -> None:
    prog = task_selector.prog

    reference_int = None
    if args.reference is not None:
        try:
            reference_int = int(args.reference, 10)
            reference_int_base = 10
        except ValueError:
            try:
                reference_int = int(args.reference, 16)
                reference_int_base = 16
            except ValueError:
                pass

        reference_path = os.fsencode(args.reference)

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)

        if reference_int is not None:
            if reference_int_base == 10:
                code.append(f"reference = {reference_int}\n")
            else:
                code.append(f"reference = {hex(reference_int)}\n")
        if args.reference is not None:
            code.add_import("os")
            code.append(
                f"reference_path = os.fsencode({_repr_black(args.reference)})\n\n"
            )

        with task_selector.begin_task_loop(code):
            code.append_task_header()

            code.add_from_import(
                "drgn.helpers.linux.fs", "d_path", "decode_file_type", "for_each_file"
            )

            code.append(
                """
root = d_path(task.fs.root)
cwd = d_path(task.fs.pwd)

"""
            )
            if args.reference is not None:
                code.append(
                    """\
is_match = (reference_path in root) or (reference_path in cwd)

"""
                )

            code.append("for fd, file in for_each_file(task):\n")
            if args.cache:
                code.append(
                    """\
    inode = file.f_inode
    i_mapping = inode.i_mapping
    nrpages = i_mapping.nrpages
"""
                )
            else:
                code.append(
                    """\
    dentry = file.f_path.dentry
    inode = file.f_inode
"""
                )
            code.append(
                """\
    type = decode_file_type(inode.i_mode)
    path = d_path(file.f_path)
"""
            )
            if reference_int is not None:
                code.append(
                    """\
    is_match = (
        fd == reference
"""
                )
                if args.cache:
                    code.append(
                        """\
        or inode.value_() == reference
        or i_mapping.value_() == reference
"""
                    )
                else:
                    code.append(
                        """\
        or file.value_() == reference
        or dentry.value_() == reference
        or inode.value_() == reference
"""
                    )
                code.append(
                    """\
        or reference_path in path
    )
"""
                )
            elif args.reference is not None:
                code.append(
                    """\
    is_match = reference_path in path
"""
                )
        return code.print()

    first = True
    for task in task_selector.tasks():
        row: List[Any] = [CellFormat("FD", ">")]
        if args.cache:
            row.append(CellFormat("INODE", "^"))
            row.append(CellFormat("I_MAPPING", "^"))
            row.append(CellFormat("NRPAGES", ">"))
        else:
            row.append(CellFormat("FILE", "^"))
            row.append(CellFormat("DENTRY", "^"))
            row.append(CellFormat("INODE", "^"))
        row.append("TYPE")
        row.append("PATH")
        rows = [row]

        for fd, file in for_each_file(task):
            f_path = file.f_path.read_()
            inode = file.f_inode.read_()
            if args.cache:
                mapping = inode.i_mapping.read_()
            else:
                dentry = f_path.dentry.read_()
            path = d_path(f_path)

            if args.reference is not None and not (
                (
                    reference_int is not None
                    and (
                        fd == reference_int
                        or inode.value_() == reference_int
                        # Crash only matches against the columns that it prints
                        # depending on -c.
                        or (args.cache and mapping.value_() == reference_int)
                        or (not args.cache and file.value_() == reference_int)
                        or (not args.cache and dentry.value_() == reference_int)
                    )
                )
                or reference_path in path
            ):
                continue

            row = [fd]
            if args.cache:
                row.append(CellFormat(inode.value_(), "^x"))
                row.append(CellFormat(mapping.value_(), "^x"))
                row.append(mapping.nrpages.value_())
            else:
                row.append(CellFormat(file.value_(), "^x"))
                row.append(CellFormat(dentry.value_(), "^x"))
                row.append(CellFormat(inode.value_(), "^x"))
            row.append(decode_file_type(inode.i_mode))
            row.append(escape_ascii_string(path, escape_backslash=True))
            rows.append(row)

        fs = task.fs
        root_path = d_path(fs.root)
        cwd_path = d_path(fs.pwd)
        if (
            args.reference is None
            or len(rows) > 1
            or reference_path in root_path
            or reference_path in cwd_path
        ):
            if first:
                first = False
            else:
                print()
            print_task_header(task)

            fs = task.fs
            print(
                f"ROOT: {escape_ascii_string(root_path, escape_backslash=True)}"
                f"  CWD: {escape_ascii_string(cwd_path, escape_backslash=True)}"
            )

            if len(rows) > 1:
                print_table(rows)
            elif args.reference is None:
                print("No open files")


@crash_command(
    description="file information",
    long_description="""
    Show file information. By default, display the root directory, current
    working directory, and all open files of one or more tasks, including the
    file descriptor, file structure, dentry, inode, file type, and path.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-d",
                dest="dentry",
                type="hexadecimal",
                help="""
                display the inode, super block, file type, and full path of a
                dentry, given as a hexadecimal address
                """,
            ),
            argument(
                "-p",
                dest="inode",
                type="hexadecimal",
                help="""
                display the pages in the page cache of an inode, given as a
                hexadecimal address
                """,
            ),
            argument(
                "tasks",
                metavar="pid|task",
                type="pid_or_task",
                nargs="*",
                # Work around https://github.com/python/cpython/issues/72795
                # before Python 3.13.
                default=[],
                help="""
                display open files for this task, given as either a decimal process
                ID or a hexadecimal ``task_struct`` address. May be given multiple
                times. Defaults to the current context
                """,
            ),
        ),
        argument(
            "-c",
            dest="cache",
            action="store_true",
            help="""
            for each open file, display the i_mapping and number of cached
            pages instead of the file structure and dentry
            """,
        ),
        argument(
            "-R",
            dest="reference",
            help="""
            search for references to this file descriptor, path, or dentry,
            inode, address_space, or file structure address
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_files(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    # -c and -R are mutually exclusive with -d and -p, but not with each other
    # or with tasks. argparse can't express this.
    if (args.cache or args.reference is not None) and (args.dentry or args.inode):
        parser.error("-c/-R not allowed with -d/-p")

    if args.dentry is not None:
        return _print_dentry(prog, args.dentry, args.drgn)
    elif args.inode is not None:
        return _print_inode(prog, args.inode, args.drgn)

    if not args.tasks:
        args.tasks.append(None)
    return _crash_foreach_files(_TaskSelector(prog, args.tasks), args)


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
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.fs",
            "for_each_mount",
            "mount_dst",
            "mount_fstype",
            "mount_src",
        )
        # Avoid the context/mount namespace noise if -n wasn't given and the
        # current context is in the initial mount namespace.
        if (
            args.task is None
            and crash_get_context(prog).nsproxy.mnt_ns
            == prog["init_task"].nsproxy.mnt_ns
        ):
            code.append("for mnt in for_each_mount():\n")
        else:
            code.append_crash_context(args.task)
            code.append(
                """\

mnt_ns = task.nsproxy.mnt_ns
for mnt in for_each_mount(mnt_ns):
"""
            )

        code.append(
            """\
    superblock = mnt.mnt.mnt_sb
    fstype = mount_fstype(mnt)
    devname = mount_src(mnt)
    dirname = mount_dst(mnt)
"""
        )
        code.print()
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
