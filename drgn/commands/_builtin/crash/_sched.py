# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Scheduler-related crash commands."""

import argparse
from typing import Any

from drgn import Object, Program, offsetof
from drgn.commands import _repr_black, argument, drgn_argument
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _guess_type,
    _parse_type_name_and_member,
    _prefer_object_lookup,
    crash_command,
    print_task_header,
)
from drgn.helpers.linux.wait import waitqueue_for_each_task


@crash_command(
    description="list tasks on a wait queue",
    usage=r"**waitq** (*symbol* | *address* | *struct.member* *struct_addr*) [**\-\-drgn**]",
    arguments=(
        # argparse can't express symbol | address | struct.member struct_addr,
        # so we use this hack to consume all of the positional arguments (which
        # we parse manually) and define dummy arguments that are only used for
        # the help string.
        argument(
            "posargs",
            nargs="*",
            # Work around https://github.com/python/cpython/issues/72795
            # before Python 3.13.
            default=[],
            help=argparse.SUPPRESS,
        ),
        argument(
            "symbol",
            nargs="?",
            help="symbol name of wait queue",
        ),
        argument(
            "address",
            nargs="?",
            help="hexadecimal address of wait queue",
        ),
        argument(
            "struct.member",
            nargs="?",
            help="""
            name of structure type containing a wait queue member with the
            given name
            """,
        ),
        argument(
            "struct_addr",
            nargs="?",
            help="address of structure containing wait queue member",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_waitq(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    is_symbol = False
    if not args.posargs:
        parser.error("symbol, address, or struct is required")
    elif len(args.posargs) == 1:
        try:
            address = int(args.posargs[0], 16)
        except ValueError:
            is_symbol = True
    elif len(args.posargs) == 2:
        type_name, member = _parse_type_name_and_member(args.posargs[0])
        address = int(args.posargs[1], 16)
        try:
            offset_type = _guess_type(prog, type_name)
        except LookupError:
            if not args.drgn:
                raise
            type_name = "struct " + type_name
        else:
            type_name = offset_type.type_name()
    else:
        parser.error(f"unrecognized arguments: {' '.join(args.posargs[2:])}")

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.wait", "waitqueue_for_each_task")

        if len(args.posargs) == 2:
            code.add_from_import("drgn", "Object", "offsetof")
            code.append(
                f"""\
address = {hex(address)}
address += offsetof(prog.type({_repr_black(type_name)}), {_repr_black(member)})
wq = Object(prog, "wait_queue_head_t *", address)
"""
            )
        elif not is_symbol:
            code.add_from_import("drgn", "Object")
            code.append(f'wq = Object(prog, "wait_queue_head_t *", {hex(address)})\n')
        elif _prefer_object_lookup(prog, "wait_queue_head_t", args.posargs[0]):
            code.append(f"wq = prog[{_repr_black(args.posargs[0])}].address_of_()\n")
        else:
            code.add_from_import("drgn", "Object")
            code.append(
                f"""\
address = prog.symbol({_repr_black(args.posargs[0])}).address
wq = Object(prog, "wait_queue_head_t *", address)
"""
            )

        code.append("\nfor task in waitqueue_for_each_task(wq):\n")
        code.append_task_header(indent="    ")
        code.print()
        return

    if len(args.posargs) == 2:
        address += offsetof(offset_type, member)
    elif is_symbol:
        address = prog.symbol(args.posargs[0]).address

    wq = Object(prog, "wait_queue_head_t *", address)
    empty = True
    for task in waitqueue_for_each_task(wq):
        empty = False
        print_task_header(task)
    if empty:
        wq_name = f"{address:x}"
        if is_symbol:
            wq_name = f"{_repr_black(args.posargs[0])} ({wq_name})"
        print(f"wait queue {wq_name} is empty")
