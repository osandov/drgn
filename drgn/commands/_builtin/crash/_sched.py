# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Scheduler-related crash commands."""

import argparse
import sys
import textwrap
from typing import Any, List, Sequence

from drgn import Object, Program, offsetof
from drgn.commands import _repr_black, argument, drgn_argument, mutually_exclusive_group
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _guess_type,
    _parse_type_name_and_member,
    _prefer_object_lookup,
    _TaskSelector,
    crash_command,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.pid import for_each_task_in_group
from drgn.helpers.linux.signal import (
    decode_sigaction_flags_value,
    decode_sigset,
    signal_numbers,
    sigpending_for_each,
    sigset_to_hex,
)
from drgn.helpers.linux.wait import waitqueue_for_each_task


def _append_sigpending(code: CrashDrgnCodeBuilder, name: str, indent: str = "") -> None:
    code.add_from_import("drgn.helpers.linux.signal", "sigpending_for_each")
    code.append(
        f"""\
{indent}{name}_signals = {name}.signal
{indent}for sigqueue in sigpending_for_each({name}):
{indent}    info = sigqueue.info
{indent}    pending_signo = info.si_signo
"""
    )


def _print_sigpending(pending: Object, indent: str = "") -> None:
    print(indent + "    SIGNAL:", sigset_to_hex(pending.signal))
    rows = []
    first = True
    for sigqueue in sigpending_for_each(pending):
        if first:
            rows.append(
                (
                    indent + "  SIGQUEUE:",
                    CellFormat("SIG", ">"),
                    CellFormat("SIGINFO", "^"),
                )
            )
            first = False
        info = sigqueue.info
        rows.append(("", info.si_signo.value_(), CellFormat(info.address_, "^x")))
    if first:
        print(indent + "  SIGQUEUE: (empty)")
    else:
        print_table(rows)


@_crash_foreach_subcommand(
    arguments=(
        argument(
            "-g",
            dest="thread_group",
            action="store_true",
        ),
        drgn_argument,
    ),
)
def _crash_foreach_sig(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.signal", "decode_sigaction_flags")
            code.append(
                """\

signal_struct = task.signal
nr_threads = signal_struct.nr_threads

for signo, action in enumerate(task.sighand.action, 1):
    sigaction = action.sa
    handler = sigaction.sa_handler
    mask = sigaction.sa_mask
    flags = sigaction.sa_flags
    decoded_flags = decode_sigaction_flags(sigaction)
"""
            )

            if not args.thread_group:
                code.append(
                    """
blocked = task.blocked

private_pending = task.pending
"""
                )
                _append_sigpending(code, "private_pending")

            code.append(
                """
shared_pending = signal_struct.shared_pending
"""
            )
            _append_sigpending(code, "shared_pending")

            if args.thread_group:
                code.add_from_import("drgn.helpers.linux.pid", "for_each_task_in_group")
                code.append(
                    """
for task in for_each_task_in_group(task, include_self=True):
"""
                )
                code.append_task_header("    ")
                code.append(
                    """
    blocked = task.blocked

    private_pending = task.pending
"""
                )
                _append_sigpending(code, "private_pending", "    ")

        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()
        print_task_header(task)

        signal_struct = task.signal.read_()
        print(
            f"SIGNAL_STRUCT: {signal_struct.value_():x}  NR_THREADS: {signal_struct.nr_threads.value_()}"
        )

        rows: List[Sequence[Any]] = [
            (
                CellFormat("SIG", ">"),
                CellFormat("SIGACTION", "^"),
                CellFormat("HANDLER", "^"),
                CellFormat("MASK", "^"),
                "FLAGS",
            ),
        ]
        for signo, action in enumerate(task.sighand.action, 1):
            sa = action.sa

            handler = sa.sa_handler.value_()
            if handler == 0:
                handler_cell = CellFormat("SIG_DFL", "^")
            elif handler == 1:
                handler_cell = CellFormat("SIG_IGN", "^")
            else:
                handler_cell = CellFormat(handler, ">x")

            flags = sa.sa_flags.value_()
            if flags:
                flags_cell = f"{flags:x} ({decode_sigaction_flags_value(prog, flags)})"
            else:
                flags_cell = "0"

            rows.append(
                (
                    CellFormat(f"[{signo}]", ">"),
                    CellFormat(sa.address_, ">x"),
                    handler_cell,
                    sigset_to_hex(sa.sa_mask),
                    flags_cell,
                )
            )
        print_table(rows)

        # Crash also displays SIGPENDING, which checks whether TIF_SIGPENDING
        # is set on the task. But TIF flags are a pain to get, so we omit it
        # for now.
        if not args.thread_group:
            print("   BLOCKED:", sigset_to_hex(task.blocked))
            print("PRIVATE_PENDING")
            _print_sigpending(task.pending)

        print("SHARED_PENDING")
        _print_sigpending(signal_struct.shared_pending)

        if args.thread_group:
            for thread in for_each_task_in_group(task, include_self=True):
                sys.stdout.write("\n  ")
                print_task_header(thread)
                print("     BLOCKED:", sigset_to_hex(thread.blocked))
                print("  PRIVATE_PENDING")
                _print_sigpending(thread.pending, indent="  ")


@crash_command(
    description="signal handling",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-g",
                dest="thread_group",
                action="store_true",
                help="display pending signals for all threads",
            ),
            argument(
                "-l",
                dest="list",
                action="store_true",
                help="display all known signal numbers and names",
            ),
            argument(
                "-s",
                dest="sigset",
                type="hexadecimal",
                help="translate a hexadecimal signal set into a list of signal names",
            ),
        ),
        argument(
            "tasks",
            metavar="pid|task",
            type="pid_or_task",
            nargs="*",
            help="""
            display signal handlers and pending signals for this task, given as
            either a decimal process ID or a hexadecimal ``task_struct``
            address. May be given multiple times. Defaults to the current
            context
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_sig(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    **kwargs: Any,
) -> None:
    if args.list:
        if args.drgn:
            sys.stdout.write(
                """\
from drgn.helpers.linux.signal import signal_numbers


for number, names in signal_numbers().items():
    ...
"""
            )
            return

        print_table(
            [
                (CellFormat(f"[{number}]", ">"), "/".join(names))
                for number, names in sorted(signal_numbers(prog).items())
            ],
            sep=" ",
        )
        return

    if args.sigset is not None:
        if args.drgn:
            sys.stdout.write(
                f"""\
from drgn.helpers.linux.signal import decode_sigset


decoded = decode_sigset({hex(args.sigset)})
"""
            )
            return

        decoded = decode_sigset(prog, args.sigset)
        decoded = decoded.replace("{", "").replace("}", "").replace(",", " ")
        print(textwrap.fill(decoded, width=80))
        return

    if not args.tasks:
        args.tasks.append(None)
    return _crash_foreach_sig(_TaskSelector(prog, args.tasks), args)


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
