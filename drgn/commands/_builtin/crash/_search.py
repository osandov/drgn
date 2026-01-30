# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import re
from typing import Any, List, Literal, Tuple, Union

from drgn import FaultError, MemorySearchIterator, Program
from drgn.commands import (
    _repr_black,
    _repr_raw_bytes,
    argument,
    argument_group,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands._builtin.crash._rd import _print_memory
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _addr_or_sym,
    _resolve_addr_or_sym,
    crash_command,
    print_task_header,
)
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import cpu_curr

# Number of bytes to print for a string search (including the matching string
# itself). This is copied from crash (although crash seems to truncate the
# searched string to this size, too).
_STRING_CONTEXT = 56


def _search_drgn_option(prog: Program, args: argparse.Namespace) -> None:
    code = CrashDrgnCodeBuilder(prog)

    for_targets = (
        "address" if args.strings and len(args.values) == 1 else "address, value"
    )

    need_it = (
        args.task_stacks
        or args.active_task_stacks
        or args.start is not None
        or args.end is not None
        or args.length is not None
        or args.physical
    )

    if need_it:
        code.append("it = ")
    else:
        code.append(f"for {for_targets} in ")

    if args.strings:
        if len(args.values) == 1:
            code.add_from_import("drgn", "search_memory")
            code.append("search_memory(")
            code.append(_repr_black(args.values[0]))
            code.append(")")
        else:
            pattern = bytearray()
            for value in args.values:
                if pattern:
                    pattern.extend(b"|")
                pattern.extend(re.escape(value.encode()))
            code.add_from_import("drgn", "search_memory_regex")
            code.append("search_memory_regex(")
            code.append(_repr_raw_bytes(pattern))
            code.append(")")
    else:
        if args.u32:
            iterator_func = "search_memory_u32"
        elif args.u16:
            iterator_func = "search_memory_u16"
        else:
            iterator_func = "search_memory_word"
        code.add_from_import("drgn", iterator_func)
        code.append(iterator_func)
        code.append("(")

        first = True
        for value in args.values:
            if first:
                first = False
            else:
                code.append(", ")
            code.append_addr_or_sym(_addr_or_sym(value))

        if args.ignore_mask is not None:
            code.append(f", ignore_mask={args.ignore_mask:#x}")
        code.append(")")

    if need_it:
        code.append("\n")
    else:
        code.begin_block(":\n")

    if args.task_stacks or args.active_task_stacks:
        code.append('\nstack_size = prog["THREAD_SIZE"].value_()\n')
        if args.task_stacks:
            code.add_from_import("drgn.helpers.linux.pid", "for_each_task")
            code.begin_block("for task in for_each_task(idle=True):\n")
        else:
            code.add_from_import("drgn.helpers.linux.cpumask", "for_each_online_cpu")
            code.add_from_import("drgn.helpers.linux.sched", "cpu_curr")
            code.begin_block("for cpu in for_each_online_cpu():\n")
            code.append("task = cpu_curr(cpu)\n")
        code.append(
            """\
stack = task.stack.value_()
if not stack:
    continue
it.set_address_range(stack, stack + stack_size - 1)
"""
        )

    if (
        args.start is not None
        or args.end is not None
        or args.length is not None
        or args.physical
    ):
        first = True
        if args.start is not None and args.length is not None:
            code.append("min_address = ")
            code.append_addr_or_sym(args.start)
            code.append("\n")
            code.append(
                f"it.set_address_range(min_address=min_address, max_address=min_address + {args.length} - 1"
            )
            first = False
        else:
            code.append("it.set_address_range(")
            first = True
            if args.start is not None:
                code.append("min_address=")
                code.append_addr_or_sym(args.start)
                first = False
            if args.end is not None:
                if first:
                    first = False
                else:
                    code.append(", ")
                code.append("max_address=")
                code.append_addr_or_sym(args.end)
                code.append(" - 1")
            elif args.length is not None:
                assert first
                code.append(", ")
                first = False
                code.append(f"max_address = {args.length} - 1")

        if args.physical:
            if first:
                first = False
            else:
                code.append(", ")
            code.append("physical=True")
        code.append(")\n")

    if need_it:
        code.begin_block(f"for {for_targets} in it:\n")
    code.append("...\n")

    code.end_block()  # For the it loop.
    if args.task_stacks or args.active_task_stacks:
        code.end_block()

    code.print()


@crash_command(
    description="search memory",
    long_description="""
    Display every memory address where one or more values are found.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-p",
                dest="physical",
                action="store_true",
                help="search physical addresses",
            ),
            argument(
                "-t",
                dest="task_stacks",
                action="store_true",
                help="search only kernel stacks of all tasks",
            ),
            argument(
                "-T",
                dest="active_task_stacks",
                action="store_true",
                help="search only kernel stacks of active tasks",
            ),
        ),
        argument(
            "-s",
            dest="start",
            type="addr_or_sym",
            help="start searching at this hexadecimal address or symbol name",
        ),
        mutually_exclusive_group(
            argument(
                "-e",
                dest="end",
                type="addr_or_sym",
                help="stop searching at this hexadecimal address or symbol name",
            ),
            argument(
                "-l",
                dest="length",
                type="decimal_or_hexadecimal",
                help="search this many bytes",
            ),
        ),
        argument_group(
            mutually_exclusive_group(
                argument(
                    "-c",
                    dest="strings",
                    action="store_true",
                    help="search for strings",
                ),
                argument(
                    "-w",
                    dest="u32",
                    action="store_true",
                    help="search for unsigned ints",
                ),
                argument(
                    "-h",
                    dest="u16",
                    action="store_true",
                    help="search for unsigned shorts",
                ),
            ),
            title="units",
            description="""
            What unit the values to search for are in. The default is unsigned
            long.
            """,
        ),
        argument(
            "-x",
            dest="context",
            type=int,
            help="""
            display this many extra units of memory before and after every
            found value. Cannot be used with **-c**
            """,
        ),
        argument(
            "-m",
            dest="ignore_mask",
            type="hexadecimal",
            help="""
            ignore bits set in this hexadecimal mask. Cannot be used with
            **-c**
            """,
        ),
        argument(
            "values",
            metavar="value",
            nargs="+",
            help="""
            value to search for. Unless **-c** is given, then this is a
            hexadecimal integer, or a symbol name to use its address. If **-c**
            is given, then this is an arbitrary string
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_search(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    if args.task_stacks or args.active_task_stacks:
        if args.start is not None:
            parser.error("-s cannot be used with -t or -T")
        if args.end is not None:
            parser.error("-e cannot be used with -t or -T")
        if args.length is not None:
            parser.error("-l cannot be used with -t or -T")

    if args.strings:
        if args.ignore_mask is not None:
            parser.error("-m cannot be used with -c")
        if args.context is not None:
            parser.error("-x cannot be used with -c")

    if args.drgn:
        return _search_drgn_option(prog, args)

    address_size = prog.address_size()
    symbols = {}
    it: Union[
        MemorySearchIterator[Tuple[int, int]], MemorySearchIterator[Tuple[int, bytes]]
    ]
    if args.strings:
        pattern_parts: List[bytes] = []
        for value in args.values:
            value_bytes = value.encode()
            if pattern_parts:
                pattern_parts.append(b"|")
            pattern_parts.append(re.escape(value_bytes))
            if len(value_bytes) < _STRING_CONTEXT:
                pattern_parts.append(b"(?s:.){0,")
                pattern_parts.append(str(_STRING_CONTEXT - len(value_bytes)).encode())
                pattern_parts.append(b"}")
        it = prog.search_memory_regex(b"".join(pattern_parts))
    else:
        values = []
        for value in args.values:
            try:
                values.append(int(value, 16))
            except ValueError:
                symbol_name = value
                value = prog.symbol(symbol_name).address
                values.append(value)
                symbols[value] = symbol_name
        if args.ignore_mask is None:
            args.ignore_mask = 0
        if args.u32:
            unit: Literal[1, 2, 4, 8] = 4
            it = prog.search_memory_u32(*values, ignore_mask=args.ignore_mask)
        elif args.u16:
            unit = 2
            it = prog.search_memory_u16(*values, ignore_mask=args.ignore_mask)
        else:
            unit = address_size  # type: ignore[assignment]
            it = prog.search_memory_word(*values, ignore_mask=args.ignore_mask)

    first_match = True

    def print_match(address: int, value: Union[int, bytes]) -> None:
        nonlocal first_match

        if isinstance(value, int):
            value_str = f"{value:x}"
            try:
                symbol_name = symbols[value]
            except KeyError:
                pass
            else:
                value_str = f"{value_str} ({symbol_name})"
        else:
            # Replace non-printable characters with ".".
            value_str = re.sub(rb"[^ -~]", b".", value).decode("ascii")

        if args.context:
            if first_match:
                first_match = False
            else:
                print()

            for size in range(args.context * unit, 0, -unit):
                try:
                    mem = prog.read(address - size, size)
                except FaultError:
                    pass
                else:
                    _print_memory(prog, address - size, mem, unit)
                    break

            print(f"{address:{address_size * 2}x}:  {value_str}")

            for size in range(args.context * unit, 0, -unit):
                try:
                    mem = prog.read(address + unit, size)
                except FaultError:
                    pass
                else:
                    _print_memory(prog, address + unit, mem, unit)
                    break
        else:
            print(f"{address:x}: {value_str}")

    if args.task_stacks or args.active_task_stacks:
        if args.task_stacks:
            tasks = for_each_task(prog, idle=True)
        else:
            tasks = (cpu_curr(prog, cpu) for cpu in for_each_online_cpu(prog))
        first = True
        thread_size = prog["THREAD_SIZE"].value_()
        for task in tasks:
            stack = task.stack.value_()
            if not stack:
                continue
            it.set_address_range(stack, stack + thread_size - 1)
            found_match = False
            for address, value in it:
                if not found_match:
                    if first:
                        first = False
                    else:
                        print()
                    print_task_header(task)
                    found_match = True
                print_match(address, value)
    else:
        min_address = 0
        max_address = None
        if args.start is not None:
            min_address = _resolve_addr_or_sym(prog, args.start)
        if args.end is not None:
            max_address = _resolve_addr_or_sym(prog, args.end) - 1
        elif args.length is not None:
            max_address = min_address + args.length - 1
        it.set_address_range(
            min_address=min_address, max_address=max_address, physical=args.physical
        )
        for address, value in it:
            print_match(address, value)
