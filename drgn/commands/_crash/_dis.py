# Copyright (c) IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Disassembly crash command (dis)."""

import argparse
from typing import Any, Literal, Optional

from drgn import Program
from drgn.commands import _repr_black, argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.disassembly import disasm


@crash_command(
    description="disassemble",
    long_description="Disassemble the code at a specific address.",
    arguments=(
        argument(
            "address",
            metavar="address|symbol",
            type="addr_or_sym",
            help="""
            hexadecimal address, symbol name, or ``symbol+offset`` to
            disassemble. If this is a function name or the address of the start
            of a function and *count* is not given, then the whole function is
            disassembled. Otherwise, one instruction is disassembled
            """,
        ),
        argument(
            "count",
            type="decimal_or_hexadecimal",
            nargs="?",
            help="number of instructions to disassemble",
        ),
        argument(
            "-x",
            dest="offset_base",
            action="store_const",
            const=16,
            help="output symbol offsets in hexadecimal format regardless of the default",
        ),
        argument(
            "-d",
            dest="offset_base",
            action="store_const",
            const=10,
            help="output symbol offsets in decimal format regardless of the default",
        ),
        mutually_exclusive_group(
            argument(
                "-f",
                dest="forward",
                action="store_true",
                help="""
                disassemble from the given address to the end of the function.
                Ignored if *count* is given
                """,
            ),
            argument(
                "-r",
                dest="reverse",
                action="store_true",
                help="""
                disassemble from the start of the function up to and including
                the given address. If *count* is given, only display the last
                *count* instructions
                """,
            ),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_dis(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    address = args.address[1]
    mode: Optional[Literal["from", "up_to"]] = None
    num_insns = args.count
    offset_base = args.offset_base or prog.config.get("crash_radix", 10)

    if args.reverse:
        mode = "up_to"
    elif num_insns is None:
        if args.forward:
            mode = "from"
        else:
            # Like crash, disassemble the whole function if given its name or
            # starting address and one instruction otherwise.
            if args.address[0] == "sym":
                if "+" in address:
                    num_insns = 1
            else:
                try:
                    if prog.symbol(address).address != address:
                        num_insns = 1
                except LookupError:
                    pass

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.common.disassembly", "disasm")
        code.append("disasm(")
        code.append(hex(address) if args.address[0] == "addr" else _repr_black(address))
        if mode is not None:
            code.append(f", mode={_repr_black(mode)}")
        if num_insns is not None:
            code.append(f", num_insns={num_insns}")
        if offset_base != 16:
            code.append(f", offset_base={offset_base}")
        code.append(")\n")
        return code.print()

    disasm(prog, address, mode=mode, num_insns=num_insns, offset_base=offset_base)
