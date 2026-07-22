# Copyright (c) IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Disassmebly crash command (dis)."""

import argparse
from typing import Any

from drgn import Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.disasm import disasm


@crash_command(
    description="disassemble",
    long_description="Disassemble the memory at a specific address.",
    arguments=(
        argument(
            "address",
            type="addr_or_sym",
            help="hexadecimal start virtual address or symbol to disassemble",
        ),
        argument(
            "size",
            type="hexadecimal",
            nargs="?",
            help="size of the region to disassemble in bytes",
        ),
        mutually_exclusive_group(
            argument(
                "-d",
                dest="offset_base",
                action="store_const",
                const=10,
                help="override default output format with decimal format.",
            ),
            argument(
                "-x",
                dest="offset_base",
                action="store_const",
                const=16,
                help="override default output format with hexadecimal format.",
            ),
        ),
        mutually_exclusive_group(
            argument(
                "-f",
                dest="forward",
                action="store_true",
                help="dissassemble from addr to addr+size.",
            ),
            argument(
                "-r",
                dest="reverse",
                action="store_true",
                help="disassemble from addr-size to addr.",
            ),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_dis(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.common.disasm", "disasm")
        if args.address[0] == "sym":
            addr_args_str = f'"{args.address[1]}"'
        else:
            addr_args_str = f"{args.address[1]}"
        code.append(
            f"""\
disasm(
    prog,
    {addr_args_str},
    {args.size},
    reverse={args.reverse},
    offset_base={args.offset_base or 10},
)
    """
        )
        code.print()
    else:
        disasm(
            prog,
            args.address[1],
            args.size,
            reverse=args.reverse,
            offset_base=args.offset_base or 10,
        )
