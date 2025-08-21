# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands."""

import argparse
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.swap import (
    for_each_swap_info,
    swap_file_path,
    swap_is_file,
    swap_usage_in_pages,
)


@crash_command(
    description="bytes to page",
    long_description="Convert byte numbers (usually physical addresses) to page numbers.",
    arguments=(
        argument(
            "address",
            type="hexadecimal",
            nargs="+",
            help="hexadecimal byte number/physical address",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_btop(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.mm", "PHYS_PFN")

        if len(args.address) == 1:
            code.append(f"phys_addr = {hex(args.address[0])}\n")
        else:
            code.append("for phys_addr in ")
            for i, address in enumerate(args.address):
                if i > 0:
                    code.append(", ")
                code.append(hex(address))
            code.append(":\n    ")

        code.append("pfn = PHYS_PFN(phys_addr)\n")
        code.print()
        return

    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
    for address in args.address:
        print(f"{address:x}: {address >> PAGE_SHIFT:x}")


@crash_command(
    description="page to bytes",
    long_description="Convert page frame numbers to byte numbers (physical addresses).",
    arguments=(
        argument(
            "pfn", type="decimal_or_hexadecimal", nargs="+", help="page frame number"
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ptob(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.mm", "PFN_PHYS")

        if len(args.pfn) == 1:
            code.append(f"pfn = {hex(args.pfn[0])}\n")
        else:
            code.append("for pfn in ")
            for i, pfn in enumerate(args.pfn):
                if i > 0:
                    code.append(", ")
                code.append(hex(pfn))
            code.append(":\n    ")

        code.append("phys_addr = PFN_PHYS(pfn)\n")
        code.print()
        return

    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
    for pfn in args.pfn:
        print(f"{pfn:x}: {pfn << PAGE_SHIFT:x}")


@crash_command(
    description="list swap devices",
    arguments=(drgn_argument,),
)
def _crash_cmd_swap(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.swap",
            "for_each_swap_info",
            "swap_file_path",
            "swap_is_file",
            "swap_usage_in_pages",
        )
        code.append(
            """\
for si in for_each_swap_info():
    is_file = swap_is_file(si)
    pages = si.pages
    used_pages = swap_usage_in_pages(si)
    priority = si.prio
    path = swap_file_path(si)
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = [
        (
            "SWAP_INFO_STRUCT",
            CellFormat("TYPE", "^"),
            CellFormat("SIZE", "^"),
            CellFormat("USED", "^"),
            CellFormat("PCT", ">"),
            CellFormat("PRI", ">"),
            "FILENAME",
        ),
    ]
    for si in for_each_swap_info(prog):
        size = (si.pages * prog["PAGE_SIZE"]).value_()
        used = swap_usage_in_pages(si) * prog["PAGE_SIZE"].value_()
        rows.append(
            (
                CellFormat(si.value_(), "x"),
                CellFormat(
                    "FILE" if swap_is_file(si) else "PARTITION",
                    "^",
                ),
                CellFormat(f"{size // 1024}k", "^"),
                CellFormat(f"{used // 1024}k", "^"),
                CellFormat(used / size, ".0%"),
                si.prio.value_(),
                escape_ascii_string(swap_file_path(si)),
            ),
        )
    print_table(rows)
