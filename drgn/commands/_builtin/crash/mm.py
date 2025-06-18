# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import print_table
from drgn.helpers.linux.mm import follow_phys, page_to_phys, phys_to_page


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
        print(
            """\
PHYS_PFN(address)
# or
address >> prog["PAGE_SHIFT"]"""
        )
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
        print(
            """\
PFN_PHYS(address)
# or
address << prog["PAGE_SHIFT"]"""
        )
        return

    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
    for pfn in args.pfn:
        print(f"{pfn:x}: {pfn << PAGE_SHIFT:x}")


@crash_command(
    description="physical or per-CPU to virtual",
    long_description="TODO",
    arguments=(
        argument(
            "address",
            metavar="address|offset:cpuspec",
            type="hexadecimal",
            nargs="+",
            help="hexadecimal physical address or hexadecimal per-CPU offset and CPU specifier",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ptov(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        print("phys_to_virt(address)")
        return

    # TODO


@crash_command(
    description="virtual to physical",
    long_description="TODO",
    arguments=(
        # TODO: -c flag
        # argument(
        #     "-c", dest="task", metavar="pid | taskp", help="TODO"
        # ),
        # TODO: -k, -u flags
        argument(
            "address", type="hexadecimal", nargs="+", help="hexadecimal virtual address"
        ),
        drgn_argument,
    ),
)
def _crash_cmd_vtop(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # TODO: --drgn

    mm = prog["init_mm"].address_of_()

    for i, address in enumerate(args.address):
        phys = follow_phys(mm, address)
        page = phys_to_page(phys)

        if i != 0:
            print()
        print_table(
            (
                ("VIRTUAL", "PHYSICAL"),
                (f"{address:x}", f"{phys.value_():x}"),
            )
        )

        # TODO: page table info

        # TODO: crash tries printing VMAs, possibly other things?

        print()
        # TODO: we justify things differently than crash
        print_table(
            (
                ("PAGE", "PHYSICAL", "MAPPING", "INDEX", "CNT", "FLAGS"),
                (
                    f"{page.value_():x}",
                    f"{page_to_phys(page).value_():x}",
                    f"{page.mapping.value_():x}",
                    "TODO",  # TODO: not sure what base these are in
                    "TODO",
                    f"{page.flags.value_():x}",
                ),
            )
        )
