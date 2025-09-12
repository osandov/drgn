# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands."""

import argparse
import sys
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import (
    CellFormat,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.linux.hugetlb import hugetlb_total_usage
from drgn.helpers.linux.mm import (
    for_each_vmap_area,
    global_node_page_state,
    nr_blockdev_pages,
    nr_free_pages,
    totalram_pages,
    vm_commit_limit,
    vm_memory_committed,
)
from drgn.helpers.linux.slab import slab_total_usage
from drgn.helpers.linux.swap import (
    for_each_swap_info,
    swap_file_path,
    swap_is_file,
    swap_total_usage,
    swap_usage_in_pages,
    total_swapcache_pages,
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


def _kmem_info(
    prog: Program,
    drgn_arg: bool,
) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.hugetlb", "hugetlb_total_usage")
        code.add_from_import(
            "drgn.helpers.linux.mm",
            "global_node_page_state",
            "nr_blockdev_pages",
            "nr_free_pages",
            "totalram_pages",
            "vm_commit_limit",
            "vm_memory_committed",
        )
        code.add_from_import("drgn.helpers.linux.slab", "slab_total_usage")
        code.add_from_import(
            "drgn.helpers.linux.swap", "swap_total_usage", "total_swapcache_pages"
        )
        code.append(
            """\
total_mem = totalram_pages()
free = nr_free_pages()
used = total_mem - free
buffers = nr_blockdev_pages()
cached = (
    global_node_page_state(prog["NR_FILE_PAGES"]) - total_swapcache_pages() - buffers
)
slab_usage = slab_total_usage()

hugetlb_usage = hugetlb_total_usage()

swap_usage = swap_total_usage()

commit_limit = vm_commit_limit()
committed = vm_memory_committed()
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = [
        (
            "",
            CellFormat("PAGES", ">"),
            CellFormat("TOTAL", ">"),
            CellFormat("PERCENTAGE", "^"),
        )
    ]

    page_size = prog["PAGE_SIZE"].value_()

    def binary_units_cell(n: int) -> CellFormat:
        return CellFormat(
            "0" if n == 0 else number_in_binary_units(n * page_size) + "B", ">"
        )

    total_mem = totalram_pages(prog)
    rows.append(
        (
            CellFormat("TOTAL MEM", ">"),
            total_mem,
            binary_units_cell(total_mem),
            CellFormat("----", "^"),
        )
    )

    free = nr_free_pages(prog)
    buffers = nr_blockdev_pages(prog)
    cached = (
        global_node_page_state(prog["NR_FILE_PAGES"])
        - total_swapcache_pages(prog)
        - buffers
    )

    for label, pages in (
        ("FREE", free),
        ("USED", total_mem - free),
        ("BUFFERS", buffers),
        ("CACHED", cached),
        ("SLAB", slab_total_usage(prog).total_pages),
    ):
        rows.append(
            (
                CellFormat(label, ">"),
                pages,
                binary_units_cell(pages),
                CellFormat(f"{pages / total_mem:.0%} of TOTAL MEM", ">"),
            ),
        )

    rows.append(())

    hugetlb_usage = hugetlb_total_usage(prog)
    rows.append(
        (
            CellFormat("TOTAL HUGE", ">"),
            hugetlb_usage.pages,
            binary_units_cell(hugetlb_usage.pages),
            CellFormat("----", "^"),
        )
    )
    rows.append(
        (
            CellFormat("HUGE FREE", ">"),
            hugetlb_usage.free_pages,
            binary_units_cell(hugetlb_usage.free_pages),
            CellFormat(
                f"{hugetlb_usage.free_pages / hugetlb_usage.pages if hugetlb_usage.pages else 0:.0%} of TOTAL HUGE",
                ">",
            ),
        )
    )

    rows.append(())

    swap_usage = swap_total_usage(prog)
    rows.append(
        (
            CellFormat("TOTAL SWAP", ">"),
            swap_usage.pages,
            binary_units_cell(swap_usage.pages),
            CellFormat("----", "^"),
        )
    )
    for label, pages in (
        ("SWAP USED", swap_usage.used_pages),
        ("SWAP FREE", swap_usage.free_pages),
    ):
        rows.append(
            (
                CellFormat(label, ">"),
                pages,
                binary_units_cell(pages),
                CellFormat(
                    f"{pages / swap_usage.pages if swap_usage.pages else 0:.0%} of TOTAL SWAP",
                    ">",
                ),
            )
        )

    rows.append(())

    commit_limit = vm_commit_limit(prog)
    committed = vm_memory_committed(prog)
    rows.append(
        (
            CellFormat("COMMIT LIMIT", ">"),
            commit_limit,
            binary_units_cell(commit_limit),
            CellFormat("----", "^"),
        )
    )
    rows.append(
        (
            CellFormat("COMMITTED", ">"),
            committed,
            binary_units_cell(committed),
            CellFormat(
                f"{committed / commit_limit:.0%} of TOTAL LIMIT",
                ">",
            ),
        )
    )

    print_table(rows)


def _kmem_vmalloc(
    prog: Program,
    drgn_arg: bool,
) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.mm import for_each_vmap_area


for va in for_each_vmap_area():
    vm = va.vm
    start = va.va_start
    end = va.va_end
    size = end - start
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("VMAP_AREA", "^"),
            CellFormat("VM_STRUCT", "^"),
            CellFormat("ADDRESS RANGE", "^"),
            CellFormat("SIZE", ">"),
        )
    ]
    for va in for_each_vmap_area(prog):
        start = va.va_start.value_()
        end = va.va_end.value_()
        rows.append(
            (
                CellFormat(va.value_(), "^x"),
                CellFormat(va.vm.value_(), "^x"),
                CellFormat(f"{start:x} - {end:x}", "^"),
                end - start,
            )
        )

    print_table(rows)


@crash_command(
    description="kernel memory",
    long_description="""
    Display information about various parts of the memory management subsystem.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-i",
                dest="info",
                action="store_true",
                help="display general memory usage information",
            ),
            argument(
                "-v",
                dest="vmalloc",
                action="store_true",
                help="display memory regions allocated with vmalloc()/vmap()",
            ),
            required=True,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_kmem(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.info:
        return _kmem_info(prog, args.drgn)
    if args.vmalloc:
        return _kmem_vmalloc(prog, args.drgn)


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
