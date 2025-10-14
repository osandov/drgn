# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands (other than kmem)."""

import argparse
from typing import Any, List, Sequence

from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, parse_cpuspec
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.mm import phys_to_virt
from drgn.helpers.linux.percpu import per_cpu_ptr
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
    description="physical or per-CPU to virtual",
    long_description="""This command translates a hexadecimal physical address into a
                        kernel virtual address. Alternatively, a hexadecimal per-cpu
                        offset and cpu specifier will be translated into kernel virtual
                        addresses for each cpu specified.""",
    arguments=(
        argument(
            "address",
            metavar="address|offset:cpuspec",
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
        # Create a single builder for all addresses
        builder = CrashDrgnCodeBuilder(prog)
        physical_addresses = []
        per_cpu_offsets = []

        for address in args.address:
            if ":" in address:
                # Add imports only once
                builder.add_from_import("drgn", "Object")
                builder.add_from_import("drgn.helpers.linux.percpu", "per_cpu_ptr")
                builder.add_from_import(
                    "drgn.helpers.linux.cpumask", "for_each_possible_cpu"
                )
                # Parse the cpuspec in the actual command code
                offset_str, cpu_spec = address.split(":", 1)
                offset = int(offset_str, 16)
                per_cpu_offsets.append((offset, parse_cpuspec(cpu_spec)))
            else:
                # Add imports only once
                builder.add_from_import("drgn.helpers.linux.mm", "phys_to_virt")
                physical_addresses.append(int(address, 16))

        # Generate code for physical addresses
        if physical_addresses:
            builder.append("addresses = [")
            builder.append(", ".join(f"0x{addr:x}" for addr in physical_addresses))
            builder.append("]\n")
            builder.append("for address in addresses:\n")
            builder.append("    virt = phys_to_virt(address)\n")

        # Generate code for per-CPU offsets
        for offset, cpuspec in per_cpu_offsets:
            builder.append(f"\noffset = {offset:#x}\n")
            builder.append_cpuspec(
                cpuspec,
                """
    virt = per_cpu_ptr(Object(prog, 'void *', offset), cpu)
                """,
            )

        # Print the generated code once at the end
        builder.print()
        return

    # Handle direct execution without --drgn
    for i, address in enumerate(args.address):
        if i > 0:
            print()  # Add a blank line between outputs for multiple addresses

        if ":" in address:
            # Handle per-CPU offset case
            offset_str, cpu_spec = address.split(":", 1)
            offset = int(offset_str, 16)

            # Parse CPU specifier using parse_cpuspec
            cpus = parse_cpuspec(cpu_spec)

            # Print offset information
            print(f"PER-CPU OFFSET: {offset:x}")  # Directly print offset information

            # Prepare data for print_table()
            rows = [("  CPU", "  VIRTUAL")]  # Add CPU and VIRTUAL header
            ptr = Object(prog, "void *", offset)  # Changed type to "void *"
            for cpu in cpus.cpus(prog):
                virt = per_cpu_ptr(ptr, cpu)
                rows.append((f"  [{cpu}]", f"{virt.value_():016x}"))

            # Print the table
            print_table(rows)
        else:
            # Handle physical address case
            phys = int(address, 16)
            virt = phys_to_virt(prog, phys)
            virt_int = virt.value_()

            # Prepare data for print_table()
            rows = [("VIRTUAL", "PHYSICAL"), (f"{virt_int:016x}", f"{phys:x}")]

            # Print the table
            print_table(rows)


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
