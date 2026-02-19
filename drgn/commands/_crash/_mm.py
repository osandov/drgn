# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands (other than kmem)."""

import argparse
import sys
from typing import Any, List, Sequence

from drgn import Architecture, FaultError, Object, Platform, Program
from drgn.commands import (
    DrgnCodeBlockContext,
    argument,
    argument_group,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands._crash.common import (
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _TaskSelector,
    crash_command,
    parse_cpuspec,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.mm import (
    follow_phys,
    for_each_vma,
    phys_to_virt,
    task_rss,
    vma_name,
)
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
            with builder.begin_cpuspec_loop(cpuspec):
                builder.append(
                    'virt = per_cpu_ptr(Object(prog, "void *", offset), cpu)\n'
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


# This is not an exhaustive list.
def _overlapping_address_spaces(prog: Program) -> bool:
    platform: Platform = prog.platform  # type: ignore[assignment]  # platform can't be None.
    return platform.arch == Architecture.S390X


@_crash_foreach_subcommand(
    arguments=(
        mutually_exclusive_group(
            argument(
                "-u",
                dest="user",
                action="store_true",
            ),
            argument(
                "-k",
                dest="kernel",
                action="store_true",
            ),
        ),
        argument(
            "addresses",
            metavar="address",
            type="hexadecimal",
            nargs="+",
        ),
        drgn_argument,
    ),
)
def _crash_foreach_vtop(
    task_selector: _TaskSelector, args: argparse.Namespace, *, task_headers: bool = True
) -> None:
    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn", "FaultError")
        code.add_from_import("drgn.helpers.linux.mm", "follow_phys")

        if len(args.addresses) == 1:
            code.append(f"virtual_address = {hex(args.addresses[0])}\n\n")
        else:
            code.append(
                "virtual_addresses = ("
                + ", ".join([hex(address) for address in args.addresses])
                + ")\n\n"
            )

        def virtual_address_loop() -> DrgnCodeBlockContext:
            if len(args.addresses) == 1:
                return code.begin_block("")
            else:
                return code.begin_block("for virtual_address in virtual_addresses:\n")

        if not args.user:
            if not args.kernel:
                code.append("# As kernel address.\n")
            code.append('init_mm = prog["init_mm"].address_of_()\n')
            with virtual_address_loop():
                code.append(
                    """\
try:
    physical_address = follow_phys(init_mm, virtual_address)
except FaultError:
    pass
"""
                )

        if not args.kernel:
            if not args.user:
                code.append("\n# As user address.\n")
            with task_selector.begin_task_loop(code):
                if task_headers:
                    code.append_task_header()

                with code.begin_block(
                    """\
mm = task.mm.read_()
if mm:
"""
                ), virtual_address_loop():
                    code.append(
                        """\
try:
    physical_address = follow_phys(mm, virtual_address)
except FaultError:
    pass
"""
                    )
        return code.print()

    overlapping = _overlapping_address_spaces(prog)
    init_mm = prog["init_mm"].address_of_()

    first_task = True
    for task in task_selector.tasks():
        if first_task:
            first_task = False
        else:
            print()
        if task_headers:
            print_task_header(task)

        mm = task.mm.read_()
        if not args.kernel and not args.user and mm and not overlapping:
            task_size = mm.task_size.value_()

        first_address = True
        for address in args.addresses:
            if first_address:
                first_address = False
            else:
                print()

            kernel_phys_addr = None
            user_phys_addr = None
            if args.kernel or (
                not args.user and (not mm or overlapping or address >= task_size)
            ):
                try:
                    kernel_phys_addr = follow_phys(init_mm, address).value_()
                except FaultError:
                    pass
            if args.user or (
                not args.kernel and mm and (overlapping or address < task_size)
            ):
                try:
                    user_phys_addr = follow_phys(mm, address).value_()
                except FaultError:
                    pass

            if kernel_phys_addr is not None and user_phys_addr is not None:
                print(
                    "error: ambiguous address: %x: -u or -k is required",
                    address,
                    file=sys.stderr,
                )
                continue
            elif kernel_phys_addr is None and user_phys_addr is None:
                phys_addr_cell: Any = "(not accessible)"
            else:
                phys_addr_cell = CellFormat(
                    kernel_phys_addr if user_phys_addr is None else user_phys_addr, "<x"
                )
            print_table(
                (
                    ("VIRTUAL", "PHYSICAL"),
                    (CellFormat(address, "<x"), phys_addr_cell),
                )
            )


@crash_command(
    description="virtual to physical address",
    arguments=(
        argument_group(
            mutually_exclusive_group(
                argument(
                    "-u",
                    dest="user",
                    action="store_true",
                    help="treat addresses as user space virtual addresses",
                ),
                argument(
                    "-k",
                    dest="kernel",
                    action="store_true",
                    help="treat addresses as kernel space virtual addresses",
                ),
            ),
            title="address space",
            description="""
            In some kernel configurations, whether an address belongs to kernel
            space or user space can be determined from only its value. In those
            cases, this command will automatically determine whether the
            address belongs to kernel or user space.

            In other configurations (including s390x, SPARC, and 4G:4G), this
            is not possible, and one of these options is required.
            """,
        ),
        argument(
            "-c",
            dest="task",
            type="pid_or_task",
            help="""
            PID or hexadecimal task_struct pointer of task whose address space
            should be used for translating virtual addresses
            """,
        ),
        argument(
            "addresses",
            metavar="address",
            type="hexadecimal",
            nargs="+",
            help="hexadecimal virtual address",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_vtop(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    return _crash_foreach_vtop(
        _TaskSelector(prog, [args.task]), args, task_headers=False
    )


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


@_crash_foreach_subcommand(
    arguments=(drgn_argument,),
)
def _crash_foreach_vm(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import(
                "drgn.helpers.linux.mm", "for_each_vma", "task_rss", "vma_name"
            )
            code.append(
                """\

mm = task.mm.read_()
if mm:
    pgd = mm.pgd
    rss = task_rss(task)
    total_vm = mm.total_vm

    for vma in for_each_vma(mm):
        start = vma.vm_start
        end = vma.vm_end
        flags = vma.vm_flags
        file = vma_name(vma)
"""
            )
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()
        print_task_header(task)

        mm = task.mm.read_()
        if mm:
            pgd_value = mm.pgd.value_()
            rss_total = task_rss(task).total
            total_vm = mm.total_vm.value_()
        else:
            pgd_value = rss_total = total_vm = 0
        page_size = prog["PAGE_SIZE"].value_()
        print_table(
            (
                (
                    CellFormat("MM", "^"),
                    CellFormat("PGD", "^"),
                    CellFormat("RSS", "^"),
                    CellFormat("TOTAL_VM", "^"),
                ),
                (
                    CellFormat(mm.value_(), "^x"),
                    CellFormat(pgd_value, "^x"),
                    CellFormat(f"{rss_total * page_size // 1024}k", "^"),
                    CellFormat(f"{total_vm * page_size // 1024}k", "^"),
                ),
            )
        )
        if not mm:
            return

        rows: List[Sequence[Any]] = [
            (
                CellFormat("VMA", "^"),
                CellFormat("START", "^"),
                CellFormat("END", "^"),
                CellFormat("FLAGS", "<"),
                CellFormat("FILE", "<"),
            )
        ]
        for vma in for_each_vma(mm):
            rows.append(
                (
                    CellFormat(vma.value_(), "^x"),
                    CellFormat(vma.vm_start.value_(), "^x"),
                    CellFormat(vma.vm_end.value_(), "^x"),
                    CellFormat(vma.vm_flags.value_(), "<x"),
                    escape_ascii_string(vma_name(vma), escape_backslash=True),
                )
            )
        print_table(rows)


@crash_command(
    description="virtual memory",
    long_description="""This command displays basic virtual memory information of a context,
consisting of a pointer to its mm_struct and page directory, its RSS and
total virtual memory size; and a list of pointers to each vm_area_struct,
its starting and ending address, vm_flags value, and file pathname. If no
arguments are entered, the current context is used.
""",
    arguments=(
        argument(
            "tasks",
            metavar="pid|task",
            nargs="*",
            type="pid_or_task",
            help="one or more process PIDs or hexadecimal task_struct pointers",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_vm(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if not args.tasks:
        args.tasks.append(None)
    return _crash_foreach_vm(_TaskSelector(prog, args.tasks), args)
