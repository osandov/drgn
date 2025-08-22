# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any

from drgn import Object, Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, parse_cpuspec
from drgn.helpers.common.format import print_table
from drgn.helpers.linux.mm import phys_to_virt
from drgn.helpers.linux.percpu import per_cpu_ptr


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
        for address in args.address:
            if ":" in address:
                # Parse the cpuspec in the actual command code
                offset_str, cpu_spec = address.split(":", 1)
                offset = int(offset_str, 16)

                # Use CrashDrgnCodeBuilder to generate code
                builder = CrashDrgnCodeBuilder(prog)
                builder.add_from_import("drgn.helpers.linux.percpu", "per_cpu_ptr")
                builder.add_from_import("drgn", "Object")
                builder.append(f"offset = {offset:#x}\n")
                builder.append_cpuspec(
                    parse_cpuspec(cpu_spec),
                    """
virt = per_cpu_ptr(Object(prog, 'unsigned long', offset), cpu)
                    """,
                )
                builder.print()
            else:
                # Generate code for physical address translation
                builder = CrashDrgnCodeBuilder(prog)
                builder.add_from_import("drgn.helpers.linux.mm", "phys_to_virt")
                builder.append(f"address = {address!r}\n")
                builder.append("virt = phys_to_virt(int(address, 16))\n")
                builder.print()
        return

    # Handle direct execution without --drgn
    for address in args.address:
        if ":" in address:
            # Handle per-CPU offset case
            offset_str, cpu_spec = address.split(":", 1)
            offset = int(offset_str, 16)

            # Parse CPU specifier using parse_cpuspec
            cpus = parse_cpuspec(cpu_spec)

            # Prepare data for print_table()
            rows = []  # Add header row
            rows.append(("PER-CPU OFFSET: ", f"{offset:x}"))  # Add offset information
            rows.append(("  CPU", "  VIRTUAL"))  # Add CPU and VIRTUAL header
            ptr = Object(prog, "unsigned long", offset)
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
