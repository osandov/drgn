# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import Any

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import crash_command, parse_cpuspec
from drgn.helpers.linux.mm import phys_to_virt


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
        if ":" in args.address[0]:
            print("from drgn.commands.crash import parse_cpuspec")
            print(f'address = ["{args.address[0]}"]')
            print("""
    offset_str, cpu_spec = address.split(":", 1)
    offset = int(offset_str, 16)
    cpus = parse_cpuspec(cpu_spec)
    print("PER-CPU OFFSET: {:x}".format(offset))
    print("  CPU    VIRTUAL")
    for cpu in cpus.cpus(prog):
        virt = prog["__per_cpu_offset"][cpu].value_() + offset
        print("  [{:d}]  {:016x}".format(cpu, virt))
                  """)
            return 
        else:
            print("from drgn.helpers.linux.mm import phys_to_virt")
            print("phys_to_virt(address)")
            return

    # Parse input address or per-CPU offset
    if ":" in args.address[0]:
        # Handle per-CPU offset case
        offset_str, cpu_spec = args.address[0].split(":", 1)
        offset = int(offset_str, 16)
        
        # Parse CPU specifier using parse_cpuspec
        cpus = parse_cpuspec(cpu_spec)

        # Translate per-CPU offsets
        print("PER-CPU OFFSET: {:x}".format(offset))
        print("  CPU    VIRTUAL")
        for cpu in cpus.cpus(prog):
            virt = prog["__per_cpu_offset"][cpu].value_() + offset
            print("  [{:d}]  {:016x}".format(cpu, virt))
    else:
        # Handle physical address case
        address_str = args.address[0]
        phys = int(address_str, 16)
        virt = phys_to_virt(phys)
        virt_int = virt.value_() 
        print("VIRTUAL           PHYSICAL")
        print("{:016x}  {:x}".format(virt_int, phys), flush=True)

