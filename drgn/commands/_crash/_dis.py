# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands (other than kmem)."""

import argparse
import sys
from typing import Any, List, Sequence

from drgn import Architecture, FaultError, Object, Platform, Program
from drgn.commands import (
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands._crash.common import (
    _resolve_addr_or_sym,
    crash_command,
)

try:
    from capstone import *
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


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
                dest="decimal",
                action="store_true",
                help="override default output format with decimal format.",
            ),
            argument(
                "-x",
                dest="hexadecimal",
                action="store_true",
                help="override default output format with hexadecimal format.",
            ),
        ),
        mutually_exclusive_group(
            argument(
                "-f",
                dest="forward",
                action="store_true",
                help="override default output format with decimal format.",
            ),
            argument(
                "-r",
                dest="reverse",
                action="store_true",
                help="override default output format with hexadecimal format.",
            ),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_dis(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        print("from capstone import *")
        print("")
        capstone_args = {
            Architecture.X86_64: "CS_ARCH_X86, CS_MODE_64",
            Architecture.I386: "CS_ARCH_X86, CS_MODE_32",
            Architecture.AARCH64: "CS_ARCH_ARM64, CS_MODE_ARM",
            Architecture.ARM: "CS_ARCH_ARM, CS_MODE_ARM",
            Architecture.PPC64: "CS_ARCH_PPC, CS_MODE_64",
            Architecture.S390X: "CS_ARCH_SYSZ, 0",
            Architecture.S390: "CS_ARCH_SYSZ, 0",
        }.get(prog.platform.arch)
        print(f"disassembler = Cs({capstone_args:s})")
        print(f"try:")
        print(f"    symbol = prog.symbol({args.address[1]})")
        print(f"except LookupError:")
        print(f"    symbol = None")
        if args.address[0] == "sym":
            print(f"addr = symbol.address")
        else:
            print(f"addr = {args.address[1]}")
        if args.size is None:
            print("if symbol:")
            if args.reverse:
                print("    size = addr - symbol.address")
                print("    addr = symbol.address")
            else:
                print("    size = symbol.size - (addr - symbol.address)")
            print("else:")
            print("    size = 20")
        else:
            print(f"size = {args.size}")
        print(f"machine_code = prog.read(addr, size)")
        print(f"for i in disassembler.disasm(machine_code, addr):")
        print("    if symbol:")
        print("        offset = i.address - symbol.address")
        if args.hexadecimal:
            print("        print(f\"0x{i.address:x} <{symbol.namer:s}+0x{offset:x}>:\\t{i.mnemonic}\\t{i.op_str}\")")
        else:
            print("        print(f\"0x{i.address:x} <{symbol.namer:s}+{offset:d}>:\\t{i.mnemonic}\\t{i.op_str}\")")
        print("    else:")
        print("        print(f\"0x{i.address:x}:\\t{i.mnemonic}\\t{i.op_str}\")")

        return None
    if not HAVE_CAPSTONE:
        print("The crash dis command reqiires the python capstone library bindings")
        return
    capstone_args = {
        Architecture.X86_64: (CS_ARCH_X86, CS_MODE_64),
        Architecture.I386: (CS_ARCH_X86, CS_MODE_32),
        Architecture.AARCH64: (CS_ARCH_ARM64, CS_MODE_ARM),
        Architecture.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
        Architecture.PPC64: (CS_ARCH_PPC, CS_MODE_64),
        Architecture.S390X: (CS_ARCH_SYSZ, 0),
        Architecture.S390: (CS_ARCH_SYSZ, 0),
    }.get(prog.platform.arch)
    disassembler = Cs(*capstone_args)
    addr = _resolve_addr_or_sym(prog, args.address)
    size = args.size or 20
    try:
        symbol = prog.symbol(args.address[1])
    except LookupError:
        symbol = None
    if args.size is None and symbol:
        if args.reverse:
            size = addr - symbol.address
            addr = symbol.address
        else:
            size = symbol.size - (addr - symbol.address)
    machine_code = prog.read(addr, size)
    for i in disassembler.disasm(machine_code, addr):
        if symbol:
            offset = i.address - symbol.address
            num_string = f"0x{offset:x}" if args.hexadecimal else f"{offset:d}"
            print(f"0x{i.address:x} <{symbol.name:s}+{num_string:s}>:\t{i.mnemonic}\t{i.op_str}")
        else:
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

