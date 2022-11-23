#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

r"""
This script reads a drgn architecture definition file ("arch_foo_defs.py") and
outputs architecture definition code which must then be processed by
gen_strswitch.py to produce the final "arch_foo.inc" file.

The definition file must define three global variables:

* REGISTERS must be a sequence of DrgnRegister defining the names of all of the
  registers in the architecture. They should be defined in the architecture's
  logical order. See DrgnRegister below for more details.

* REGISTER_LAYOUT must be a sequence of DrgnRegisterLayout defining how drgn
  stores the registers in memory. The defined registers are laid out
  sequentially. To minimize memory usage, registers can be ordered by how
  commonly they are saved (typically, the program counter/return address
  register first, then the stack pointer register, then callee-saved registers,
  and last caller-saved registers). They can also be ordered to match the
  format in, e.g., NT_PRSTATUS. Every register in REGISTERS must have an entry
  in REGISTER_LAYOUT. However, the converse does not need to be true. For
  example, REGISTER_LAYOUT can contain pseudo-registers that are not in
  REGISTERS and are thus not exposed to the API. See DrgnRegisterLayout below
  for more details.

* STACK_POINTER_REGISTER must be the identifier of the register which contains
  the stack pointer.

The generated file includes "arch_register_layout.h" and defines several things:

1. An enum of register numbers used to implement DRGN_REGISTER_NUMBER().

2. A structure corresponding to the register layout used to implement
   DRGN_REGISTER_OFFSET(), DRGN_REGISTER_SIZE(), and DRGN_REGISTER_END():
   struct drgn_arch_register_layout;

3. An array of register layouts indexed by internal register number:
   static const struct drgn_register_layout register_layout[];

4. An array of register definitions:
   static const struct drgn_register registers[];

5. A name lookup function:
   static const struct drgn_register *register_by_name(const char *name);

6. A mapping from DWARF register numbers to internal register numbers:
   static drgn_register_number dwarf_regno_to_internal(uint64_t dwarf_regno);

7. A macro containing initializers for the "register_layout",
   "dwarf_regno_to_internal", "registers", "num_registers",
   "stack_pointer_regno", and "register_by_name" members of
   "struct drgn_architecture_info":
   #define DRGN_ARCHITECTURE_REGISTERS ...
"""

import argparse
import re
import runpy
import sys
from typing import Optional, Sequence, TextIO, Union

from codegen_utils import c_string_literal


class ArchDefsError(Exception):
    pass


class DrgnRegister:
    def __init__(
        self, names: Union[str, Sequence[str]], *, identifier: Optional[str] = None
    ) -> None:
        """
        Register definition.

        :param names: Name or names of the register (i.e., name used for this
            register in assembly language or documentation).
        :param identifier: Register identifier matching
            :attr:`DrgnRegisterLayout.identifier`. Defaults to the first
            register name with non-alphanumeric characters replaced by "_" and
            prepended with "_" if the first character is numeric.
        """
        self.names = (names,) if isinstance(names, str) else names
        for name in self.names:
            if not name:
                raise ArchDefsError(f"invalid register name {name!r}")
        if identifier is None:
            identifier = re.sub(r"[^a-zA-Z0-9_]", "_", self.names[0])
            if not re.match(r"^[a-zA-Z_]", identifier):
                identifier = "_" + identifier
        self.identifier = identifier


class DrgnRegisterLayout:
    def __init__(
        self, identifier: str, *, size: int, dwarf_number: Optional[int]
    ) -> None:
        """
        Register layout definition.

        :param identifier: C identifier for the register to use in the
            generated file.
        :param size: Size used to store the register in bytes.
        :param dwarf_number: DWARF register number, or ``None`` if the register
            is not represented in DWARF.
        """
        self.identifier = identifier
        if not re.fullmatch(r"^[a-zA-Z_][a-zA-Z0-9_]*", identifier):
            raise ArchDefsError(f"invalid register identifier {identifier!r}")
        self.size = size
        if size <= 0:
            raise ArchDefsError(f"invalid register layout size {size}")
        self.dwarf_number = dwarf_number


def validate_register_defs(
    registers: Sequence[DrgnRegister],
    register_layout: Sequence[DrgnRegisterLayout],
    stack_pointer_register: str,
) -> None:
    layout_by_identifier = {}
    for layout in register_layout:
        if layout.identifier in layout_by_identifier:
            raise ArchDefsError(
                f"register identifier {layout.identifier!r} is duplicated in REGISTER_LAYOUT"
            )
        layout_by_identifier[layout.identifier] = layout

    names = set()
    register_identifiers = set()
    for register in registers:
        for name in register.names:
            if name in names:
                raise ArchDefsError(
                    f"register name {name!r} is duplicated in REGISTERS"
                )
            names.add(name)
        if register.identifier not in layout_by_identifier:
            raise ArchDefsError(
                f"register identifier {register.identifier} in REGISTERS is not in REGISTER_LAYOUT"
            )
        if register.identifier in register_identifiers:
            raise ArchDefsError(
                f"register identifier {register.identifier!r} is duplicated in REGISTERS"
            )
        register_identifiers.add(register.identifier)

    if stack_pointer_register not in layout_by_identifier:
        raise ArchDefsError(
            f"stack pointer register identifier {stack_pointer_register!r} is not in REGISTER_LAYOUT"
        )
    if layout_by_identifier[stack_pointer_register].size > 8:
        raise ArchDefsError(
            f"stack pointer register {stack_pointer_register!r} is too big"
        )


def gen_arch_inc_strswitch(
    registers: Sequence[DrgnRegister],
    register_layout: Sequence[DrgnRegisterLayout],
    stack_pointer_register: str,
    out_file: TextIO,
) -> None:
    validate_register_defs(registers, register_layout, stack_pointer_register)

    out_file.write("/* Generated by libdrgn/build-aux/gen_arch_inc_strswitch.py. */\n")

    out_file.write("\n")
    out_file.write("enum {\n")
    for layout in register_layout:
        out_file.write(f"\tDRGN_REGISTER_NUMBER__{layout.identifier},\n")
    out_file.write("};\n")

    out_file.write("\n")
    out_file.write("struct drgn_arch_register_layout {\n")
    for layout in register_layout:
        out_file.write(f"\tchar {layout.identifier}[{layout.size}];\n")
    out_file.write("};\n")

    out_file.write("\n")
    out_file.write("static const struct drgn_register_layout register_layout[] = {\n")
    for layout in register_layout:
        out_file.write(
            f"\t{{ offsetof(struct drgn_arch_register_layout, {layout.identifier}), {layout.size} }},\n"
        )
    out_file.write("};\n")

    out_file.write("\n")
    out_file.write(
        "static drgn_register_number dwarf_regno_to_internal(uint64_t dwarf_regno)\n"
    )
    out_file.write("{\n")
    out_file.write("\tswitch (dwarf_regno) {\n")
    for layout in register_layout:
        if layout.dwarf_number is not None:
            out_file.write(f"\tcase {layout.dwarf_number}:\n")
            out_file.write(f"\t\treturn DRGN_REGISTER_NUMBER__{layout.identifier};\n")
    out_file.write("\tdefault:\n")
    out_file.write("\t\treturn DRGN_REGISTER_NUMBER_UNKNOWN;\n")
    out_file.write("\t}\n")
    out_file.write("}\n")

    out_file.write("\n")
    out_file.write("static const struct drgn_register registers[] = {\n")
    for register in registers:
        out_file.write("\t{\n")
        out_file.write("\t\t.names = (const char * const []){\n")
        for name in register.names:
            out_file.write(f"\t\t\t{c_string_literal(name)},\n")
        out_file.write("\t\t},\n")
        out_file.write(f"\t\t.num_names = {len(register.names)},\n")
        out_file.write(f"\t\t.regno = DRGN_REGISTER_NUMBER__{register.identifier},\n")
        out_file.write("\t},\n")
    out_file.write("};\n")

    out_file.write("\n")
    out_file.write(
        "static const struct drgn_register *register_by_name(const char *name)\n"
    )
    out_file.write("{\n")
    out_file.write("\t@strswitch (name)@\n")
    for i, register in enumerate(registers):
        for name in register.names:
            out_file.write(f"\t@case {c_string_literal(name)}@\n")
            out_file.write(f"\t\treturn &registers[{i}];\n")
    out_file.write("\t@default@\n")
    out_file.write("\t\treturn NULL;\n")
    out_file.write("\t@endswitch@\n")
    out_file.write("}\n")

    out_file.write("\n")
    out_file.write("#define DRGN_ARCHITECTURE_REGISTERS \\\n")
    out_file.write("\t.register_layout = register_layout, \\\n")
    out_file.write("\t.dwarf_regno_to_internal = dwarf_regno_to_internal, \\\n")
    out_file.write("\t.registers = registers, \\\n")
    out_file.write(f"\t.num_registers = {len(registers)}, \\\n")
    out_file.write(
        f"\t.stack_pointer_regno = DRGN_REGISTER_NUMBER__{stack_pointer_register}, \\\n"
    )
    out_file.write("\t.register_by_name = register_by_name\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate arch_foo.inc.strswitch from arch_foo_defs.py"
    )
    parser.add_argument("input", metavar="FILE", help="input arch_foo_defs.py file")
    args = parser.parse_args()

    try:
        defs = runpy.run_path(
            args.input,
            init_globals={
                "DrgnRegister": DrgnRegister,
                "DrgnRegisterLayout": DrgnRegisterLayout,
            },
        )
        try:
            registers = defs["REGISTERS"]
            register_layout = defs["REGISTER_LAYOUT"]
            stack_pointer_register = defs["STACK_POINTER_REGISTER"]
        except KeyError as e:
            sys.exit(f"{e.args[0]} is not defined")
        gen_arch_inc_strswitch(
            registers, register_layout, stack_pointer_register, sys.stdout
        )
    except ArchDefsError as e:
        sys.exit(e)


if __name__ == "__main__":
    main()
