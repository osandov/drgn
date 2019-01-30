# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Index of variables for the Linux kernel"""

import os.path

from drgn.helpers.kernel import list_for_each_entry
from drgn.internal.dwarf import Die, DwarfAttribNotFoundError
from drgn.internal.dwarftypeindex import DwarfTypeIndex
from drgn.internal.dwarfvariableindex import DwarfVariableIndex
from drgn.internal.elf import ET_EXEC
from drgn.internal.program import Program
from drgn.type import Type


class KernelVariableIndex(DwarfVariableIndex):
    """
    This class is an implementation of VariableIndex for the Linux kernel. It
    supports KASLR and kernel modules.
    """

    def __init__(self, type_index: DwarfTypeIndex, kaslr_offset: int = 0) -> None:
        super().__init__(type_index)
        self._kaslr_offset = kaslr_offset

    # This isn't pretty, but we need the program in order to apply relocations
    # to kernel modules.
    def set_program(self, program: Program) -> None:
        self._prog = program

    def _find_variable_address(self, name: str, die: Die) -> int:
        address = die.location()
        dwarf_file = die.cu.dwarf_file
        elf_file = dwarf_file.elf_file

        # vmlinux is an executable file, kernel modules are relocatable
        # files.
        if elf_file.ehdr.e_type == ET_EXEC:
            return address + self._kaslr_offset

        file_name = os.path.basename(dwarf_file.path).split('.', 1)[0]
        module_name = file_name.replace('-', '_').encode('ascii')
        for mod in list_for_each_entry('struct module',
                                       self._prog['modules'].address_of_(),
                                       'list'):
            if mod.name.string_() == module_name:
                break
        else:
            raise KeyError(f'{module_name.decode()} is not loaded')
        for sym in elf_file.symbols[name]:
            if sym.st_value == address:
                break
        else:
            raise KeyError(f'Could not find {name} symbol')
        section_name = elf_file.shdrs[sym.st_shndx].name.encode()
        mod_sects = mod.sect_attrs.attrs
        for i in range(mod.sect_attrs.nsections):
            attr = mod.sect_attrs.attrs[i]
            if attr.name.string_() == section_name:
                return address + attr.address.value_()
        else:
            raise KeyError(f'Could not find module section {section_name.decode()}')
