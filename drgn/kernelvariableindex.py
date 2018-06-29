# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import os.path
from typing import Optional, Tuple

from drgn.dwarf import DW_TAG, DwarfAttribNotFoundError
from drgn.helpers.kernel import list_for_each_entry
from drgn.type import Type
from drgn.typeindex import DwarfTypeIndex
from drgn.program import Program
from drgn.variableindex import VariableIndex


# This would ideally just go in variableindex.py, but then we end up with
# circular imports between program.py and variableindex.py.

class KernelVariableIndex(VariableIndex):
    def __init__(self, type_index: DwarfTypeIndex, kaslr_offset: int = 0) -> None:
        super().__init__(type_index)
        self._type_index: DwarfTypeIndex
        self._dwarf_index = type_index._dwarf_index
        self._kaslr_offset = kaslr_offset

    # This isn't pretty, but we need the program in order to apply relocations
    # to kernel modules.
    def set_program(self, program: Program) -> None:
        self._prog = program

    def find(self, name: str,
             filename: Optional[str] = None) -> Tuple[int, Type]:
        try:
            dies = self._dwarf_index.find(name, DW_TAG.variable)
        except ValueError:
            raise ValueError(f'could not find {name!r}') from None
        for variable in dies:
            try:
                if filename is None or variable.decl_file() == filename:
                    break
            except DwarfAttribNotFoundError:
                continue
        else:
            raise ValueError(f'could not find {name!r} in {filename!r}')
        address = variable.location()
        elf_file = variable.cu.dwarf_file.elf_file
        file_name = os.path.basename(elf_file.path).split('.', 1)[0]
        if file_name == 'vmlinux':
            address += self._kaslr_offset
        else:
            module_name = file_name.replace('-', '_').encode('ascii')
            for mod in list_for_each_entry('struct module',
                                           self._prog['modules'].address_of_(),
                                           'list'):
                if mod.name.string_() == module_name:
                    break
            else:
                raise ValueError(f'{module_name.decode()} is not loaded')
            for sym in elf_file.symbols[name]:
                if sym.st_value == address:
                    break
            else:
                raise ValueError(f'Could not find {name} symbol')
            section_name = elf_file.shdrs[sym.st_shndx].name.encode()
            mod_sects = mod.sect_attrs.attrs
            for i in range(mod.sect_attrs.nsections):
                attr = mod.sect_attrs.attrs[i]
                if attr.name.string_() == section_name:
                    address += attr.address.value_()
                    break
            else:
                raise ValueError(f'Could not find module section {section_name.decode()}')
        try:
            dwarf_type = variable.type()
        except DwarfAttribNotFoundError:
            dwarf_type = variable.specification().type()
        return address, self._type_index.find_dwarf_type(dwarf_type)
