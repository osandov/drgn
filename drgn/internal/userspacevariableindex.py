# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Index of variables for userspace programs"""

from typing import List

from drgn.internal.dwarf import Die
from drgn.internal.dwarfvariableindex import DwarfVariableIndex
from drgn.internal.dwarftypeindex import DwarfTypeIndex
from drgn.internal.elf import PT_LOAD
from drgn.internal.util import FileMapping


class UserspaceVariableIndex(DwarfVariableIndex):
    """
    This class is an implementation of VariableIndex for userspace programs. It
    supports ASLR and shared libraries.
    """

    def __init__(self, type_index: DwarfTypeIndex,
                 file_mappings: List[FileMapping]) -> None:
        super().__init__(type_index)
        self._file_mappings = file_mappings

    def _find_variable_address(self, name: str, die: Die) -> int:
        address = die.location()
        dwarf_file = die.cu.dwarf_file
        path = dwarf_file.path
        elf_file = dwarf_file.elf_file

        for phdr in elf_file.phdrs:
            if phdr.p_type != PT_LOAD:
                continue
            if phdr.p_vaddr <= address < phdr.p_vaddr + phdr.p_memsz:
                break
        else:
            raise ValueError(f'Could not find segment containing {name}')
        file_offset = phdr.p_offset + address - phdr.p_vaddr

        for mapping in self._file_mappings:
            mapping_size = mapping.end - mapping.start
            if (mapping.path == path and
                    mapping.file_offset <= file_offset <
                    mapping.file_offset + mapping_size):
                return mapping.start + file_offset - mapping.file_offset
        else:
            raise ValueError(f'Could not find file mapping containing {name}')
