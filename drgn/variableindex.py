# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

from typing import cast, Any, Optional, Tuple

from drgn.dwarf import Die, DW_TAG, DwarfAttribNotFoundError
from drgn.type import Type, EnumType
from drgn.typeindex import DwarfTypeIndex, TypeIndex


class VariableIndex:
    def __init__(self, type_index: TypeIndex) -> None:
        self._type_index = type_index

    def find(self, name: str,
             filename: Optional[str] = None) -> Tuple[Type, Any, Optional[int]]:
        raise NotImplementedError()


class DwarfVariableIndex(VariableIndex):
    def __init__(self, type_index: DwarfTypeIndex) -> None:
        super().__init__(type_index)
        self._type_index: DwarfTypeIndex
        self._dwarf_index = type_index._dwarf_index

    def _find_die(self, name: str,
                  filename: Optional[str] = None) -> Die:
        for tag in [DW_TAG.variable, DW_TAG.enumerator]:
            try:
                dies = self._dwarf_index.find(name, tag)
            except ValueError:
                continue
            for die in dies:
                try:
                    if filename is None or die.decl_file() == filename:
                        return die
                except DwarfAttribNotFoundError:
                    continue
        if filename is None:
            raise ValueError(f'could not find {name!r}')
        else:
            raise ValueError(f'could not find {name!r} in {filename!r}')

    def _find_variable_address(self, name: str, die: Die) -> int:
        raise NotImplementedError()

    def find(self, name: str,
             filename: Optional[str] = None) -> Tuple[Type, Any, Optional[int]]:
        die = self._find_die(name, filename)
        if die.tag == DW_TAG.variable:
            address = self._find_variable_address(name, die)
            try:
                dwarf_type = die.type()
            except DwarfAttribNotFoundError:
                dwarf_type = die.specification().type()
            return self._type_index.find_dwarf_type(dwarf_type), None, address
        else:  # die.tag == DW_TAG.enumeration_type
            type_ = cast(EnumType, self._type_index.find_dwarf_type(die))
            return type_, getattr(type_.enum, name), None
