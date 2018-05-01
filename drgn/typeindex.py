# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import functools
from typing import FrozenSet, List, Optional, Tuple, Union

from drgn.dwarf import (
    Die,
    DwarfAttribNotFoundError,
    DwarfFormatError,
    DW_AT,
    DW_ATE,
    DW_TAG,
)
from drgn.dwarfindex import DwarfIndex
from drgn.type import (
    ArrayType,
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    FunctionType,
    IntType,
    PointerType,
    StructType,
    Type,
    TypedefType,
    UnionType,
    VoidType,
)
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    BasicTypeName,
    EnumTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
    VoidTypeName,
)


class TypeIndex:
    def _find_type(self, type_name: TypeName) -> Type:
        raise NotImplementedError()

    @functools.lru_cache()
    def find_type(self, type_name: Union[str, TypeName]) -> Type:
        if not isinstance(type_name, TypeName):
            type_name = parse_type_name(type_name)
        return self._find_type(type_name)


class DwarfTypeIndex(TypeIndex):
    def __init__(self, dwarf_index: DwarfIndex) -> None:
        super().__init__()
        self._dwarf_index = dwarf_index
        self._address_size = dwarf_index.address_size

    def _find_type(self, type_name: TypeName) -> Type:
        if isinstance(type_name, VoidTypeName):
            return VoidType(type_name.qualifiers)
        elif isinstance(type_name, PointerTypeName):
            return PointerType(self._address_size,
                               self.find_type(type_name.type),
                               type_name.qualifiers)
        elif isinstance(type_name, ArrayTypeName):
            return ArrayType(self.find_type(type_name.type), type_name.size)
        elif isinstance(type_name, BasicTypeName):
            tag = DW_TAG.base_type
        elif isinstance(type_name, StructTypeName):
            tag = DW_TAG.structure_type
        elif isinstance(type_name, UnionTypeName):
            tag = DW_TAG.union_type
        elif isinstance(type_name, EnumTypeName):
            tag = DW_TAG.enumeration_type
        elif isinstance(type_name, TypedefTypeName):
            tag = DW_TAG.typedef
        else:
            assert False
        dwarf_type = self._dwarf_index.find(type_name.name, tag)
        return self.find_dwarf_type(dwarf_type, type_name.qualifiers)

    @functools.lru_cache()
    def find_dwarf_type(self, dwarf_type: Die,
                        qualifiers: FrozenSet[str] = frozenset()) -> Type:
        extra_qualifiers = set()
        while True:
            if dwarf_type.tag == DW_TAG.const_type:
                extra_qualifiers.add('const')
            elif dwarf_type.tag == DW_TAG.restrict_type:
                extra_qualifiers.add('restrict')
            elif dwarf_type.tag == DW_TAG.volatile_type:
                extra_qualifiers.add('volatile')
            elif dwarf_type.tag == DW_TAG.atomic_type:
                extra_qualifiers.add('_Atomic')
            else:
                break
            dwarf_type = dwarf_type.type()
        if extra_qualifiers:
            qualifiers = qualifiers.union(extra_qualifiers)

        if dwarf_type.find_flag(DW_AT.declaration):
            try:
                dwarf_type = self._dwarf_index.find(dwarf_type.name(),
                                                    dwarf_type.tag)
            except (DwarfAttribNotFoundError, ValueError):
                pass

        if dwarf_type.tag == DW_TAG.base_type:
            encoding = dwarf_type.find_constant(DW_AT.encoding)
            name = str(parse_type_name(dwarf_type.name()))
            size = dwarf_type.size()
            if encoding == DW_ATE.boolean:
                return BoolType(name, size, qualifiers)
            elif encoding == DW_ATE.float:
                return FloatType(name, size, qualifiers)
            elif (encoding == DW_ATE.signed or
                  encoding == DW_ATE.signed_char):
                return IntType(name, size, True, qualifiers)
            elif (encoding == DW_ATE.unsigned or
                  encoding == DW_ATE.unsigned_char):
                return IntType(name, size, False, qualifiers)
            else:
                raise NotImplementedError(DW_ATE.str(encoding))
        elif (dwarf_type.tag == DW_TAG.structure_type or
              dwarf_type.tag == DW_TAG.union_type):
            if dwarf_type.find_flag(DW_AT.declaration):
                size = None
                members = None
            else:
                size = dwarf_type.size()
                members = []
                for child in dwarf_type.children():
                    if child.tag != DW_TAG.member:
                        continue
                    try:
                        name = child.name()
                    except DwarfAttribNotFoundError:
                        name = None
                    if dwarf_type.tag == DW_TAG.structure_type:
                        offset = child.find_constant(DW_AT.data_member_location)
                    else:
                        offset = 0
                    if child.has_attrib(DW_AT.bit_size):
                        type_thunk = functools.partial(self._from_dwarf_bit_field,
                                                       child)
                    else:
                        type_thunk = functools.partial(self.find_dwarf_type,
                                                       child.type())
                    members.append((name, offset, type_thunk))
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            if dwarf_type.tag == DW_TAG.structure_type:
                return StructType(name, size, members, qualifiers)  # type: ignore
                                                                    # mypy issue #1484
            else:
                return UnionType(name, size, members, qualifiers)  # type: ignore
                                                                   # mypy issue #1484
        elif dwarf_type.tag == DW_TAG.enumeration_type:
            if dwarf_type.find_flag(DW_AT.declaration):
                size = None
                signed = None
                compatible = None
                enumerators = None
            else:
                size = dwarf_type.size()
                encoding = dwarf_type.find_constant(DW_AT.encoding)
                if encoding == DW_ATE.signed:
                    signed = True
                elif encoding == DW_ATE.unsigned:
                    signed = False
                else:
                    raise NotImplementedError(DW_ATE.str(encoding))
                enumerators = []
                for child in dwarf_type.children():
                    if child.tag != DW_TAG.enumerator:
                        continue
                    name = child.name()
                    value = child.find_constant(DW_AT.const_value)
                    enumerators.append((name, value))
                compatible = str(parse_type_name(dwarf_type.type().name()))
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            return EnumType(name, size, signed, enumerators, compatible,
                            qualifiers)
        elif dwarf_type.tag == DW_TAG.typedef:
            return TypedefType(dwarf_type.name(),
                               self.find_dwarf_type(dwarf_type.type()),
                               qualifiers)
        elif dwarf_type.tag == DW_TAG.pointer_type:
            size = dwarf_type.size()
            try:
                deref_type = dwarf_type.type()
            except DwarfAttribNotFoundError:
                type_: Type = VoidType()
            else:
                type_ = self.find_dwarf_type(deref_type)
            return PointerType(size, type_, qualifiers)
        elif dwarf_type.tag == DW_TAG.array_type:
            type_ = self.find_dwarf_type(dwarf_type.type())
            for child in reversed(dwarf_type.children()):
                if child.tag == DW_TAG.subrange_type:
                    try:
                        size = child.find_constant(DW_AT.upper_bound) + 1
                    except DwarfAttribNotFoundError:
                        size = None
                    type_ = ArrayType(type_, size)
            assert isinstance(type_, ArrayType)
            return type_
        elif dwarf_type.tag == DW_TAG.subroutine_type:
            try:
                return_type = self.find_dwarf_type(dwarf_type.type())
            except DwarfAttribNotFoundError:
                return_type = VoidType()
            parameters: Optional[List[Tuple[Type, Optional[str]]]] = []
            variadic = False
            for child in dwarf_type.children():
                if child.tag == DW_TAG.formal_parameter:
                    if parameters is None or variadic:
                        raise DwarfFormatError('formal parameter after unspecified parameters')
                    parameter_type = self.find_dwarf_type(child.type())
                    try:
                        parameter_name = child.name()
                    except DwarfAttribNotFoundError:
                        parameter_name = None
                    parameters.append((parameter_type, parameter_name))
                elif child.tag == DW_TAG.unspecified_parameters:
                    if parameters:
                        variadic = True
                    else:
                        parameters = None
            return FunctionType(return_type, parameters, variadic)
        else:
            raise NotImplementedError(DW_TAG.str(dwarf_type.tag))

    def _from_dwarf_bit_field(self, die: Die) -> Type:
        type_ = self.find_dwarf_type(die.type())
        while isinstance(type_, TypedefType):
            type_ = type_.type
        if not isinstance(type_, IntType):
            raise DwarfFormatError('bit field type is not integer')
        bit_size = die.find_constant(DW_AT.bit_size)
        try:
            bit_offset = die.find_constant(DW_AT.data_bit_offset)
        except DwarfAttribNotFoundError:
            bit_offset = (8 * type_.sizeof() - bit_size -
                          die.find_constant(DW_AT.bit_offset))
        return BitFieldType(type_, bit_offset, bit_size)
