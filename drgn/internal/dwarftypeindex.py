# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Index of types using DWARF debugging information"""

import functools
import itertools
from typing import Dict, Iterable, List, Optional, Tuple

from drgn.internal.dwarf import (
    Die,
    DwarfAttribNotFoundError,
    DwarfFormatError,
    DW_AT,
    DW_ATE,
    DW_TAG,
)
from drgn.internal.dwarfindex import DwarfIndex
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
from drgn.typeindex import TypeIndex
from drgn.typename import (
    parse_type_name,
    BasicTypeName,
    EnumTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
)


# Mapping from canonical base type name to all possible ways to specify the
# same type.
_BASE_TYPES = {}
for specifiers in [
    ['_Bool'],
    ['char'],
    ['signed', 'char'],
    ['unsigned', 'char'],
    ['short', 'int'],
    ['short', 'unsigned', 'int'],
    ['int'],
    ['unsigned', 'int'],
    ['long', 'int'],
    ['long', 'unsigned', 'int'],
    ['long long', 'int'],
    ['long long', 'unsigned', 'int'],
    ['float'],
    ['double'],
    ['long', 'double'],
]:
    spellings = []
    for permutation in itertools.permutations(specifiers):
        spellings.append(' '.join(permutation))
    if len(specifiers) > 1 and specifiers[-1] == 'int':
        for permutation in itertools.permutations(specifiers[:-1]):
            spellings.append(' '.join(permutation))
    _BASE_TYPES[str(parse_type_name(' '.join(specifiers)))] = spellings
del permutation, specifiers, spellings


class DwarfTypeIndex(TypeIndex):
    """
    This class is an implementation of TypeIndex using DWARF debugging
    information.
    """

    def __init__(self, dwarf_index: DwarfIndex) -> None:
        super().__init__(dwarf_index.address_size)
        self._dwarf_index = dwarf_index
        self._base_types: Dict[str, Die] = {}
        for type_name, spellings in _BASE_TYPES.items():
            for spelling in spellings:
                try:
                    self._base_types[type_name] = self._dwarf_index.find(spelling,
                                                                         DW_TAG.base_type)[0]
                    break
                except ValueError:
                    pass

    def _find_type(self, type_name: TypeName, filename: Optional[str]) -> Type:
        dwarf_type = None
        if isinstance(type_name, BasicTypeName):
            tag = DW_TAG.base_type
            try:
                dwarf_type = self._base_types[type_name.name]
            except KeyError:
                pass
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
        if type_name.name is None:
            raise ValueError("can't find anonymous type")
        if dwarf_type is None:
            try:
                dies = self._dwarf_index.find(type_name.name, tag)
            except ValueError:
                raise ValueError(f'could not find {str(type_name)!r}') from None
            for dwarf_type in dies:
                try:
                    if filename is None or dwarf_type.decl_file() == filename:
                        break
                except DwarfAttribNotFoundError:
                    continue
            else:
                raise ValueError(f'could not find {str(type_name)!r} in {filename!r}')
        return self._from_dwarf_type(dwarf_type, type_name.qualifiers)

    @functools.lru_cache()
    def _from_dwarf_type(self, dwarf_type: Die,
                         qualifiers: Iterable[str] = frozenset()) -> Type:
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
            try:
                dwarf_type = dwarf_type.type()
            except DwarfAttribNotFoundError:
                extra_qualifiers.update(qualifiers)
                return VoidType(extra_qualifiers)
        if extra_qualifiers:
            extra_qualifiers.update(qualifiers)
            qualifiers = extra_qualifiers

        if dwarf_type.find_flag(DW_AT.declaration):
            try:
                dwarf_type = self._dwarf_index.find(dwarf_type.name(),
                                                    dwarf_type.tag)[0]
            except (DwarfAttribNotFoundError, ValueError):
                pass

        name: Optional[str]
        size: Optional[int]
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
                        type_thunk = functools.partial(self._from_dwarf_type,
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
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            if dwarf_type.find_flag(DW_AT.declaration):
                return EnumType(name, None, None, qualifiers)
            else:
                size = dwarf_type.size()
                signed_max = 2**(size - 1) - 1
                signed = True
                enumerators = []
                for child in dwarf_type.children():
                    if child.tag != DW_TAG.enumerator:
                        continue
                    enumerator_name = child.name()
                    enumerator_value = child.find_constant(DW_AT.const_value)
                    if enumerator_value > signed_max:
                        signed = False
                    enumerators.append((enumerator_name, enumerator_value))
                int_type: Type
                try:
                    type_die = dwarf_type.type()
                except DwarfAttribNotFoundError:
                    # GCC before 5.1 did not include DW_AT_type for
                    # DW_TAG_enumeration_type DIEs, so we have to fabricate
                    # one.
                    int_type = IntType('', size, signed)
                else:
                    int_type = self._from_dwarf_type(type_die)
                    if not isinstance(int_type, IntType):
                        raise DwarfFormatError('enum compatible type is not an integer type')
                return EnumType(name, int_type, enumerators, qualifiers)
        elif dwarf_type.tag == DW_TAG.typedef:
            return TypedefType(dwarf_type.name(),
                               self._from_dwarf_type(dwarf_type.type()),
                               qualifiers)
        elif dwarf_type.tag == DW_TAG.pointer_type:
            size = dwarf_type.size()
            try:
                deref_type = dwarf_type.type()
            except DwarfAttribNotFoundError:
                type_: Type = VoidType()
            else:
                type_ = self._from_dwarf_type(deref_type)
            return PointerType(size, type_, qualifiers)
        elif dwarf_type.tag == DW_TAG.array_type:
            type_ = self._from_dwarf_type(dwarf_type.type())
            for child in reversed(dwarf_type.children()):
                if child.tag == DW_TAG.subrange_type:
                    try:
                        size = child.find_constant(DW_AT.upper_bound) + 1
                    except DwarfAttribNotFoundError:
                        size = None
                    type_ = ArrayType(type_, size, self._address_size)
            if not isinstance(type_, ArrayType):
                raise DwarfFormatError('array type does not have any subranges')
            return type_
        elif dwarf_type.tag == DW_TAG.subroutine_type:
            try:
                return_type = self._from_dwarf_type(dwarf_type.type())
            except DwarfAttribNotFoundError:
                return_type = VoidType()
            parameters: Optional[List[Tuple[Type, Optional[str]]]] = []
            variadic = False
            for child in dwarf_type.children():
                if child.tag == DW_TAG.formal_parameter:
                    if parameters is None or variadic:
                        raise DwarfFormatError('formal parameter after unspecified parameters')
                    parameter_type = self._from_dwarf_type(child.type())
                    try:
                        parameter_name: Optional[str] = child.name()
                    except DwarfAttribNotFoundError:
                        parameter_name = None
                    parameters.append((parameter_type, parameter_name))
                elif child.tag == DW_TAG.unspecified_parameters:
                    if parameters:
                        variadic = True
                    else:
                        parameters = None
            return FunctionType(self._address_size, return_type, parameters,
                                variadic)
        else:
            raise NotImplementedError(DW_TAG.str(dwarf_type.tag))

    def _from_dwarf_bit_field(self, die: Die) -> Type:
        type_ = self._from_dwarf_type(die.type())
        bit_size = die.find_constant(DW_AT.bit_size)
        try:
            bit_offset = die.find_constant(DW_AT.data_bit_offset)
        except DwarfAttribNotFoundError:
            bit_offset = (8 * type_.sizeof() - bit_size -
                          die.find_constant(DW_AT.bit_offset))
        return BitFieldType(type_, bit_offset, bit_size)
