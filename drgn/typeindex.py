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
    ArithmeticType,
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


_INTEGER_CONVERSION_RANKS = {
    '_Bool': 0,
    'char': 1,
    'signed char': 1,
    'unsigned char': 1,
    'short': 2,
    'unsigned short': 2,
    'int': 3,
    'unsigned int': 3,
    'long': 4,
    'unsigned long': 4,
    'long long': 5,
    'unsigned long long': 5,
}

_INT_CONVERSION_RANK = _INTEGER_CONVERSION_RANKS['int']


def _integer_conversion_rank(type: Union[IntType, BitFieldType]) -> int:
    if isinstance(type, BitFieldType):
        return _integer_conversion_rank(type.type)
    else:
        name = type.name
    return _INTEGER_CONVERSION_RANKS[name]


def _can_represent_all_values(type1: Type, type2: Type) -> bool:
    # Return whether type1 can represent all values of type2.

    if (not isinstance(type1, (IntType, BitFieldType)) or
            not isinstance(type2, (IntType, BitFieldType))):
        raise TypeError()

    if isinstance(type1, BitFieldType):
        width1 = type1.bit_size
        signed1 = type1.type.signed
    else:
        width1 = 8 * type1.size
        signed1 = type1.signed

    if isinstance(type2, BitFieldType):
        width2 = type2.bit_size
        signed2 = type2.type.signed
    else:
        width2 = 8 * type2.size
        signed2 = type2.signed

    if signed1 == signed2:
        return width1 >= width2
    elif signed1 and not signed2:
        return width1 > width2
    else:  # not signed1 and signed2
        return False


def _corresponding_unsigned_type(type_: Type) -> Type:
    if isinstance(type_, BitFieldType):
        if type_.type.signed:
            underlying_type = _corresponding_unsigned_type(type_.type)
            assert isinstance(underlying_type, IntType)
            return BitFieldType(underlying_type, None, type_.bit_size)
        else:
            return type_
    elif isinstance(type_, BoolType):
        return type_
    elif isinstance(type_, EnumType):
        if type_.signed:
            return IntType('unsigned ' + type_.compatible_name, type_.size,
                           False)
        else:
            return type_
    elif isinstance(type_, IntType):
        if type_.signed:
            return IntType('unsigned ' + type_.name, type_.size, False)
        else:
            return type_
    else:
        raise TypeError()


class TypeIndex:
    def _find_type(self, type_name: TypeName) -> Type:
        raise NotImplementedError()

    @functools.lru_cache()
    def find_type(self, type_name: Union[str, TypeName]) -> Type:
        if not isinstance(type_name, TypeName):
            type_name = parse_type_name(type_name)
        return self._find_type(type_name)

    def integer_promotions(self, type: Type) -> Type:
        # Integer promotions are performed on types whose integer conversion
        # rank is less than or equal to the rank of int and unsigned int and
        # bit-fields.

        real_type = type.real_type()

        if isinstance(real_type, EnumType):
            type = real_type = IntType(real_type.compatible_name,
                                       real_type.size, real_type.signed)

        if isinstance(real_type, BitFieldType):
            int_type = self.find_type('int')
            unsigned_int_type = self.find_type('unsigned int')
            if _can_represent_all_values(int_type, real_type):
                return int_type
            elif _can_represent_all_values(unsigned_int_type, real_type):
                return unsigned_int_type
            else:
                # GCC does not promote a bit-field to its full type, but Clang
                # does. The GCC behavior seems more correct in terms of the
                # standard.
                return BitFieldType(real_type.type, None, real_type.bit_size)

        if (not isinstance(real_type, IntType) or
                real_type.name == 'int' or real_type.name == 'unsigned int' or
                _integer_conversion_rank(real_type) > _INT_CONVERSION_RANK):
            return type

        int_type = self.find_type('int')
        if _can_represent_all_values(int_type, real_type):
            # If int can represent all values of the original type, then the
            # result is int.
            return int_type
        else:
            # Otherwise, the result is unsigned int.
            return self.find_type('unsigned int')

    def usual_arithmetic_conversions(self, type1: Type, type2: Type) -> Type:
        type1 = type1.unqualified()
        type2 = type2.unqualified()
        real_type1 = type1.real_type()
        real_type2 = type2.real_type()

        if (not isinstance(real_type1, (ArithmeticType, BitFieldType)) or
                not isinstance(real_type2, (ArithmeticType, BitFieldType))):
            raise TypeError('operands must be arithmetic types or bit fields')

        # If either operand is long double, then the result is long double.
        if isinstance(real_type1, FloatType) and real_type1.name == 'long double':
            return type1
        if isinstance(real_type2, FloatType) and real_type2.name == 'long double':
            return type2
        # If either operand is double, then the result is double.
        if isinstance(real_type1, FloatType) and real_type1.name == 'double':
            return type1
        if isinstance(real_type2, FloatType) and real_type2.name == 'double':
            return type2
        # Otherwise, if either operand is float, then the result is float.
        if isinstance(real_type1, FloatType) and real_type1.name == 'float':
            return type1
        if isinstance(real_type2, FloatType) and real_type2.name == 'float':
            return type2

        # Otherwise, the integer promotions are performed before applying the
        # following rules.
        type1 = self.integer_promotions(type1)
        type2 = self.integer_promotions(type2)
        real_type1 = type1.real_type()
        real_type2 = type2.real_type()

        assert isinstance(real_type1, (IntType, BitFieldType))
        assert isinstance(real_type2, (IntType, BitFieldType))

        # If both operands have the same type, then no further conversions are
        # needed.
        if (isinstance(real_type1, IntType) and isinstance(real_type2, IntType) and
                real_type1.name == real_type2.name):
            # We can return either type1 or type2 here; it only makes a
            # difference for typedefs. Arbitrarily pick type2 because that's
            # what GCC seems to do (Clang always just throws away the typedef).
            return type2

        rank1 = _integer_conversion_rank(real_type1)
        rank2 = _integer_conversion_rank(real_type2)
        signed1 = real_type1.type.signed if isinstance(real_type1, BitFieldType) else real_type1.signed
        signed2 = real_type2.type.signed if isinstance(real_type2, BitFieldType) else real_type2.signed

        if (isinstance(real_type1, BitFieldType) or
                isinstance(real_type2, BitFieldType)):
            if isinstance(real_type1, BitFieldType):
                width1 = real_type1.bit_size
            else:
                width1 = 8 * real_type1.size

            if isinstance(real_type2, BitFieldType):
                width2 = real_type2.bit_size
            else:
                width2 = 8 * real_type2.size

            if width1 > width2:
                return type1
            elif width2 > width1:
                return type2

        # Otherwise, if both operands have signed integer types or both have
        # unsigned integer types, then the result is the type of the operand
        # with the greater rank.
        if signed1 == signed2:
            if rank1 > rank2:
                return type1
            else:
                return type2

        # Otherwise, if the operand that has unsigned integer type has rank greater
        # or equal to the rank of the type of the other operand, then the result is
        # the unsigned integer type.
        if not signed1 and rank1 >= rank2:
            return type1
        if not signed2 and rank2 >= rank1:
            return type2

        # Otherwise, if the type of the operand with signed integer type can
        # represent all of the values of the type of the operand with unsigned
        # integer type, then the result is the signed integer type.
        if signed1 and _can_represent_all_values(real_type1, real_type2):
            return type1
        if signed2 and _can_represent_all_values(real_type2, real_type1):
            return type2

        # Otherwise, then the result is is the unsigned integer type corresponding
        # to the type of the operand with signed integer type.
        if signed1:
            return _corresponding_unsigned_type(real_type1)
        else:  # signed2
            return _corresponding_unsigned_type(real_type2)


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
                compatible_name = None
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
                compatible_name = str(parse_type_name(dwarf_type.type().name()))
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            return EnumType(name, size, signed, enumerators, compatible_name,
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
