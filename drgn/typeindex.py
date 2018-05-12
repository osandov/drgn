# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import functools
import itertools
import numbers
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Union, overload

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


_IntegerOperandType = Union[IntType, BitFieldType, EnumType, TypedefType]
_RealOperandType = Union[ArithmeticType, BitFieldType, EnumType, TypedefType]


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


def _integer_conversion_rank(type_: Union[IntType, BitFieldType]) -> int:
    if isinstance(type_, BitFieldType):
        return _integer_conversion_rank(type_.type)
    else:
        name = type_.name
    return _INTEGER_CONVERSION_RANKS[name]


def _can_represent_all_values(type1: Union[IntType, BitFieldType],
                              type2: Union[IntType, BitFieldType]) -> bool:
    # Return whether type1 can represent all values of type2.

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


@overload
def _corresponding_unsigned_type(type_: IntType) -> IntType: ...
@overload
def _corresponding_unsigned_type(type_: BitFieldType) -> BitFieldType: ...
def _corresponding_unsigned_type(type_: Union[IntType, BitFieldType]) -> Union[IntType, BitFieldType]:
    if isinstance(type_, BitFieldType):
        if type_.type.signed:
            underlying_type = _corresponding_unsigned_type(type_.type)
            return BitFieldType(underlying_type, None, type_.bit_size)
        else:
            return type_
    elif isinstance(type_, BoolType):
        return type_
    else:
        if type_.signed:
            return IntType('unsigned ' + type_.name, type_.size, False)
        else:
            return type_


class TypeIndex:
    def __init__(self, address_size: int) -> None:
        self._address_size = address_size

    def _find_type(self, type_name: TypeName) -> Type:
        raise NotImplementedError()

    @functools.lru_cache()
    def find_type(self, type_name: Union[str, TypeName]) -> Type:
        if not isinstance(type_name, TypeName):
            type_name = parse_type_name(type_name)
        if isinstance(type_name, VoidTypeName):
            return VoidType(type_name.qualifiers)
        elif isinstance(type_name, PointerTypeName):
            return self.pointer(self.find_type(type_name.type),
                                type_name.qualifiers)
        elif isinstance(type_name, ArrayTypeName):
            return self.array(self.find_type(type_name.type), type_name.size)
        else:
            return self._find_type(type_name)

    def array(self, type_: Type, size: Optional[int]) -> ArrayType:
        return ArrayType(type_, size)

    def pointer(self, type_: Type,
                qualifiers: FrozenSet[str] = frozenset()) -> PointerType:
        return PointerType(self._address_size, type_, qualifiers)

    def ptrdiff_t(self) -> Type:
        try:
            return self.find_type('ptrdiff_t')
        except ValueError:
            pass
        return self.find_type('long')

    @overload
    def operand_type(self, type_: VoidType) -> VoidType: ...
    @overload
    def operand_type(self, type_: BoolType) -> BoolType: ...
    @overload
    def operand_type(self, type_: IntType) -> IntType: ...
    @overload
    def operand_type(self, type_: FloatType) -> FloatType: ...
    @overload
    def operand_type(self, type_: BitFieldType) -> BitFieldType: ...
    @overload
    def operand_type(self, type_: EnumType) -> EnumType: ...
    @overload
    def operand_type(self, type_: StructType) -> StructType: ...
    @overload
    def operand_type(self, type_: UnionType) -> UnionType: ...
    @overload
    def operand_type(self, type_: Union[PointerType, ArrayType, FunctionType]) -> PointerType:
        ...
    @overload
    def operand_type(self, type_: Type) -> Type: ...
    def operand_type(self, type_: Type) -> Type:
        if isinstance(type_, VoidType):
            if type_.qualifiers:
                return VoidType()
        elif isinstance(type_, BoolType):
            if type_.qualifiers:
                return BoolType(type_.name, type_.size)
        elif isinstance(type_, IntType):
            if type_.qualifiers:
                return IntType(type_.name, type_.size, type_.signed)
        elif isinstance(type_, FloatType):
            if type_.qualifiers:
                return FloatType(type_.name, type_.size)
        elif isinstance(type_, BitFieldType):
            if type_.type.qualifiers:
                int_type = self.operand_type(type_.type)
                return BitFieldType(int_type, type_.bit_offset, type_.bit_size)
        elif isinstance(type_, EnumType):
            if type_.qualifiers:
                return EnumType(type_.name, type_.type,
                                None if type_.enum is None else type_.enum.__members__)
        elif isinstance(type_, StructType):
            if type_.qualifiers:
                return StructType(type_.name, type_.size, type_._members)
        elif isinstance(type_, UnionType):
            if type_.qualifiers:
                return UnionType(type_.name, type_.size, type_._members)
        elif isinstance(type_, TypedefType):
            type2 = type_.type
            while isinstance(type2, TypedefType):
                if type2.qualifiers:
                    return self.operand_type(type2.real_type())
                type2 = type2.type
            if isinstance(type2, (ArrayType, FunctionType)) or type2.qualifiers:
                return self.operand_type(type2)
            if type_.qualifiers:
                return TypedefType(type_.name, type_.type)
        elif isinstance(type_, PointerType):
            if type_.qualifiers:
                return PointerType(type_.size, type_.type)
        elif isinstance(type_, ArrayType):
            return self.pointer(type_.type)
        elif isinstance(type_, FunctionType):
            return self.pointer(type_)
        else:
            assert False
        return type_

    def literal_type(self, value: Any) -> Any:
        if isinstance(value, bool):
            return self.find_type('_Bool')
        elif isinstance(value, numbers.Integral):
            value = int(value)
            for type_name in ['int', 'long', 'long long']:
                type_ = self.find_type(type_name)
                assert isinstance(type_, IntType)
                if -(1 << (8 * type_.size - 1)) <= value < (1 << (8 * type_.size - 1)):
                    return type_
                elif 0 <= value < (1 << 8 * type_.size):
                    return _corresponding_unsigned_type(type_)
            raise TypeError('integer is too large')
        elif isinstance(value, numbers.Real):
            return self.find_type('double')
        else:
            raise TypeError()

    def integer_promotions(self, type_: _IntegerOperandType) -> _IntegerOperandType:
        # Integer promotions are performed on types whose integer conversion
        # rank is less than or equal to the rank of int and unsigned int and
        # bit-fields. GCC and Clang always convert enums to their compatible
        # type.

        real_type = type_.real_type()

        if not isinstance(real_type, (IntType, BitFieldType, EnumType)):
            raise ValueError('cannot promote non-integer type')

        if isinstance(real_type, BitFieldType):
            int_type = self.find_type('int')
            assert isinstance(int_type, IntType)
            if _can_represent_all_values(int_type, real_type):
                return int_type

            unsigned_int_type = self.find_type('unsigned int')
            assert isinstance(unsigned_int_type, IntType)
            if _can_represent_all_values(unsigned_int_type, real_type):
                return unsigned_int_type

            # GCC does not promote a bit-field to its full type, but Clang
            # does. The GCC behavior seems more correct in terms of the
            # standard.
            return BitFieldType(real_type.type, None, real_type.bit_size)

        if isinstance(real_type, EnumType):
            if real_type.type is None:
                raise ValueError('operand cannot have incomplete enum type')
            type_ = real_type = real_type.type

        if (real_type.name == 'int' or real_type.name == 'unsigned int' or
                _integer_conversion_rank(real_type) > _INT_CONVERSION_RANK):
            return type_

        int_type = self.find_type('int')
        assert isinstance(int_type, IntType)
        if _can_represent_all_values(int_type, real_type):
            # If int can represent all values of the original type, then the
            # result is int.
            return int_type

        # Otherwise, the result is unsigned int.
        unsigned_int_type = self.find_type('unsigned int')
        assert isinstance(unsigned_int_type, IntType)
        return unsigned_int_type

    def common_real_type(self, type1: _RealOperandType,
                         type2: _RealOperandType) -> _RealOperandType:
        real_type1 = type1.real_type()
        real_type2 = type2.real_type()

        float1 = real_type1.name if isinstance(real_type1, FloatType) else None
        float2 = real_type2.name if isinstance(real_type2, FloatType) else None
        if float1 is not None or float2 is not None:
            # If either operand is long double, then the result is long double.
            if float1 == 'long double':
                return type1
            if float2 == 'long double':
                return type2
            # If either operand is double, then the result is double.
            if float1 == 'double':
                return type1
            if float2 == 'double':
                return type2
            # Otherwise, if either operand is float, then the result is float.
            if float1 == 'float':
                return type1
            if float2 == 'float':
                return type2
            raise ValueError('unknown floating-point types')

        assert isinstance(type1, (IntType, BitFieldType, EnumType, TypedefType))
        assert isinstance(type2, (IntType, BitFieldType, EnumType, TypedefType))

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

        assert isinstance(real_type1, (IntType, BitFieldType))
        assert isinstance(real_type2, (IntType, BitFieldType))

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


class DwarfTypeIndex(TypeIndex):
    def __init__(self, dwarf_index: DwarfIndex) -> None:
        super().__init__(dwarf_index.address_size)
        self._dwarf_index = dwarf_index
        self._base_types: Dict[str, Die] = {}
        for type_name, spellings in _BASE_TYPES.items():
            for spelling in spellings:
                try:
                    self._base_types[type_name] = self._dwarf_index.find(spelling, DW_TAG.base_type)
                    break
                except ValueError:
                    pass

    def _find_type(self, type_name: TypeName) -> Type:
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
        if dwarf_type is None:
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
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            if dwarf_type.find_flag(DW_AT.declaration):
                return EnumType(name, None, None, qualifiers)
            else:
                int_type = self.find_dwarf_type(dwarf_type.type())
                if not isinstance(int_type, IntType):
                    raise DwarfFormatError('enum compatible type is not an integer type')
                enumerators = []
                for child in dwarf_type.children():
                    if child.tag != DW_TAG.enumerator:
                        continue
                    enumerator_name = child.name()
                    enumerator_value = child.find_constant(DW_AT.const_value)
                    enumerators.append((enumerator_name, enumerator_value))
                return EnumType(name, int_type, enumerators, qualifiers)
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
            if not isinstance(type_, ArrayType):
                raise DwarfFormatError('array type does not have any subranges')
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
                        parameter_name: Optional[str] = child.name()
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
