# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Index of types in a program"""

import functools
import numbers
from typing import (
    Any,
    Iterable,
    Optional,
    Union,
    cast,
    overload,
)

from drgn.type import (
    ArithmeticType,
    ArrayType,
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    IntType,
    PointerType,
    Type,
    TypedefType,
    VoidType,
)
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    PointerTypeName,
    TypeName,
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


def _integer_conversion_rank(type_: Union[IntType, BitFieldType]) -> int:
    if isinstance(type_, BitFieldType):
        return _integer_conversion_rank(type_._int_type)
    else:
        name = type_.name
    return _INTEGER_CONVERSION_RANKS[name]


def _can_represent_all_values(type1: Union[IntType, BitFieldType],
                              type2: Union[IntType, BitFieldType]) -> bool:
    # Return whether type1 can represent all values of type2.

    if isinstance(type1, BitFieldType):
        width1 = type1.bit_size
        signed1 = type1._int_type.signed
    else:
        width1 = 8 * type1.size
        signed1 = type1.signed

    if isinstance(type2, BitFieldType):
        width2 = type2.bit_size
        signed2 = type2._int_type.signed
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
        if type_._int_type.signed:
            underlying_type = _corresponding_unsigned_type(type_._int_type)
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
    """
    A TypeIndex provides cached lookups of all of the types in a program.

    This is an abstract base class which is implemented by an internal class
    depending on the format of the debugging information available; it should
    not be created directly. Instead, see drgn.lib.type_index() or
    drgn.lib.kernel_type_index().
    """

    def __init__(self, address_size: int) -> None:
        self._address_size = address_size

    def _find_type(self, type_name: TypeName,
                   filename: Optional[str]) -> Type:
        raise NotImplementedError()

    @functools.lru_cache()
    def find(self, type_name: Union[str, TypeName],
             filename: Optional[str] = None) -> Type:
        """
        Return a Type object for the type with the given name, which may be a
        string or a TypeName object.

        If there are multiple types with the given name, they can be
        distinguished by passing the filename that the desired type was defined
        in. If no filename is given, it is undefined which one is returned.
        """
        if not isinstance(type_name, TypeName):
            type_name = parse_type_name(type_name)
        if isinstance(type_name, VoidTypeName):
            return VoidType(type_name.qualifiers)
        elif isinstance(type_name, PointerTypeName):
            return self.pointer(self.find(type_name.type, filename),
                                type_name.qualifiers)
        elif isinstance(type_name, ArrayTypeName):
            return self.array(self.find(type_name.type, filename),
                              type_name.size)
        else:
            return self._find_type(type_name, filename)

    def array(self, type_: Type, size: Optional[int]) -> ArrayType:
        """
        Return an array type of the given size with elements of the given type.
        """
        return ArrayType(type_, size, self._address_size)

    def pointer(self, type_: Type,
                qualifiers: Iterable[str] = frozenset()) -> PointerType:
        """Return a pointer type which points to the given type."""
        return PointerType(self._address_size, type_, qualifiers)

    def _ptrdiff_t(self) -> Type:
        try:
            return self.find('ptrdiff_t')
        except ValueError:
            pass
        return self.find('long')

    def _literal_type(self, value: Any) -> Any:
        if isinstance(value, bool):
            return self.find('_Bool')
        elif isinstance(value, numbers.Integral):
            value = int(value)
            for type_name in ['int', 'long', 'long long']:
                type_ = self.find(type_name)
                assert isinstance(type_, IntType)
                if -(1 << (8 * type_.size - 1)) <= value < (1 << (8 * type_.size - 1)):
                    return type_
                elif 0 <= value < (1 << 8 * type_.size):
                    return _corresponding_unsigned_type(type_)
            raise TypeError('integer is too large')
        elif isinstance(value, numbers.Real):
            return self.find('double')
        else:
            raise TypeError()

    def _integer_promotions(self, type_: Type) -> Type:
        # Integer promotions are performed on types whose integer conversion
        # rank is less than or equal to the rank of int and unsigned int and
        # bit-fields. GCC and Clang always convert enums to their compatible
        # type.

        if not isinstance(type_, (IntType, BitFieldType, EnumType, TypedefType)):
            return type_

        real_type = type_.real_type()

        if not isinstance(real_type, (IntType, BitFieldType, EnumType)):
            return type_

        if isinstance(real_type, BitFieldType):
            int_type = self.find('int')
            assert isinstance(int_type, IntType)
            if _can_represent_all_values(int_type, real_type):
                return int_type

            unsigned_int_type = self.find('unsigned int')
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

        int_type = self.find('int')
        assert isinstance(int_type, IntType)
        if _can_represent_all_values(int_type, real_type):
            # If int can represent all values of the original type, then the
            # result is int.
            return int_type

        # Otherwise, the result is unsigned int.
        unsigned_int_type = self.find('unsigned int')
        assert isinstance(unsigned_int_type, IntType)
        return unsigned_int_type

    def _common_real_type(self, type1: Type, type2: Type) -> Type:
        real_type1 = type1.real_type()
        real_type2 = type2.real_type()

        if (not isinstance(real_type1, (ArithmeticType, BitFieldType, EnumType)) or
                not isinstance(real_type2, (ArithmeticType, BitFieldType, EnumType))):
            raise TypeError('operands must have real types')

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

        # Otherwise, the integer promotions are performed before applying the
        # following rules.
        type1 = cast(Union[IntType, BitFieldType, TypedefType],
                     self._integer_promotions(type1))
        type2 = cast(Union[IntType, BitFieldType, TypedefType],
                     self._integer_promotions(type2))
        real_type1 = cast(Union[IntType, BitFieldType], type1.real_type())
        real_type2 = cast(Union[IntType, BitFieldType], type2.real_type())

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
        signed1 = real_type1._int_type.signed if isinstance(real_type1, BitFieldType) else real_type1.signed
        signed2 = real_type2._int_type.signed if isinstance(real_type2, BitFieldType) else real_type2.signed

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

        # Not sure why mypy needs to be reminded here.
        real_type1 = cast(Union[IntType, BitFieldType], real_type1)
        real_type2 = cast(Union[IntType, BitFieldType], real_type2)

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
