# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Program debugging library"""

from drgn.type import (
    ArithmeticType,
    BitFieldType,
    ArrayType,
    CompoundType,
    IntType,
    PointerType,
    Type,
    TypedefType,
)
from drgn.typename import TypeName
from drgn.typeindex import TypeIndex
import functools
import itertools
import math
import operator
from typing import Any, Callable, Iterable, Optional, Tuple, Union


def _c_modulo(a: int, b: int) -> int:
    if a >= 0:
        return a % abs(b)
    else:
        return -(-a % abs(b))


class ProgramObject:
    """
    A ProgramObject either represents an object in the memory of a program (an
    "lvalue") or a temporary computed value (an "rvalue"). It has three
    members: program_, the program this object is from; type_, the type of this
    object in the program; and address_, the location in memory where this
    object resides in the program (or None if it is not an lvalue).

    repr() (the default at the interactive prompt) of a ProgramObject returns a
    Python representation of the object.

    >>> prog['jiffies']
    ProgramObject(type=<volatile long unsigned int>, address=0xffffffffbf005000)

    str() (which is used by print()) returns a representation of the object in
    C syntax.

    >>> print(prog['jiffies'])
    (volatile long unsigned int)4326237045

    ProgramObjects support C operators wherever possible. E.g., structure
    members can be accessed with the dot (".") operator, arrays can be
    subscripted with "[]", arithmetic can be performed, and objects can be
    compared.

    >>> print(prog['init_task'].pid)
    (pid_t)0
    >>> print(prog['init_task'].comm[0])
    (char)115
    >>> prog['init_task'].nsproxy.mnt_ns.mounts + 1
    ProgramObject(type=<unsigned int>, address=None, value=34)
    >>> prog['init_task'].nsproxy.mnt_ns.pending_mounts > 0
    False

    Note that because the structure dereference operator ("->") is not valid
    syntax in Python, "." is also used to access members of pointers to
    structures. Similarly, the indirection operator ("*") is not valid syntax
    in Python, so pointers can be dereferenced with "[0]" (e.g., write "p[0]"
    instead of "*p"). The address-of operator ("&") is available as the
    address_of_() method.

    ProgramObject members and methods are named with a trailing underscore to
    avoid conflicting with structure or union members. The helper methods
    always take precedence over structure members; use member_() if there is a
    conflict.
    """

    def __init__(self, program: 'Program', type: Type, address: Optional[int],
                 value: Any = None) -> None:
        if address is not None and value is not None:
            raise ValueError('object cannot have address and value')
        if address is None and value is None:
            raise ValueError('object must have either address or value')
        self.program_ = program
        self.address_ = address
        self.type_ = type
        self._real_type = type.real_type()
        if value is not None:
            value = self._real_type.convert(value)
        self._value = value

    def __dir__(self) -> Iterable[str]:
        attrs = list(super().__dir__())
        if isinstance(self._real_type, PointerType):
            type_ = self._real_type.type
        else:
            type_ = self._real_type
        if isinstance(type_, CompoundType):
            attrs.extend(type_.members())
        return attrs

    def __getattr__(self, name: str) -> 'ProgramObject':
        """Implement self.name. Shortcurt for self.member_(name)."""
        if isinstance(self._real_type, PointerType):
            type_ = self._real_type.type
        else:
            type_ = self._real_type
        if not isinstance(type_, CompoundType):
            raise AttributeError(f'{self.__class__.__name__!r} object has no attribute {name!r}')
        try:
            return self.member_(name)
        except ValueError as e:
            raise AttributeError(*e.args) from None

    def __len__(self) -> int:
        if not isinstance(self._real_type, ArrayType) or self._real_type.size is None:
            raise ValueError(f'{str(self.type_.type_name())!r} has no len()')
        return self._real_type.size

    def __getitem__(self, idx: Any) -> 'ProgramObject':
        """
        Implement self[idx]. Return a ProgramObject representing an array
        element at the given index.

        This is only valid for pointers and arrays.
        """
        try:
            i = idx.__index__()
        except AttributeError:
            raise TypeError('index must be integer')
        if isinstance(self._real_type, PointerType):
            address = self.value_()
            type_ = self._real_type.type
        elif isinstance(self._real_type, ArrayType):
            address = self.address_
            # Duplicated here to work around mypy issue #4864.
            type_ = self._real_type.type
        else:
            raise ValueError('not an array or pointer')
        offset = i * type_.sizeof()
        return ProgramObject(self.program_, type_, address + offset)

    def __iter__(self) -> Iterable['ProgramObject']:
        if not isinstance(self._real_type, ArrayType) or self._real_type.size is None:
            raise ValueError(f'{str(self.type_.type_name())!r} is not iterable')
        assert self.address_ is not None  # Array rvalues are not allowed
        type_ = self._real_type.type
        for i in range(self._real_type.size):
            address = self.address_ + i * type_.sizeof()
            yield ProgramObject(self.program_, type_, address)

    def __repr__(self) -> str:
        parts = [
            'ProgramObject(type=<', str(self.type_.type_name()), '>, address=',
            'None' if self.address_ is None else hex(self.address_),
        ]
        if self._value is not None:
            parts.append(', value=')
            if isinstance(self._real_type, PointerType):
                parts.append(hex(self._value))
            else:
                parts.append(repr(self._value))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        """
        Implement str(self). Return a string representation of the value of
        this object in C syntax.
        """
        return self.type_.pretty(self.value_())

    def value_(self) -> Any:
        """
        Return the value of this object as a Python object.

        For basic types (int, bool, etc.), this returns an object of the
        directly corresponding Python type. For pointers, this returns the
        address value of the pointer. For enums, this returns an enum.IntEnum
        object or an int. For structures and unions, this returns an
        OrderedDict of members. For arrays, this returns a list of values.
        """
        if self._value is not None:
            return self._value
        assert self.address_ is not None
        buffer = self.program_.read(self.address_, self._real_type.sizeof())
        return self._real_type.read(buffer)

    def string_(self) -> bytes:
        """
        Return the null-terminated string pointed to by this object as bytes.

        This is only valid for pointers and arrays.
        """

        if isinstance(self._real_type, PointerType):
            addresses: Iterable[int] = itertools.count(self.value_())
        elif isinstance(self._real_type, ArrayType):
            assert self.address_ is not None  # Array rvalues are not allowed
            if self._real_type.size is None:
                addresses = itertools.count(self.address_)
            else:
                addresses = range(self.address_, self.address_ + self._real_type.size)
        else:
            raise ValueError('not an array or pointer')
        b = bytearray()
        for address in addresses:
            byte = self.program_.read(address, 1)[0]
            if not byte:
                break
            b.append(byte)
        return bytes(b)

    def member_(self, name: str) -> 'ProgramObject':
        """
        Return a ProgramObject representing the given structure or union
        member.

        This is only valid for structs, unions, and pointers to either.
        Normally the dot operator (".") can be used to accomplish the same
        thing, but this method can be used if there is a name conflict with a
        ProgramObject member or method.
        """

        if isinstance(self._real_type, PointerType):
            address = self.value_()
            type_ = self._real_type.type
        else:
            address = self.address_
            type_ = self._real_type
        if not isinstance(type_, CompoundType):
            raise ValueError('not a struct or union')
        member_type = type_.typeof(name)
        offset = type_.offsetof(name)
        return ProgramObject(self.program_, member_type, address + offset)

    def cast_(self, type: Union[str, Type, TypeName]) -> 'ProgramObject':
        """
        Return a copy of this object casted to another type. The given type is
        usually a string, but it can also be a Type or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.program_.type(type)
        return ProgramObject(self.program_, type, self.address_, self._value)

    def address_of_(self) -> 'ProgramObject':
        """
        Return an object pointing to this object. Corresponds to the address-of
        ("&") operator in C.
        """
        if self.address_ is None:
            raise ValueError('cannot take address of rvalue')
        return ProgramObject(self.program_,
                             self.program_._type_index.pointer(self.type_),
                             None, self.address_)

    def container_of_(self, type: Union[str, Type, TypeName],
                      member: str) -> 'ProgramObject':
        """
        Return the containing object of the object pointed to by this object.
        The given type is the type of the containing object, and the given
        member is the name of this object in that type. This corresponds to the
        container_of() macro in C.

        This is only valid for pointers.
        """
        if not isinstance(type, Type):
            type = self.program_.type(type)
        if not isinstance(type, CompoundType):
            raise ValueError('container_of is only valid with struct or union types')
        if not isinstance(self._real_type, PointerType):
            raise ValueError('container_of is only valid on pointers')
        address = self.value_() - type.offsetof(member)
        return ProgramObject(self.program_,
                             PointerType(self._real_type.size, type,
                                         self._real_type.qualifiers),
                             None, address)

    def _unary_operator(self, op: Callable, op_name: str,
                        integer: bool = False) -> 'ProgramObject':
        if ((integer and not self._real_type.is_integer()) or
                (not integer and not self._real_type.is_arithmetic())):
            raise TypeError(f"invalid operand to unary {op_name} ('{self.type_}')")
        type_ = self.program_._type_index.operand_type(self.type_)
        if self._real_type.is_integer():
            type_ = self.program_._type_index.integer_promotions(type_)
        return ProgramObject(self.program_, type_, None, op(self.value_()))

    def _binary_operands(self, lhs: Any, rhs: Any) -> Tuple[Any, Type, Any, Type]:
        if (isinstance(lhs, ProgramObject) and isinstance(rhs, ProgramObject) and
                lhs.program_ is not rhs.program_):
            raise ValueError('operands are from different programs')
        if isinstance(lhs, ProgramObject):
            lhs_type = lhs.type_
            if isinstance(lhs._real_type, ArrayType):
                lhs = lhs.address_
            else:
                lhs = lhs.value_()
        else:
            lhs_type = self.program_._type_index.literal_type(lhs)
        if isinstance(rhs, ProgramObject):
            rhs_type = rhs.type_
            if isinstance(rhs._real_type, ArrayType):
                rhs = rhs.address_
            else:
                rhs = rhs.value_()
        else:
            rhs_type = self.program_._type_index.literal_type(rhs)
        return lhs, lhs_type, rhs, rhs_type

    def _usual_arithmetic_conversions(self, lhs: Any, lhs_type: Type,
                                      rhs: Any, rhs_type: Type) -> Tuple[Type, Any, Any]:
        type_ = self.program_._type_index.common_real_type(lhs_type, rhs_type)
        return type_, type_.convert(lhs), type_.convert(rhs)

    def _arithmetic_operator(self, op: Callable, op_name: str,
                             lhs: Any, rhs: Any) -> 'ProgramObject':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic():
            raise TypeError(f"invalid operands to binary {op_name} ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                             rhs, rhs_type)
        return ProgramObject(self.program_, type_, None, op(lhs, rhs))

    def _integer_operator(self, op: Callable, op_name: str,
                          lhs: Any, rhs: Any) -> 'ProgramObject':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_integer() or not rhs_type.is_integer():
            raise TypeError(f"invalid operands to binary {op_name} ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                             rhs, rhs_type)
        return ProgramObject(self.program_, type_, None, op(lhs, rhs))

    def _shift_operator(self, op: Callable, op_name: str,
                        lhs: Any, rhs: Any) -> 'ProgramObject':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_integer() or not rhs_type.is_integer():
            raise TypeError(f"invalid operands to binary {op_name} ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        lhs_type = self.program_._type_index.integer_promotions(lhs_type)
        rhs_type = self.program_._type_index.integer_promotions(rhs_type)
        return ProgramObject(self.program_, lhs_type, None, op(lhs, rhs))

    def _relational_operator(self, op: Callable, op_name: str,
                             other: Any) -> bool:
        lhs_pointer = isinstance(self._real_type, (ArrayType, PointerType))
        rhs_pointer = (isinstance(other, ProgramObject) and
                       isinstance(other._real_type, (ArrayType, PointerType)))
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(self, other)
        if ((lhs_pointer != rhs_pointer) or
                (not lhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f"invalid operands to binary {op_name} ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        if not lhs_pointer:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
        return op(lhs, rhs)

    def _add(self, lhs: Any, rhs: Any) -> 'ProgramObject':
        lhs_pointer = (isinstance(lhs, ProgramObject) and
                       isinstance(lhs._real_type, (ArrayType, PointerType)))
        rhs_pointer = (isinstance(rhs, ProgramObject) and
                       isinstance(rhs._real_type, (ArrayType, PointerType)))
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if ((lhs_pointer and rhs_pointer) or
                (lhs_pointer and not rhs_type.is_integer()) or
                (rhs_pointer and not lhs_type.is_integer()) or
                (not lhs_pointer and not rhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f"invalid operands to binary + ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        if lhs_pointer:
            assert isinstance(lhs_type, PointerType)
            return ProgramObject(self.program_, lhs_type, None,
                                 lhs + lhs_type.type.sizeof() * rhs)
        elif rhs_pointer:
            assert isinstance(rhs_type, PointerType)
            return ProgramObject(self.program_, rhs_type, None,
                                 rhs + rhs_type.type.sizeof() * lhs)
        else:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
            return ProgramObject(self.program_, type_, None, lhs + rhs)

    def _sub(self, lhs: Any, rhs: Any) -> 'ProgramObject':
        lhs_pointer = (isinstance(lhs, ProgramObject) and
                       isinstance(lhs._real_type, (ArrayType, PointerType)))
        if lhs_pointer:
            lhs_sizeof = lhs._real_type.type.sizeof()
        rhs_pointer = (isinstance(rhs, ProgramObject) and
                       isinstance(rhs._real_type, (ArrayType, PointerType)))
        if rhs_pointer:
            rhs_sizeof = rhs._real_type.type.sizeof()
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if ((lhs_pointer and rhs_pointer and lhs_sizeof != rhs_sizeof) or
                (lhs_pointer and not rhs_pointer and not rhs_type.is_integer()) or
                (rhs_pointer and not lhs_pointer) or
                (not lhs_pointer and not rhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f"invalid operands to binary - ('{lhs_type}' and '{rhs_type}')")
        lhs_type = self.program_._type_index.operand_type(lhs_type)
        rhs_type = self.program_._type_index.operand_type(rhs_type)
        if lhs_pointer and rhs_pointer:
            return ProgramObject(self.program_,
                                 self.program_._type_index.ptrdiff_t(),
                                 None, (lhs - rhs) // lhs_sizeof)
        elif lhs_pointer:
            return ProgramObject(self.program_, lhs_type, None,
                                 lhs - lhs_sizeof * rhs)
        else:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
            return ProgramObject(self.program_, type_, None, lhs - rhs)

    def __add__(self, other: Any) -> 'ProgramObject':
        return self._add(self, other)

    def __sub__(self, other: Any) -> 'ProgramObject':
        return self._sub(self, other)

    def __mul__(self, other: Any) -> 'ProgramObject':
        return self._arithmetic_operator(operator.mul, '*', self, other)

    def __truediv__(self, other: Any) -> 'ProgramObject':
        return self._arithmetic_operator(operator.truediv, '/', self, other)

    def __mod__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(_c_modulo, '%', self, other)

    def __lshift__(self, other: Any) -> 'ProgramObject':
        return self._shift_operator(operator.lshift, '<<', self, other)

    def __rshift__(self, other: Any) -> 'ProgramObject':
        return self._shift_operator(operator.rshift, '>>', self, other)

    def __and__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.and_, '&', self, other)

    def __xor__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.xor, '^', self, other)

    def __or__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.or_, '|', self, other)

    def __radd__(self, other: Any) -> 'ProgramObject':
        return self._add(other, self)

    def __rsub__(self, other: Any) -> 'ProgramObject':
        return self._sub(other, self)

    def __rmul__(self, other: Any) -> 'ProgramObject':
        return self._arithmetic_operator(operator.mul, '*', other, self)

    def __rtruediv__(self, other: Any) -> 'ProgramObject':
        return self._arithmetic_operator(operator.truediv, '/', other, self)

    def __rmod__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(_c_modulo, '%', other, self)

    def __rlshift__(self, other: Any) -> 'ProgramObject':
        return self._shift_operator(operator.lshift, '<<', other, self)

    def __rrshift__(self, other: Any) -> 'ProgramObject':
        return self._shift_operator(operator.rshift, '>>', other, self)

    def __rand__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.and_, '&', other, self)

    def __rxor__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.xor, '^', other, self)

    def __ror__(self, other: Any) -> 'ProgramObject':
        return self._integer_operator(operator.or_, '|', other, self)

    def __lt__(self, other: Any) -> bool:
        return self._relational_operator(operator.lt, '<', other)

    def __le__(self, other: Any) -> bool:
        return self._relational_operator(operator.le, '<=', other)

    def __eq__(self, other: Any) -> bool:
        return self._relational_operator(operator.eq, '==', other)

    def __ne__(self, other: Any) -> bool:
        return self._relational_operator(operator.ne, '!=', other)

    def __gt__(self, other: Any) -> bool:
        return self._relational_operator(operator.gt, '>', other)

    def __ge__(self, other: Any) -> bool:
        return self._relational_operator(operator.ge, '>=', other)

    def __bool__(self) -> bool:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType,
                                            PointerType)):
            raise TypeError(f"invalid operand to bool() ('{self.type_}')")
        return bool(self.value_())

    def __neg__(self) -> 'ProgramObject':
        return self._unary_operator(operator.neg, '-')

    def __pos__(self) -> 'ProgramObject':
        return self._unary_operator(operator.pos, '+')

    def __invert__(self) -> 'ProgramObject':
        return self._unary_operator(operator.invert, '~', True)

    def __int__(self) -> int:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't convert {self.type_} to int")
        return int(self.value_())

    def __float__(self) -> float:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't convert {self.type_} to float")
        return float(self.value_())

    def __index__(self) -> int:
        if not isinstance(self._real_type, (IntType, BitFieldType)):
            raise TypeError(f"can't convert {self.type_} to index")
        return self.value_()

    def __round__(self, ndigits: Optional[int] = None) -> Union[int, 'ProgramObject']:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't round {self.type_}")
        if ndigits is None:
            return round(self.value_())
        return ProgramObject(self.program_, self.type_, None,
                             round(self.value_(), ndigits))

    def __trunc__(self) -> int:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't round {self.type_}")
        return math.trunc(self.value_())

    def __floor__(self) -> int:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't round {self.type_}")
        return math.floor(self.value_())

    def __ceil__(self) -> int:
        if not isinstance(self._real_type, (ArithmeticType, BitFieldType)):
            raise TypeError(f"can't round {self.type_}")
        return math.ceil(self.value_())


class Program:
    """
    A Program object represents a crashed or running program. It can be used to
    lookup type definitions, access variables, and read arbitrary memory.
    """

    def __init__(self, *, type_index: TypeIndex,
                 lookup_variable_fn: Callable[[str], Tuple[int, Type]],
                 read_memory_fn: Callable[[int, int], bytes]) -> None:
        self._type_index = type_index
        self._read_memory = read_memory_fn
        self._lookup_variable = lookup_variable_fn

    def __getitem__(self, name: str) -> ProgramObject:
        """
        Implement self[name]. This is equivalent to self.variable(name) and is
        provided for convenience.

        >>> prog['init_task']
        ProgramObject(type=<struct task_struct>, address=0xffffffffbe012480)
        """
        return self.variable(name)

    def object(self, type: Union[str, Type, TypeName], address: Optional[int],
               value: Any = None) -> ProgramObject:
        """
        Return a ProgramObject with the given address of the given type. The
        type can be a string, Type object, or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.type(type)
        return ProgramObject(self, type, address, value)

    def read(self, address: int, size: int) -> bytes:
        """
        Return size bytes of memory starting at address in the program.

        >>> prog.read(0xffffffffbe012b40, 16)
        b'swapper/0\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        """
        return self._read_memory(address, size)

    def type(self, name: Union[str, TypeName]) -> Type:
        """
        Return a Type object for the type with the given name. The name is
        usually a string, but it can also be a TypeName object.
        """
        return self._type_index.find_type(name)

    def variable(self, name: str) -> ProgramObject:
        """
        Return a ProgramObject representing the variable with the given name.
        """
        address, type_ = self._lookup_variable(name)
        return ProgramObject(self, type_, address)
