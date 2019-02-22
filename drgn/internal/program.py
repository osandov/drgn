# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Program debugging library

This module provides the two main interfaces provided by drgn -- the Program
class, which represents the program being debugged, and the Object class, which
represents an object (i.e., variable or value) in that program.
"""

import math
import operator
from typing import cast, Any, Callable, Iterable, Optional, Tuple, Union

from drgn.internal.corereader import CoreReader
from drgn.internal.variableindex import VariableIndex
from drgn.type import ArrayType, CompoundType, PointerType, Type
from drgn.typeindex import TypeIndex
from drgn.typename import TypeName


def _c_modulo(a: int, b: int) -> int:
    if a >= 0:
        return a % abs(b)
    else:
        return -(-a % abs(b))


class Object:
    """
    An Object represents a variable or value in a program. The object may be in
    the memory of the program (an "lvalue").

    >>> Object(prog, 'int', address=0xffffffffc09031a0)

    It can also be a temporary computed value (an "rvalue").

    >>> Object(prog, 'int', value=4)

    An Object has three members: prog_, the program this object is from; type_,
    the type of this object in the program; and address_, the location in
    memory where this object resides in the program (or None if it is an
    rvalue).

    repr() of an Object returns a Python representation of the object.

    >>> print(repr(prog['jiffies']))
    Object(type=<volatile long unsigned int>, address=0xffffffffbf005000)

    str() returns a representation of the object in C syntax.

    >>> print(prog['jiffies'])
    (volatile long unsigned int)4326237045

    Note that the drgn CLI is set up so that Objects are displayed with str()
    instead of repr() (the latter is the default behavior of Python's
    interactive mode). This means that in the drgn CLI, the call to print() in
    the second example above is not necessary.

    Objects support C operators wherever possible. E.g., structure members can
    be accessed with the dot (".") operator, arrays can be subscripted with
    "[]", arithmetic can be performed, and objects can be compared.

    >>> print(prog['init_task'].pid)
    (pid_t)0
    >>> print(prog['init_task'].comm[0])
    (char)115
    >>> print(repr(prog['init_task'].nsproxy.mnt_ns.mounts + 1))
    Object(type=<unsigned int>, value=34)
    >>> prog['init_task'].nsproxy.mnt_ns.pending_mounts > 0
    False

    Note that because the structure dereference operator ("->") is not valid
    syntax in Python, "." is also used to access members of pointers to
    structures. Similarly, the indirection operator ("*") is not valid syntax
    in Python, so pointers can be dereferenced with "[0]" (e.g., write "p[0]"
    instead of "*p"). The address-of operator ("&") is available as the
    address_of_() method.

    Object members and methods are named with a trailing underscore to avoid
    conflicting with structure or union members. The helper methods always take
    precedence over structure members; use member_() if there is a conflict.
    """

    def __init__(self, prog: 'Program', type: Union[str, Type, TypeName], *,
                 value: Any = None, address: Optional[int] = None) -> None:
        if not isinstance(type, Type):
            type = prog.type(type)
        self.prog_ = prog
        self.type_ = type
        real_type = type.real_type()
        self._real_type = real_type
        if value is None:
            if address is None:
                raise ValueError('object must have either address or value')
            self._value = None
            self.address_: Optional[int] = address
        elif address is not None:
            raise ValueError('object cannot have address and value')
        else:
            self._value = real_type._convert(value)
            self.address_ = None

    def __dir__(self) -> Iterable[str]:
        attrs = list(super().__dir__())
        if isinstance(self._real_type, PointerType):
            type_ = self._real_type.type.real_type()
        else:
            type_ = self._real_type
        if isinstance(type_, CompoundType):
            attrs.extend(type_.member_names())
        return attrs

    def __getattr__(self, name: str) -> 'Object':
        """Implement self.name. Shortcut for self.member_(name)."""
        try:
            return self.member_(name)
        except ValueError as e:
            if len(e.args) == 1 and 'struct or union' in e.args[0]:
                raise AttributeError(f'{self.__class__.__name__!r} object has no attribute {name!r}') from None
            elif e.args and 'has no member' in e.args[0]:
                raise AttributeError(e.args[0]) from None
            else:
                raise

    def __len__(self) -> int:
        if not isinstance(self._real_type, ArrayType) or self._real_type.size is None:
            raise ValueError(f'{self.type_.name!r} has no len()')
        return self._real_type.size

    def __getitem__(self, idx: Any) -> 'Object':
        """
        Implement self[idx]. Return an Object representing an array element at
        the given index.

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
            raise ValueError(f'subscripted value must be an array or pointer, not {self.type_.name!r}')
        offset = i * type_.sizeof()
        return Object(self.prog_, type_, address=address + offset)

    def __iter__(self) -> Iterable['Object']:
        if not isinstance(self._real_type, ArrayType) or self._real_type.size is None:
            raise ValueError(f'{self.type_.name!r} is not iterable')
        assert self.address_ is not None  # Array rvalues are not allowed
        type_ = self._real_type.type
        for i in range(self._real_type.size):
            address = self.address_ + i * type_.sizeof()
            yield Object(self.prog_, type_, address=address)

    def __repr__(self) -> str:
        parts = ['Object(type=<', self.type_.name, '>']
        if self._value is not None:
            parts.append(', value=')
            if isinstance(self._real_type, PointerType):
                parts.append(hex(self._value))
            else:
                parts.append(repr(self._value))
        if self.address_ is not None:
            parts.append(', address=')
            parts.append(hex(self.address_))
        parts.append(')')
        return ''.join(parts)

    def __format__(self, format_spec: str) -> str:
        columns = 0
        if format_spec:
            if format_spec[0] != '.':
                raise ValueError('Format specifier can only include precision')
            try:
                columns = int(format_spec[1:], 10)
            except ValueError:
                raise ValueError('Format specifier missing precision') from None
        return self.type_._pretty(self.value_(), columns=columns,
                                  reader=self.prog_._reader)

    def __str__(self) -> str:
        """
        Implement str(self). Return a string representation of the value of
        this object in C syntax.
        """
        return self.__format__('')

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
        return self._real_type._read(self.prog_._reader,
                                     cast(int, self.address_))

    def string_(self) -> bytes:
        """
        Return the null-terminated string pointed to by this object as bytes.

        This is only valid for pointers and arrays.
        """
        if isinstance(self._real_type, PointerType):
            return self.prog_._reader.read_c_string(self.value_())
        elif isinstance(self._real_type, ArrayType):
            assert self.address_ is not None  # Array rvalues are not allowed
            return self.prog_._reader.read_c_string(
                self.address_, maxsize=self._real_type.size or -1)
        else:
            raise ValueError(f'string_() value must be an array or pointer, not {self.type_.name!r}')

    def member_(self, name: str) -> 'Object':
        """
        Return an Object representing the given structure or union member.

        This is only valid for structs, unions, and pointers to either.
        Normally the dot operator (".") can be used to accomplish the same
        thing, but this method can be used if there is a name conflict with an
        Object member or method.
        """
        if isinstance(self._real_type, PointerType):
            address = self.value_()
            type_ = self._real_type.type.real_type()
        else:
            address = self.address_
            type_ = self._real_type
        try:
            # mypy doesn't understand the except AttributeError.
            member_type, offset = type_.member(name)  # type: ignore
        except AttributeError:
            raise ValueError(f'member access must be on a struct or union, not {self.type_.name!r}') from None
        return Object(self.prog_, member_type, address=address + offset)

    def address_of_(self) -> 'Object':
        """
        Return an object pointing to this object. Corresponds to the address-of
        ("&") operator in C.
        """
        if self.address_ is None:
            raise ValueError('cannot take address of rvalue')
        return Object(self.prog_, self.prog_._type_index.pointer(self.type_),
                      value=self.address_)

    def _unary_operator(self, op: Callable, op_name: str,
                        integer: bool = False) -> 'Object':
        if ((integer and not self._real_type.is_integer()) or
                (not integer and not self._real_type.is_arithmetic())):
            raise TypeError(f'invalid operand to unary {op_name} ({self.type_.name!r})')
        type_ = self.type_.operand_type()
        if self._real_type.is_integer():
            type_ = self.prog_._type_index._integer_promotions(type_)
        return Object(self.prog_, type_, value=op(self.value_()))

    def _binary_operands(self, lhs: Any, rhs: Any) -> Tuple[Any, Type, Any, Type]:
        lhs_obj = isinstance(lhs, Object)
        rhs_obj = isinstance(rhs, Object)
        if lhs_obj and rhs_obj and lhs.prog_ is not rhs.prog_:
            raise ValueError('operands are from different programs')
        if lhs_obj:
            lhs_type = lhs.type_
            if isinstance(lhs._real_type, ArrayType):
                lhs = lhs.address_
            else:
                lhs = lhs.value_()
        else:
            lhs_type = self.prog_._type_index._literal_type(lhs)
        if rhs_obj:
            rhs_type = rhs.type_
            if isinstance(rhs._real_type, ArrayType):
                rhs = rhs.address_
            else:
                rhs = rhs.value_()
        else:
            rhs_type = self.prog_._type_index._literal_type(rhs)
        return lhs, lhs_type, rhs, rhs_type

    def _usual_arithmetic_conversions(self, lhs: Any, lhs_type: Type,
                                      rhs: Any, rhs_type: Type) -> Tuple[Type, Any, Any]:
        type_ = self.prog_._type_index._common_real_type(lhs_type, rhs_type)
        return type_, type_._convert(lhs), type_._convert(rhs)

    def _arithmetic_operator(self, op: Callable, op_name: str, lhs: Any,
                             rhs: Any) -> 'Object':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic():
            raise TypeError(f'invalid operands to binary {op_name} ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                             rhs, rhs_type)
        return Object(self.prog_, type_, value=op(lhs, rhs))

    def _integer_operator(self, op: Callable, op_name: str,
                          lhs: Any, rhs: Any) -> 'Object':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_integer() or not rhs_type.is_integer():
            raise TypeError(f'invalid operands to binary {op_name} ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                             rhs, rhs_type)
        return Object(self.prog_, type_, value=op(lhs, rhs))

    def _shift_operator(self, op: Callable, op_name: str, lhs: Any,
                        rhs: Any) -> 'Object':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        if not lhs_type.is_integer() or not rhs_type.is_integer():
            raise TypeError(f'invalid operands to binary {op_name} ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        lhs_type = self.prog_._type_index._integer_promotions(lhs_type)
        rhs_type = self.prog_._type_index._integer_promotions(rhs_type)
        return Object(self.prog_, lhs_type, value=op(lhs, rhs))

    def _relational_operator(self, op: Callable, op_name: str,
                             other: Any) -> bool:
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(self, other)
        lhs_pointer = lhs_type.is_pointer_operand()
        rhs_pointer = rhs_type.is_pointer_operand()
        if ((lhs_pointer != rhs_pointer) or
                (not lhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f'invalid operands to binary {op_name} ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        if not lhs_pointer:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
        return op(lhs, rhs)

    def _add(self, lhs: Any, rhs: Any) -> 'Object':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        lhs_pointer = lhs_type.is_pointer_operand()
        rhs_pointer = rhs_type.is_pointer_operand()
        if ((lhs_pointer and rhs_pointer) or
                (lhs_pointer and not rhs_type.is_integer()) or
                (rhs_pointer and not lhs_type.is_integer()) or
                (not lhs_pointer and not rhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f'invalid operands to binary + ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        if lhs_pointer:
            assert isinstance(lhs_type, PointerType)
            return Object(self.prog_, lhs_type,
                          value=lhs + lhs_type.type.sizeof() * rhs)
        elif rhs_pointer:
            assert isinstance(rhs_type, PointerType)
            return Object(self.prog_, rhs_type,
                          value=rhs + rhs_type.type.sizeof() * lhs)
        else:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
            return Object(self.prog_, type_, value=lhs + rhs)

    def _sub(self, lhs: Any, rhs: Any) -> 'Object':
        lhs, lhs_type, rhs, rhs_type = self._binary_operands(lhs, rhs)
        lhs_pointer = lhs_type.is_pointer_operand()
        if lhs_pointer:
            lhs_sizeof = cast(PointerType, lhs_type).type.sizeof()
        rhs_pointer = rhs_type.is_pointer_operand()
        if rhs_pointer:
            rhs_sizeof = cast(PointerType, rhs_type).type.sizeof()
        if ((lhs_pointer and rhs_pointer and lhs_sizeof != rhs_sizeof) or
                (lhs_pointer and not rhs_pointer and not rhs_type.is_integer()) or
                (rhs_pointer and not lhs_pointer) or
                (not lhs_pointer and not rhs_pointer and
                 (not lhs_type.is_arithmetic() or not rhs_type.is_arithmetic()))):
            raise TypeError(f'invalid operands to binary - ({lhs_type.name!r} and {rhs_type.name!r})')
        lhs_type = lhs_type.operand_type()
        rhs_type = rhs_type.operand_type()
        if lhs_pointer and rhs_pointer:
            return Object(self.prog_, self.prog_._type_index._ptrdiff_t(),
                          value=(lhs - rhs) // lhs_sizeof)
        elif lhs_pointer:
            return Object(self.prog_, lhs_type, value=lhs - lhs_sizeof * rhs)
        else:
            type_, lhs, rhs = self._usual_arithmetic_conversions(lhs, lhs_type,
                                                                 rhs, rhs_type)
            return Object(self.prog_, type_, value=lhs - rhs)

    def __add__(self, other: Any) -> 'Object':
        return self._add(self, other)

    def __sub__(self, other: Any) -> 'Object':
        return self._sub(self, other)

    def __mul__(self, other: Any) -> 'Object':
        return self._arithmetic_operator(operator.mul, '*', self, other)

    def __truediv__(self, other: Any) -> 'Object':
        return self._arithmetic_operator(operator.truediv, '/', self, other)

    def __mod__(self, other: Any) -> 'Object':
        return self._integer_operator(_c_modulo, '%', self, other)

    def __lshift__(self, other: Any) -> 'Object':
        return self._shift_operator(operator.lshift, '<<', self, other)

    def __rshift__(self, other: Any) -> 'Object':
        return self._shift_operator(operator.rshift, '>>', self, other)

    def __and__(self, other: Any) -> 'Object':
        return self._integer_operator(operator.and_, '&', self, other)

    def __xor__(self, other: Any) -> 'Object':
        return self._integer_operator(operator.xor, '^', self, other)

    def __or__(self, other: Any) -> 'Object':
        return self._integer_operator(operator.or_, '|', self, other)

    def __radd__(self, other: Any) -> 'Object':
        return self._add(other, self)

    def __rsub__(self, other: Any) -> 'Object':
        return self._sub(other, self)

    def __rmul__(self, other: Any) -> 'Object':
        return self._arithmetic_operator(operator.mul, '*', other, self)

    def __rtruediv__(self, other: Any) -> 'Object':
        return self._arithmetic_operator(operator.truediv, '/', other, self)

    def __rmod__(self, other: Any) -> 'Object':
        return self._integer_operator(_c_modulo, '%', other, self)

    def __rlshift__(self, other: Any) -> 'Object':
        return self._shift_operator(operator.lshift, '<<', other, self)

    def __rrshift__(self, other: Any) -> 'Object':
        return self._shift_operator(operator.rshift, '>>', other, self)

    def __rand__(self, other: Any) -> 'Object':
        return self._integer_operator(operator.and_, '&', other, self)

    def __rxor__(self, other: Any) -> 'Object':
        return self._integer_operator(operator.xor, '^', other, self)

    def __ror__(self, other: Any) -> 'Object':
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
        if (not self._real_type.is_arithmetic() and
                not self._real_type.is_pointer_operand()):
            raise TypeError(f'invalid operand to bool() ({self.type_.name!r})')
        return bool(self.value_())

    def __neg__(self) -> 'Object':
        return self._unary_operator(operator.neg, '-')

    def __pos__(self) -> 'Object':
        return self._unary_operator(operator.pos, '+')

    def __invert__(self) -> 'Object':
        return self._unary_operator(operator.invert, '~', True)

    def __int__(self) -> int:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot convert {self.type_.name!r} to int')
        return int(self.value_())

    def __float__(self) -> float:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot convert {self.type_.name!r} to float')
        return float(self.value_())

    def __index__(self) -> int:
        if not self._real_type.is_integer():
            raise TypeError(f'cannot convert {self.type_.name!r} to index')
        return int(self.value_())

    def __round__(self, ndigits: Optional[int] = None) -> Union[int, 'Object']:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot round {self.type_.name!r}')
        if ndigits is None:
            return round(self.value_())
        return Object(self.prog_, self.type_,
                      value=round(self.value_(), ndigits))

    def __trunc__(self) -> int:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot round {self.type_.name!r}')
        return math.trunc(self.value_())

    def __floor__(self) -> int:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot round {self.type_.name!r}')
        return math.floor(self.value_())

    def __ceil__(self) -> int:
        if not self._real_type.is_arithmetic():
            raise TypeError(f'cannot round {self.type_.name!r}')
        return math.ceil(self.value_())


class Program:
    """
    A Program object represents a crashed or running program. It can be used to
    lookup type definitions, access variables, and read arbitrary memory.
    """

    def __init__(self, *, reader: CoreReader, type_index: TypeIndex,
                 variable_index: VariableIndex) -> None:
        self._reader = reader
        self._type_index = type_index
        self._variable_index = variable_index
        # Ugly hack for KernelVariableIndex.
        try:
            set_program = variable_index.set_program  # type: ignore
        except AttributeError:
            pass
        else:
            set_program(self)

    def __enter__(self) -> 'Program':
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def _is_kernel(self) -> bool:
        from drgn.internal.kernelvariableindex import KernelVariableIndex
        return isinstance(self._variable_index, KernelVariableIndex)

    def close(self) -> None:
        """
        Close resources associated with this Program.

        After this is called, other methods on this object must not be called.
        A Program may also be used as a context manager, in which case it will
        be closed automatically.

        Note that this method is only useful when using drgn as a library; when
        using the drgn CLI, the main Program object is created and closed
        automatically.
        """
        self._reader.close()

    def __getitem__(self, name: str) -> Object:
        """
        Implement self[name]. This is equivalent to self.variable(name) and is
        provided for convenience.

        >>> prog['init_task']
        Object(type=<struct task_struct>, address=0xffffffffbe012480)
        """
        return self.variable(name)

    def read(self, address: int, size: int, physical: bool = False) -> bytes:
        """
        Return size bytes of memory starting at address in the program. The
        address may be virtual (the default) or physical if the program
        supports it.

        >>> prog.read(0xffffffffbe012b40, 16)
        b'swapper/0\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        """
        return self._reader.read(address, size, physical)

    def type(self, name: Union[str, TypeName],
             filename: Optional[str] = None) -> Type:
        """
        Return a Type object for the type with the given name. The name is
        usually a string, but it can also be a TypeName object.

        If there are multiple types with the given name, they can be
        distinguished by passing the filename that the desired type was defined
        in. If no filename is given, it is undefined which one is returned.
        """
        return self._type_index.find(name, filename)

    def variable(self, name: str, filename: Optional[str] = None) -> Object:
        """
        Return an Object representing the variable or enumerator with the given
        name.

        If there are multiple identifiers with the given name, they can be
        distinguished by passing the filename that the desired identifier was
        defined in. If no filename is given, it is undefined which one is
        returned.
        """
        type_, value, address = self._variable_index.find(name, filename)
        return Object(self, type_, value=value, address=address)
