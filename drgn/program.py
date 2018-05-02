# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Program debugging library"""

from drgn.type import (
    ArrayType,
    CompoundType,
    PointerType,
    Type,
    TypedefType,
)
from drgn.typename import TypeName
from drgn.typeindex import TypeIndex
import itertools
from typing import Any, Callable, Iterable, Optional, Tuple, Union


class ProgramObject:
    """
    A ProgramObject either represents an object in the memory of a program (an
    "lvalue") or a temporary computed value (an "rvalue"). It has three
    members: program_, the program this object is from; address_, the location
    in memory where this object resides in the program (or None if it is not an
    lvalue); and type_, the type of this object in the program.

    repr() (the default at the interactive prompt) of a ProgramObject returns a
    Python representation of the object.

    >>> prog['jiffies']
    ProgramObject(address=0xffffffffbf005000, type=<volatile long unsigned int>)

    str() (which is used by print()) returns a representation of the object in
    C syntax.

    >>> print(prog['jiffies'])
    (volatile long unsigned int)4326237045

    ProgramObjects try to behave transparently like the object they represent
    in C. E.g., structure members can be accessed with the dot (".") operator
    and arrays can be subscripted with "[]".

    >>> print(prog['init_task'].pid)
    (pid_t)0
    >>> print(prog['init_task'].comm[0])
    (char)115

    Note that because the structure dereference operator ("->") is not valid
    syntax in Python, "." is also used to access members of pointers to
    structures. Similarly, the indirection operator ("*") is not valid syntax
    in Python, so pointers can be dereferenced with "[0]" (e.g., write "p[0]"
    instead of "*p").

    ProgramObject members and methods are named with a trailing underscore to
    avoid conflicting with structure or union members. The helper methods
    always take precedence over structure members; use member_() if there is a
    conflict.
    """

    def __init__(self, program: 'Program', address: Optional[int],
                 type: Type, value: Any = None) -> None:
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
        return ProgramObject(self.program_, address + offset, type_)

    def __iter__(self) -> Iterable['ProgramObject']:
        if not isinstance(self._real_type, ArrayType) or self._real_type.size is None:
            raise ValueError(f'{str(self.type_.type_name())!r} is not iterable')
        address = self.address_
        type_ = self._real_type.type
        for i in range(self._real_type.size):
            address = self.address_ + i * type_.sizeof()
            yield ProgramObject(self.program_, address, type_)

    def __repr__(self) -> str:
        parts = [
            'ProgramObject(address=',
            'None' if self.address_ is None else hex(self.address_), ', ',
            'type=<', str(self.type_.type_name()), '>',
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
        return ProgramObject(self.program_, address + offset, member_type)

    def cast_(self, type: Union[str, Type, TypeName]) -> 'ProgramObject':
        """
        Return a copy of this object casted to another type. The given type is
        usually a string, but it can also be a Type or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.program_.type(type)
        return ProgramObject(self.program_, self.address_, type, self._value)

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
        return ProgramObject(self.program_, None,
                             PointerType(self._real_type.size, type,
                                         self._real_type.qualifiers),
                             address)


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
        ProgramObject(address=0xffffffffbe012480, type=<struct task_struct>)
        """
        return self.variable(name)

    def object(self, address: Optional[int], type: Union[str, Type, TypeName],
               value: Any = None) -> ProgramObject:
        """
        Return a ProgramObject with the given address of the given type. The
        type can be a string, Type object, or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.type(type)
        return ProgramObject(self, address, type, value)

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
        return ProgramObject(self, address, type_)
