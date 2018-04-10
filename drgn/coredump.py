from drgn.type import (
    ArrayType,
    CompoundType,
    PointerType,
    Type,
    TypedefType,
)
from drgn.type import TypeName
import itertools
from typing import Any, Callable, Iterable, Optional, Tuple, Union


class CoredumpObject:
    """
    CoredumpObject(coredump, address, type, value=None) -> new object

    A CoredumpObject either represents an object in the memory of a program (an
    "lvalue") or a temporary computed value (an "rvalue"). It has three
    members: coredump_, the program this object is from; address_, the location
    in memory where this object resides in the program (or None if it is not an
    lvalue); and type_, the type of this object in the program.

    CoredumpObjects try to behave transparently like the object they represent
    in C. E.g., structure members can be accessed with the dot (".") operator
    and arrays can be subscripted with "[]". Note that because the structure
    dereference operator ("->") is not valid syntax in Python, "." is also used
    to access members of pointers to structures. Similarly, the indirection
    operator ("*") is not valid syntax in Python, so pointers can be
    dereferenced with "[0]" (e.g., write "p[0]" instead of "*p").

    CoredumpObject members and methods are named with a trailing underscore to
    avoid conflicting with structure or union members. The helper methods
    always take precedence over structure members; use member_() if there is a
    conflict.
    """

    def __init__(self, coredump: 'Coredump', address: Optional[int],
                 type: Type, value: Any = None) -> None:
        if address is not None and value is not None:
            raise ValueError('object cannot have address and value')
        if address is None and value is None:
            raise ValueError('object must have either address or value')
        self.coredump_ = coredump
        self.address_ = address
        self.type_ = type
        while isinstance(type, TypedefType):
            type = type.type
        self._real_type = type
        self._value = value

    def __getattr__(self, name: str) -> 'CoredumpObject':
        """Implement self.name. Shortcurt for self.member_(name)"""
        try:
            return self.member_(name)
        except ValueError as e:
            raise AttributeError(*e.args) from None

    def __getitem__(self, idx: Any) -> 'CoredumpObject':
        """
        Implement self[idx]. Return a CoredumpObject representing an array
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
        return CoredumpObject(self.coredump_, address + offset, type_)

    def __repr__(self) -> str:
        parts = [
            'CoredumpObject(address=',
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
        buffer = self.coredump_.read(self.address_, self._real_type.sizeof())
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
            byte = self.coredump_.read(address, 1)[0]
            if not byte:
                break
            b.append(byte)
        return bytes(b)

    def member_(self, name: str) -> 'CoredumpObject':
        """
        Return a CoredumpObject representing the given structure or union
        member.

        This is only valid for structs, unions, and pointers to either.
        Normally the dot operator (".") can be used to accomplish the same
        thing, but this method can be used if there is a name conflict with a
        CoredumpObject member or method.
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
        return CoredumpObject(self.coredump_, address + offset, member_type)

    def cast_(self, type: Union[str, Type, TypeName]) -> 'CoredumpObject':
        """
        Return a copy of this object casted to another type. The given type is
        usually a string, but it can also be a Type or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.coredump_.type(type)
        return CoredumpObject(self.coredump_, self.address_, type, self._value)

    def container_of_(self, type: Union[str, Type, TypeName],
                      member: str) -> 'CoredumpObject':
        """
        Return the containing object of the object pointed to by this object.
        The given type is the type of the containing object, and the given
        member is the name of this object in that type. This corresponds to the
        container_of() macro in C.

        This is only valid for pointers.
        """
        if not isinstance(type, Type):
            type = self.coredump_.type(type)
        if not isinstance(type, CompoundType):
            raise ValueError('container_of is only valid with struct or union types')
        if not isinstance(self._real_type, PointerType):
            raise ValueError('container_of is only valid on pointers')
        address = self.value_() - type.offsetof(member)
        return CoredumpObject(self.coredump_, None,
                              PointerType(self._real_type.size, type,
                                          self._real_type.qualifiers),
                              address)


class Coredump:
    """
    A Coredump object represents a crashed or running program to be debugged.
    """

    def __init__(self, *, lookup_type_fn: Callable[[Union[str, TypeName]], Type],
                 lookup_variable_fn: Callable[[str], Tuple[int, Type]],
                 read_memory_fn: Callable[[int, int], bytes]) -> None:
        self._lookup_type = lookup_type_fn
        self._read_memory = read_memory_fn
        self._lookup_variable = lookup_variable_fn

    def __getitem__(self, name: str) -> CoredumpObject:
        """
        Implement self[name]. This is equivalent to self.variable(name) and is
        provided for convenience.

        >>> core['init_task']
        CoredumpObject(address=0xffffffffbe012480, type=<struct task_struct>)
        """
        return self.variable(name)

    def object(self, address: int, type: Union[str, Type, TypeName],
               value: Any = None) -> CoredumpObject:
        """
        Return a CoredumpObject with the given address of the given type. The
        type can be a string, Type object, or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.type(type)
        return CoredumpObject(self, address, type, value)

    def read(self, address: int, size: int) -> bytes:
        """
        Return size bytes of memory starting at address in the coredump.

        >>> core.read(0xffffffffbe012b40, 16)
        b'swapper/0\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        """
        return self._read_memory(address, size)

    def type(self, name: Union[str, TypeName]) -> Type:
        """
        Return a Type object for the type with the given name. The name is
        usually a string, but it can also be a TypeName object.
        """
        return self._lookup_type(name)

    def variable(self, name: str) -> CoredumpObject:
        """
        Return a CoredumpObject representing the variable with the given name.
        """
        address, type_ = self._lookup_variable(name)
        return CoredumpObject(self, address, type_)
