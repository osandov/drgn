from drgn.type import (
    ArrayType,
    CompoundType,
    PointerType,
    Type,
    TypedefType,
)
import itertools


class CoredumpObject:
    """
    CoredumpObject(coredump, address, type) -> new object

    A CoredumpObject represents an object in the memory of a program. It has
    three members: coredump_, the program this object is from; address_, the
    location in memory where this object resides in the program; and type_, the
    type of this object in the program.

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

    def __init__(self, coredump, address, type):
        self.coredump_ = coredump
        self.address_ = address
        self.type_ = type
        while isinstance(type, TypedefType):
            type = type.type
        self._real_type = type

    def __getattr__(self, name):
        """Implement self.name. Shortcurt for self.member_(name)"""
        return self.member_(name)

    def __getitem__(self, idx):
        """
        Implement self[idx]. Return a CoredumpObject representing an array
        element at the given index.

        This is only valid for pointers and arrays.
        """
        if isinstance(self._real_type, PointerType):
            buffer = self.coredump_.read(self.address_, self._real_type.sizeof())
            address = self._real_type.read(buffer)
            offset = idx.__index__() * self._real_type.type.sizeof()
        elif isinstance(self._real_type, ArrayType):
            address = self.address_
            offset = idx.__index__() * self._real_type.type.sizeof()
        else:
            raise ValueError('not an array or pointer')
        return CoredumpObject(self.coredump_, address + offset,
                              self._real_type.type)

    def __repr__(self):
        return f'CoredumpObject(address=0x{self.address_:x}, type=<{self.type_.type_name()}>)'

    def __str__(self):
        """
        Implement str(self). Return a string representation of the value of
        this object in C syntax.
        """
        buffer = self.coredump_.read(self.address_, self._real_type.sizeof())
        return self._real_type.format(buffer)

    def value_(self):
        """
        Return the value of this object as a Python object.

        For basic types (int, bool, etc.), this returns an object of the
        directly corresponding Python type. For pointers, this returns the
        address value of the pointer. For enums, this returns an enum.IntEnum
        object. For structures and unions, this returns an OrderedDict of
        members. For arrays, this returns a list of values.
        """
        buffer = self.coredump_.read(self.address_, self._real_type.sizeof())
        return self._real_type.read(buffer)

    def string_(self):
        """
        Return the null-terminated string pointed to by this object as bytes.

        This is only valid for pointers and arrays.
        """

        if isinstance(self._real_type, PointerType):
            addresses = itertools.count(self.value_())
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

    def member_(self, name):
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
            raise AttributeError()
        member_type = type_.typeof(name)
        offset = type_.offsetof(name)
        return CoredumpObject(self.coredump_, address + offset, member_type)

    def cast_(self, type):
        """
        Return a copy of this object casted to another type. The given type is
        usually a string, but it can also be a Type or TypeName object.
        """
        if not isinstance(type, Type):
            type = self.coredump_.find_type(type)
        return CoredumpObject(self.coredump_, self.address_, type)

    def container_of_(self, type, member):
        """
        Return the containing object of the object pointed to by this object.
        The given type is the type of the containing object, and the given
        member is the name of this object in that type. This corresponds to the
        container_of() macro in C.

        This is only valid for pointers.
        """
        if not isinstance(type, Type):
            type = self.coredump_.find_type(type)
        if not isinstance(self._real_type, PointerType):
            raise ValueError('containerof is only valid on pointers')
        address = self.value_() - type.offsetof(member)
        return CoredumpObject(self.coredump_, address, type)


class Coredump:
    """
    A Coredump object represents a crashed or running program to be debugged.
    """

    def __init__(self, *, lookup_type_fn, lookup_variable_fn, read_memory_fn):
        self._lookup_type = lookup_type_fn
        self._read_memory = read_memory_fn
        self._lookup_variable = lookup_variable_fn

    def __getitem__(self, name):
        """
        Implement self[name]. Return a CoredumpObject representing the variable
        with the given name.

        >>> core['init_task']
        CoredumpObject(address=0xffffffffbe012480, type=<struct task_struct>)
        """
        address, type_ = self._lookup_variable(name)
        return CoredumpObject(self, address, type_)

    def find_type(self, name):
        """
        Return a Type object for the type with the given name. The name is
        usually a string, but it can also be a TypeName object.
        """
        return self._lookup_type(name)

    def read(self, address, size):
        """
        Return size bytes of memory starting at address in the coredump.

        >>> core.read(0xffffffffbe012b40, 16)
        b'swapper/0\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        """
        return self._read_memory(address, size)
