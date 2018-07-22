# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Source program type representation

Types in a program are represented by objects of the Type class and its
subclasses. Different subclasses have different members describing the type,
like its name, qualifiers, signedness, etc. All subclasses of Type support
pretty-printing with str(type_obj) and getting the size in bytes with
type_obj.sizeof(). See the class documentation for more details, especially
help(Type).
"""

from collections import OrderedDict
import enum
import functools
import re
import struct
import sys
from types import MethodType
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
    cast,
)

from drgn.internal.corereader import CoreReader
from drgn.internal.memberdesignator import parse_member_designator
from drgn.internal.util import c_string
from drgn.typename import (
    ArrayTypeName,
    BasicTypeName,
    EnumTypeName,
    FunctionTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
    VoidTypeName,
)


_INT_READ = {
    (1, False): CoreReader.read_u8,
    (2, False): CoreReader.read_u16,
    (4, False): CoreReader.read_u32,
    (8, False): CoreReader.read_u64,
    (1, True): CoreReader.read_s8,
    (2, True): CoreReader.read_s16,
    (4, True): CoreReader.read_s32,
    (8, True): CoreReader.read_s64,
}

_BOOL_READ = {
    1: CoreReader.read_bool,
    2: CoreReader.read_bool16,
    4: CoreReader.read_bool32,
    8: CoreReader.read_bool64,
}

_FLOAT_READ = {
    4: CoreReader.read_float,
    8: CoreReader.read_double,
    16: CoreReader.read_long_double,
}


class Type:
    """
    A Type object represents a C type.

    repr() (the default at the interactive prompt) returns a Python
    representation of the type.
    >>> print(repr(prog['init_task'].fs.root.type_))
    StructType('path', 16, [('mnt', 0, ...), ('dentry', 8, ...)])

    str() (which is used by print()) returns a representation of the type in C
    syntax.

    >>> print(prog['init_task'].fs.root.type_)
    struct path {
            struct vfsmount *mnt;
            struct dentry *dentry;
    }

    A Type can have qualifiers as is the case in C.

    >>> prog['jiffies'].type_.qualifiers
    frozenset({'volatile'})

    There are several Type subclasses representing more specific types.
    """

    def __init__(self, qualifiers: Iterable[str] = frozenset()) -> None:
        self.qualifiers = frozenset(qualifiers)

    def __repr__(self) -> str:
        parts = [self.__class__.__name__, '(']
        if self.qualifiers:
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        return self.declaration('')

    def type_name(self) -> TypeName:
        """Get the name of this type as a drgn.typename.TypeName."""
        raise NotImplementedError()

    def declaration(self, name: str) -> str:
        """
        Return a C statement which would declare a variable of the given name
        to have this type.
        """
        return self.type_name().declaration(name)

    def sizeof(self) -> int:
        """Return sizeof(type)."""
        raise NotImplementedError()

    def real_type(self) -> 'Type':
        """
        Return the non-typedef type underlying this type if it is a typedef, or
        this type otherwise.

        In other words, if this type is a typedef, get its underlying type,
        recursively.
        """
        return self

    def unqualified(self) -> 'Type':
        """Return this type without qualifiers."""
        raise NotImplementedError()

    def operand_type(self) -> 'Type':
        """
        Return the type that this type is converted to when used in an
        expression.
        """
        return self.unqualified()

    def is_anonymous(self) -> bool:
        """
        Return whether this is an anonymous type (i.e., a struct, union, or
        enum type without a tag).
        """
        return False

    def is_arithmetic(self) -> bool:
        """
        Return whether this type is an arithmetic type. This is true for
        instances of ArithmeticType, EnumType, BitFieldType, and TypedefType if
        the underlying type is one of those.
        """
        return False

    def is_integer(self) -> bool:
        """
        Return whether this type is an integer type. This is true for instances
        of IntType, BitFieldType, and TypedefType if the underlying type is one
        of those.
        """
        return False

    def is_pointer(self) -> bool:
        """
        Return whether this type is a pointer type or implicitly converts to
        one (array types, function types, and typedefs with an underlying type
        of one of these).
        """
        return False

    def _convert(self, value: Any) -> Any:
        """Return the given value converted to a valid value of this type."""
        raise TypeError(f'cannot convert to {self}')

    def _read(self, reader: CoreReader, address: int) -> Any:
        """
        Read memory at the given address interpreted as this type.

        This is used internally by drgn and typically doesn't need to be used
        directly.
        """
        raise NotImplementedError()

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        """
        Return a representation of the value returned from self._read() in C
        syntax, optionally with an explicit cast to the name of this type. A
        number of columns to wrap to can be specified.
        """
        raise NotImplementedError()

    def _read_pretty(self, reader: CoreReader, address: int, *,
                     cast: bool = True) -> str:
        """
        Return self._pretty(self._read(...)).
        """
        return self._pretty(self._read(reader, address), cast)


class VoidType(Type):
    """
    A VoidType represents C's void. It can have qualifiers. See help(Type) for
    more information.
    """

    def type_name(self) -> VoidTypeName:
        return VoidTypeName(self.qualifiers)

    def sizeof(self) -> int:
        raise ValueError("can't get size of void")

    def unqualified(self) -> 'VoidType':
        if self.qualifiers:
            return VoidType()
        return self

    def _convert(self, value: Any) -> None:
        return None

    def _read(self, reader: CoreReader, address: int) -> Any:
        raise ValueError("can't read void")

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        raise ValueError("can't format void")


class ArithmeticType(Type):
    """
    An ArithmeticType represents an integer or floating-point data type. It has
    a name, a size, and qualifiers. See help(Type) for more information.

    >>> print(prog['init_task'].prio.type_.name)
    int
    >>> print(prog['init_task'].prio.type_.size)
    4
    """

    def __init__(self, name: str, size: int,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(qualifiers)
        self.name = name
        self.size = size

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.size),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def type_name(self) -> TypeName:
        return BasicTypeName(self.name, self.qualifiers)

    def sizeof(self) -> int:
        return self.size

    def is_arithmetic(self) -> bool:
        return True

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', str(value)]
            return ''.join(parts)
        else:
            return str(value)


def _int_convert(value: int, bit_size: int, signed: bool) -> int:
    value &= (1 << bit_size) - 1
    if signed and (value & (1 << (bit_size - 1))):
        value -= 1 << bit_size
    return value


class IntType(ArithmeticType):
    """
    An IntType represents an integral type. It has a name, size, signedness,
    and qualifiers. See help(ArithmeticType) and help(Type) for more
    information.

    >>> print(prog['init_task'].prio.type_.signed)
    True
    """

    def __init__(self, name: str, size: int, signed: bool,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(name, size, qualifiers)
        self.signed = signed
        setattr(self, '_read', _INT_READ[size, signed])

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.size), ', ',
            repr(self.signed),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def unqualified(self) -> 'IntType':
        if self.qualifiers:
            return IntType(self.name, self.size, self.signed)
        return self

    def is_integer(self) -> bool:
        return True

    def _convert(self, value: Any) -> int:
        try:
            value = value.__int__()
        except AttributeError:
            raise TypeError(f'cannot convert to {self}') from None
        return _int_convert(value, 8 * self.size, self.signed)


class BoolType(IntType):
    """
    A BoolType represents a boolean type. It has a name, size, and qualifiers.
    See help(IntType), help(ArithmeticType), and help(Type) for more
    information.
    """

    def __init__(self, name: str, size: int,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(name, size, False, qualifiers)
        setattr(self, '_read', _BOOL_READ[size])

    def __repr__(self) -> str:
        return ArithmeticType.__repr__(self)

    def unqualified(self) -> 'BoolType':
        if self.qualifiers:
            return BoolType(self.name, self.size)
        return self

    def _convert(self, value: Any) -> bool:
        try:
            return bool(value + 0)
        except TypeError:
            raise TypeError(f'cannot convert to {self}') from None

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', str(int(value))]
            return ''.join(parts)
        else:
            return str(int(value))


class FloatType(ArithmeticType):
    """
    A FloatType represents a floating-point type. It has a name, size, and
    qualifiers. See help(ArithmeticType) and help(Type) for more information.
    """

    def __init__(self, name: str, size: int,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(name, size, qualifiers)
        setattr(self, '_read', _FLOAT_READ[size])

    def unqualified(self) -> 'FloatType':
        if self.qualifiers:
            return FloatType(self.name, self.size)
        return self

    def _convert(self, value: Any) -> float:
        try:
            value = value.__float__()
        except AttributeError:
            raise TypeError(f'cannot convert to {self}') from None
        if self.size == 4:
            # Python doesn't have a native float32 type.
            return struct.unpack('f', struct.pack('f', value))[0]
        elif self.size == 8:
            return value
        else:
            raise ValueError(f"can't convert to float of size {self.size}")


class BitFieldType(Type):
    """
    A BitFieldType is not a real C type. It represents a bit field. It has an
    underlying integer type, a bit offset, and a bit size.

    >>> print(repr(prog['init_task'].in_execve.type_))
    BitFieldType(IntType('unsigned int', 4, False), 0, 1)
    >>> print(prog['init_task'].in_execve.type_)
    unsigned int : 1
    >>> print(repr(prog['init_task'].in_execve.type_.type))
    IntType('unsigned int', 4, False)
    >>> prog['init_task'].in_execve.type_.bit_size
    1
    >>> prog['init_task'].in_execve.type_.bit_offset
    0
    """

    def __init__(self, type: Type, bit_offset: Optional[int], bit_size: int,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        self.type = type
        real_type = type.real_type()
        self._int_type: IntType
        if isinstance(real_type, IntType):
            self._int_type = real_type
        elif isinstance(real_type, EnumType):
            if real_type.type is None:
                raise ValueError('bit field type is incomplete enum')
            self._int_type = real_type.type
        else:
            raise ValueError('bit field type is not integer')
        self.bit_offset = bit_offset
        self.bit_size = bit_size

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.type), ', ',
            repr(self.bit_offset), ', ',
            repr(self.bit_size), ')',
        ]
        return ''.join(parts)

    def type_name(self) -> TypeName:
        raise ValueError("can't get type name of bit field")

    def declaration(self, name: str) -> str:
        if name:
            name += ' : '
        else:
            name = ': '
        name += str(self.bit_size)
        return self.type.declaration(name)

    def sizeof(self) -> int:
        # Not really, but for convenience.
        if self.bit_offset is None:
            bit_offset = 0
        else:
            bit_offset = self.bit_offset
        return (bit_offset + self.bit_size + 7) // 8

    def unqualified(self) -> 'BitFieldType':
        if self.type.qualifiers:
            return BitFieldType(self.type.unqualified(), self.bit_offset,
                                self.bit_size)
        return self

    def is_arithmetic(self) -> bool:
        return True

    def is_integer(self) -> bool:
        return True

    def _convert(self, value: Any) -> int:
        try:
            value = value.__int__()
        except AttributeError:
            raise TypeError(f'cannot convert to {self}') from None
        return _int_convert(value, self.bit_size, self._int_type.signed)

    def _read(self, reader: CoreReader, address: int) -> int:
        if self.bit_offset is None:
            raise ValueError("can't read bit-field type")

        # XXX: this assumes little-endian
        buffer = reader.read(address, self.sizeof())
        offset = self.bit_offset // 8
        bit_offset = self.bit_offset % 8
        end = offset + (bit_offset + self.bit_size + 7) // 8
        value = int.from_bytes(buffer[offset:end], sys.byteorder)
        value >>= bit_offset
        value &= (1 << self.bit_size) - 1
        signed = self._int_type.signed
        if signed and (value & (1 << (self.bit_size - 1))):
            value -= (1 << self.bit_size)
        return value

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            parts = ['(', str(self.type.type_name()), ')', str(value)]
            return ''.join(parts)
        else:
            return str(value)


_TypeThunk = Callable[[], Type]


class CompoundType(Type):
    """
    A CompoundType represents a type with members. It has a name, a size,
    members, and qualifiers. The name may be None, which indicates an anonymous
    type. See help(Type) for more information.
    """

    def __init__(self, name: Optional[str], size: Optional[int],
                 members: Optional[List[Tuple[Optional[str], int, _TypeThunk]]],
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(qualifiers)
        # List of name, offset, type_thunk. type_thunk is a callable taking no
        # parameters which returns the type of the member. This lets us lazily
        # evaluate member types, which is necessary because structs may be very
        # deeply nested.
        self.name = name
        self.size = size
        self._members = members
        self._members_by_name: Dict[str, Tuple[int, _TypeThunk]] = OrderedDict()
        if members:
            self._index_members_by_name(members, 0)

    def _index_members_by_name(self, members: Any, offset: int) -> None:
        for name, member_offset, type_thunk in members:
            if name:
                self._members_by_name[name] = (offset + member_offset, type_thunk)
            else:
                self._index_members_by_name(type_thunk()._members,
                                            offset + member_offset)

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.size), ', ',
        ]
        if self._members is None:
            parts.append(repr(None))
        else:
            parts.append('[')
            parts.append(', '.join(f'({name!r}, {offset}, ...)' for
                                   name, offset, type_thunk in self._members))
            parts.append(']')
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        parts = [str(self.type_name())]
        if self._members is not None:
            parts.append(' {\n')
            for name, member_offset, type_thunk in self._members:
                member_type = type_thunk()
                decl = re.sub('^', '\t', member_type.declaration(name or ''),
                              flags=re.MULTILINE)
                parts.append(decl)
                parts.append(';\n')
            parts.append('}')
        return ''.join(parts)

    def declaration(self, name: str) -> str:
        if self.is_anonymous():
            parts = [str(self)]
            if name:
                parts.append(name)
            return ' '.join(parts)
        return super().declaration(name)

    def sizeof(self) -> int:
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size

    def is_anonymous(self) -> bool:
        return not self.name

    def _read(self, reader: CoreReader, address: int) -> Dict:
        if self.size is None:
            raise ValueError("can't read incomplete type")
        return OrderedDict([
            (name, type_thunk()._read(reader, address + member_offset))
            for name, (member_offset, type_thunk) in self._members_by_name.items()
        ])

    def _pretty(self, value: Dict, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if value.keys() != self._members_by_name.keys():
            raise ValueError('value members do not match type members')
        if cast and self.name:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        if self._members_by_name:
            parts.append('{\n')
            for name, (member_offset, type_thunk) in self._members_by_name.items():
                parts.append('\t.')
                parts.append(name)
                parts.append(' = ')
                member_pretty = type_thunk()._pretty(
                    value[name], columns=columns - 8,
                    # 9 for '\t.' + name + 3 for ' = ' + 1 for ','.
                    one_line_columns=columns - len(name) - 13)
                parts.append(member_pretty.replace('\n', '\n\t'))
                parts.append(',\n')
            parts.append('}')
        else:
            parts.append('{}')
        return ''.join(parts)

    def member_names(self) -> List[str]:
        """
        Return a list of member names.

        >>> prog['init_task'].fs.root.type_.member_names()
        ['mnt', 'dentry']
        """
        return list(self._members_by_name)

    def members(self) -> Iterable[Tuple[str, Type, int]]:
        """
        Return an iterator of all of the members of this type, as (name, type,
        offset) tuples.
        """
        for name, (offset, type_thunk) in self._members_by_name.items():
            yield name, type_thunk(), offset

    @functools.lru_cache()
    def member(self, member: str) -> Tuple[Type, int]:
        """
        Return self.typeof(member), self.offsetof(member). This is slightly
        more efficient than calling them both individually if you need both the
        type and offset.
        """
        designator = parse_member_designator(member)
        type_: Type = self
        offset = 0
        for op, value in designator:
            real_type = type_.real_type()
            if op == '.':
                if not isinstance(real_type, CompoundType):
                    raise ValueError(f'{str(type_.type_name())!r} is not a struct or union')
                try:
                    member_offset, type_thunk = real_type._members_by_name[cast(str, value)]
                except KeyError:
                    raise ValueError(f'{str(type_.type_name())!r} has no member {value!r}') from None
                type_ = type_thunk()
                offset += member_offset
            else:  # op == '[]'
                if not isinstance(real_type, ArrayType):
                    raise ValueError(f'{str(type_.type_name())!r} is not an array')
                type_ = real_type.type
                offset += cast(int, value) * type_.sizeof()
        return type_, offset

    def offsetof(self, member: str) -> int:
        """
        Return offsetof(type, member).

        >>> print(prog['init_task'].fs.root.type_.offsetof('dentry'))
        8
        """
        return self.member(member)[1]

    def typeof(self, member: str) -> Type:
        """
        Return typeof(type.member).

        >>> print(prog['init_task'].fs.root.type_.typeof('dentry'))
        struct dentry *
        """
        return self.member(member)[0]


class StructType(CompoundType):
    """
    A StructType represents a struct type. See help(CompoundType) and
    help(Type) for more information.

    >>> print(repr(prog['init_task'].fs.root.type_))
    StructType('path', 16, [('mnt', 0, ...), ('dentry', 8, ...)])
    >>> print(prog['init_task'].fs.root.type_)
    struct path {
            struct vfsmount *mnt;
            struct dentry *dentry;
    }
    """

    def type_name(self) -> StructTypeName:
        return StructTypeName(self.name, self.qualifiers)

    def unqualified(self) -> 'StructType':
        if self.qualifiers:
            return StructType(self.name, self.size, self._members)
        return self


class UnionType(CompoundType):
    """
    A UnionType represents a union type. See help(CompoundType) and help(Type)
    for more information.

    >>> print(repr(prog['init_task'].rcu_read_unlock_special.type_))
    UnionType('rcu_special', 4, [('b', 0, ...), ('s', 0, ...)])
    >>> print(prog['init_task'].rcu_read_unlock_special.type_)
    union rcu_special {
            struct {
                    u8 blocked;
                    u8 need_qs;
                    u8 exp_need_qs;
                    u8 pad;
            } b;
            u32 s;
    }
    """

    def type_name(self) -> UnionTypeName:
        return UnionTypeName(self.name, self.qualifiers)

    def unqualified(self) -> 'UnionType':
        if self.qualifiers:
            return UnionType(self.name, self.size, self._members)
        return self


class EnumType(Type):
    """
    An EnumType has a name, compatible integer type, enumerators (as a Python
    enum.IntEnum), and qualifiers. The name may be None, which indicates an
    anonymous enum type. The compatible integer type and enumerators may be
    None, which indicates an incomplete enum type. See help(Type) for more
    information.

    >>> print(prog.type('enum pid_type'))
    enum pid_type {
            PIDTYPE_PID = 0,
            PIDTYPE_PGID = 1,
            PIDTYPE_SID = 2,
            PIDTYPE_MAX = 3,
            __PIDTYPE_TGID = 4,
    }
    >>> print(prog.type('enum pid_type').enum)
    <enum 'pid_type'>
    >>> from pprint import pprint
    >>> pprint(prog.type('enum pid_type').enum.__members__)
    mappingproxy(OrderedDict([('PIDTYPE_PID', <pid_type.PIDTYPE_PID: 0>),
                              ('PIDTYPE_PGID', <pid_type.PIDTYPE_PGID: 1>),
                              ('PIDTYPE_SID', <pid_type.PIDTYPE_SID: 2>),
                              ('PIDTYPE_MAX', <pid_type.PIDTYPE_MAX: 3>),
                              ('__PIDTYPE_TGID', <pid_type.__PIDTYPE_TGID: 4>)]))
    >>> print(repr(prog.type('enum pid_type').type))
    IntType('unsigned int', 4, False)
    """

    def __init__(self, name: Optional[str], type: Optional[IntType],
                 enumerators: Optional[List[Tuple[str, int]]],
                 qualifiers: Iterable[str] = frozenset()) -> None:
        if (type is None) != (enumerators is None):
            raise ValueError('incomplete enum type must not have type or enumerators')
        super().__init__(qualifiers)
        self.name = name
        self.type = type
        if enumerators is None:
            self.enum = None
        else:
            self.enum = enum.IntEnum('' if name is None else name, enumerators)  # type: ignore
                                                                                 # mypy issue #4865.

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.type), ', ',
            repr(None if self.enum is None else self.enum.__members__),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        parts = [str(self.type_name())]
        if self.enum is not None:
            parts.append(' {\n')
            for name, value in self.enum.__members__.items():
                parts.append('\t')
                parts.append(name)
                parts.append(' = ')
                parts.append(str(value._value_))
                parts.append(',\n')
            parts.append('}')
        return ''.join(parts)

    def type_name(self) -> EnumTypeName:
        return EnumTypeName(self.name, self.qualifiers)

    def declaration(self, name: str) -> str:
        if self.is_anonymous():
            parts = [str(self)]
            if name:
                parts.append(name)
            return ' '.join(parts)
        return super().declaration(name)

    def sizeof(self) -> int:
        if self.type is None:
            raise ValueError("can't get size of incomplete type")
        return self.type.sizeof()

    def unqualified(self) -> 'EnumType':
        if self.qualifiers:
            return EnumType(self.name, self.type,
                            None if self.enum is None else self.enum.__members__)
        return self

    def is_anonymous(self) -> bool:
        return not self.name

    def is_arithmetic(self) -> bool:
        return True

    def _read(self, reader: CoreReader, address: int) -> Union[enum.IntEnum, int]:
        if self.type is None or self.enum is None:
            raise ValueError("can't read incomplete type")
        value = self.type._read(reader, address)
        try:
            return self.enum(value)
        except ValueError:
            return value

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        if self.enum is not None and not isinstance(value, self.enum):
            value = int(value)
            try:
                value = self.enum(value)
            except ValueError:
                pass
        if self.enum is not None and isinstance(value, self.enum):
            parts.append(value._name_)
        else:
            parts.append(str(value))
        return ''.join(parts)

    def _convert(self, value: Any) -> Union[enum.IntEnum, int]:
        if self.type is None or self.enum is None:
            raise ValueError("can't convert to incomplete enum type")
        try:
            value = self.type._convert(value)
        except TypeError:
            raise TypeError(f'cannot convert to {self}') from None
        try:
            return self.enum(value)
        except ValueError:
            return value


class TypedefType(Type):
    """
    A TypedefType has a name, an underlying type, and additional qualifiers.
    See help(Type) for more information.

    >>> print(repr(prog.type('u32')))
    TypedefType('u32', IntType('unsigned int', 4, False))
    >>> print(prog.type('u32'))
    typedef unsigned int u32
    >>> print(repr(prog.type('u32').type))
    IntType('unsigned int', 4, False)
    """

    def __init__(self, name: str, type: Type,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(qualifiers)
        self.name = name
        self.type = type

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.type),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        parts = sorted(self.qualifiers)  # Not real C syntax, but it gets the point across
        parts.append('typedef')
        parts.append(self.type.declaration(self.name))
        return ' '.join(parts)

    def type_name(self) -> TypedefTypeName:
        return TypedefTypeName(self.name, self.qualifiers)

    def sizeof(self) -> int:
        return self.type.sizeof()

    def real_type(self) -> Type:
        type_ = self.type
        while isinstance(type_, TypedefType):
            type_ = type_.type
        return type_

    def unqualified(self) -> 'TypedefType':
        if self.qualifiers:
            return TypedefType(self.name, self.type)
        return self

    def operand_type(self) -> Type:
        type_ = self.type
        while isinstance(type_, TypedefType):
            if type_.qualifiers:
                return type_.real_type().operand_type()
            type_ = type_.type
        if isinstance(type_, (ArrayType, FunctionType)) or type_.qualifiers:
            return type_.operand_type()
        if self.qualifiers:
            return TypedefType(self.name, self.type)
        return self

    def is_arithmetic(self) -> bool:
        return self.type.is_arithmetic()

    def is_integer(self) -> bool:
        return self.type.is_integer()

    def is_pointer(self) -> bool:
        return self.type.is_pointer()

    def _read(self, reader: CoreReader, address: int) -> Any:
        return self.type._read(reader, address)

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            if one_line_columns is None:
                one_line_columns = columns
            cast_str = str(self.type_name())
            pretty = self.type._pretty(
                value, cast=False, columns=columns,
                one_line_columns=one_line_columns - len(cast_str) - 2)
            parts = ['(', cast_str, ')', pretty]
            return ''.join(parts)
        else:
            return self.type._pretty(value, cast=False, columns=columns,
                                     one_line_columns=one_line_columns)

    def _convert(self, value: Any) -> Any:
        return self.type._convert(value)


class PointerType(Type):
    """
    A PointerType has a size, underlying type, and qualifiers. See help(Type)
    for more information.

    >>> print(repr(prog['init_task'].stack.type_))
    PointerType(8, VoidType())
    >>> print(prog['init_task'].stack.type_)
    void *
    >>> prog['init_task'].stack.type_.size
    8
    >>> print(repr(prog['init_task'].stack.type_.type))
    VoidType()
    """

    def __init__(self, size: int, type: Type,
                 qualifiers: Iterable[str] = frozenset()) -> None:
        super().__init__(qualifiers)
        self.size = size
        self.type = type
        setattr(self, '_read', _INT_READ[size, False])

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.size), ', ',
            repr(self.type),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def type_name(self) -> PointerTypeName:
        return PointerTypeName(self.type.type_name(), self.qualifiers)

    def sizeof(self) -> int:
        return self.size

    def unqualified(self) -> 'PointerType':
        if self.qualifiers:
            return PointerType(self.size, self.type)
        return self

    def is_pointer(self) -> bool:
        return True

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', hex(value)]
            return ''.join(parts)
        else:
            return hex(value)

    def _convert(self, value: Any) -> int:
        try:
            return value & ((1 << (8 * self.size)) - 1)
        except TypeError:
            raise TypeError(f'cannot convert to {self}') from None


class ArrayType(Type):
    """
    An ArrayType has an element type, a size, and a size of the pointer type
    that this type can be converted to. See help(Type) for more information.

    >>> print(repr(prog['init_task'].comm.type_))
    ArrayType(IntType('char', 1, True), 16, 8)
    >>> print(prog['init_task'].comm.type_)
    char [16]
    >>> print(repr(prog['init_task'].comm.type_.type))
    IntType('char', 1, True)
    >>> prog['init_task'].comm.type_.size
    16
    >>> prog['init_task'].comm.type_.pointer_size
    8
    """

    def __init__(self, type: Type, size: Optional[int],
                 pointer_size: int) -> None:
        self.type = type
        self.size = size
        self.pointer_size = pointer_size

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.type!r}, {self.size!r}, {self.pointer_size!r})'

    def type_name(self) -> ArrayTypeName:
        return ArrayTypeName(self.type.type_name(), self.size)

    def declaration(self, name: str) -> str:
        if self.size is None:
            name += '[]'
        else:
            name += f'[{self.size}]'
        return self.type.declaration(name)

    def sizeof(self) -> int:
        if self.size is None:
            raise ValueError("can't get size of incomplete array type")
        return self.size * self.type.sizeof()

    def _read(self, reader: CoreReader, address: int) -> List:
        if not self.size:
            return []
        element_size = self.type.sizeof()
        return [
            self.type._read(reader, address + i * element_size)
            for i in range(self.size)
        ]

    def unqualified(self) -> 'ArrayType':
        return self

    def operand_type(self) -> 'PointerType':
        return PointerType(self.pointer_size, self.type)

    def is_pointer(self) -> bool:
        return True

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        if one_line_columns is None:
            one_line_columns = columns
        if (self.size or 0) != len(value):
            raise ValueError('list size does not match type size')

        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []

        if (self.size and isinstance(self.type, IntType) and
                self.type.name.endswith('char')):
            try:
                i = value.index(0)
            except ValueError:
                i = len(value)
            parts.append(c_string(value[:i]))
        else:
            # Remove trailing zero elements.
            if value and not value[-1]:
                # Make a copy for the first one.
                value = value[:-1]
                while value and not value[-1]:
                    # Once we have a copy, we can delete the rest.
                    del value[-1]
            if not value:
                parts.append('{}')
                return ''.join(parts)

            parts.append('{')
            parts = [''.join(parts), ' ']
            current_columns = one_line_columns - len(parts[0]) - 1
            for element in value:
                # Account for the comma, space, and final closing brace.
                element_pretty = self.type._pretty(
                    element, cast=False, columns=columns - 8,
                    one_line_columns=current_columns - 3)
                if ('\n' in element_pretty or
                        current_columns - len(element_pretty) < 3):
                    break
                current_columns -= len(element_pretty) + 2
                parts.append(element_pretty)
                parts.append(', ')
            else:
                parts.append('}')
                return ''.join(parts)

            del parts[1:]
            parts.append('\n\t')
            current_columns = columns - 8
            for element in value:
                # Just the comma if at the beginning of a line, space and comma
                # otherwise.
                slack = 1 if current_columns == columns - 8 else 2
                element_pretty = self.type._pretty(
                    element, cast=False, columns=columns - 8,
                    one_line_columns=current_columns - slack)
                if ('\n' in element_pretty or
                        current_columns - len(element_pretty) < slack):
                    if current_columns != columns - 8:
                        parts.append('\n\t')
                        current_columns = columns - 8
                        element_pretty = self.type._pretty(
                            element, cast=False, columns=columns - 8,
                            one_line_columns=current_columns - 1)
                    parts.append(element_pretty.replace('\n', '\n\t'))
                    parts.append(',')
                    if '\n' in element_pretty:
                        parts.append('\n\t')
                    else:
                        current_columns -= len(element_pretty) + 1
                else:
                    if current_columns != columns - 8:
                        parts.append(' ')
                        current_columns -= 1
                    parts.append(element_pretty)
                    parts.append(',')
                    current_columns -= len(element_pretty) + 1
            if current_columns == columns - 8:
                parts[-1] = '\n}'
            else:
                parts.append('\n}')
        return ''.join(parts)


class FunctionType(Type):
    """
    A FunctionType has a return type and parameters, and may be variadic. It
    also has the size of the pointer type that this type can be converted to.
    It is often the underlying type of a PointerType or TypedefType. See
    help(Type) for more information.

    >>> print(prog.type('dio_submit_t'))
    typedef void dio_submit_t(struct bio *, struct inode *, loff_t)
    >>> prog.type('dio_submit_t').type.pointer_size
    8
    >>> print(repr(prog.type('dio_submit_t').type.return_type))
    VoidType()
    >>> prog.type('dio_submit_t').type.parameters[2]
    (TypedefType('loff_t', TypedefType('__kernel_loff_t', IntType('long long int', 8, True))), None)
    >>> prog.type('dio_submit_t').type.variadic
    False
    """

    def __init__(self, pointer_size: int, return_type: Type,
                 parameters: Optional[List[Tuple[Type, Optional[str]]]] = None,
                 variadic: bool = False) -> None:
        self.pointer_size = pointer_size
        self.return_type = return_type
        self.parameters = parameters
        self.variadic = variadic

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.return_type), ', ',
            repr(self.parameters), ', ',
            repr(self.variadic),
            ')',
        ]
        return ''.join(parts)

    def type_name(self) -> TypeName:
        if self.parameters is None:
            parameters = None
        else:
            parameters = [(type_.type_name(), name) for type_, name
                          in self.parameters]
        return FunctionTypeName(self.return_type.type_name(), parameters,
                                self.variadic)

    def sizeof(self) -> int:
        raise ValueError("can't get size of function")

    def unqualified(self) -> 'FunctionType':
        return self

    def operand_type(self) -> 'PointerType':
        return PointerType(self.pointer_size, self)

    def is_pointer(self) -> bool:
        return True

    def _read(self, reader: CoreReader, address: int) -> Dict:
        raise ValueError("can't read function")

    def _pretty(self, value: Any, cast: bool = True, columns: int = 0,
                one_line_columns: Optional[int] = None) -> str:
        raise ValueError("can't format function")
