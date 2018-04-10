from collections import OrderedDict
from drgn.dwarfindex import DwarfIndex
from drgn.dwarf import (
    Die,
    DwarfAttribNotFoundError,
    DwarfFormatError,
    DW_AT,
    DW_ATE,
    DW_TAG,
)
from drgn.typename import (
    parse_type_name,
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
import enum
import functools
import re
import struct
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


class Type:
    def __init__(self, qualifiers: Optional[Set[str]] = None) -> None:
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self) -> str:
        parts = [self.__class__.__name__, '(']
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        return str(self.type_name())

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def type_name(self) -> TypeName:
        raise NotImplementedError()

    def sizeof(self) -> int:
        raise NotImplementedError()

    def read(self, buffer: bytes, offset: int = 0) -> Any:
        raise NotImplementedError()

    def pretty(self, value: Any, cast: bool = True) -> str:
        raise NotImplementedError()

    def read_pretty(self, buffer: bytes, offset: int = 0, *,
                    cast: bool = True) -> str:
        return self.pretty(self.read(buffer, offset), cast)


class VoidType(Type):
    def type_name(self) -> VoidTypeName:
        return VoidTypeName(self.qualifiers)

    def sizeof(self) -> int:
        raise ValueError("can't get size of void")

    def read(self, buffer: bytes, offset: int = 0) -> Any:
        raise ValueError("can't read void")

    def pretty(self, value: Any, cast: bool = True) -> str:
        raise ValueError("can't format void")


class BasicType(Type):
    def __init__(self, name: str, size: int,
                 qualifiers: Optional[Set[str]] = None) -> None:
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

    def type_name(self) -> BasicTypeName:
        return BasicTypeName(self.name, self.qualifiers)

    def sizeof(self) -> int:
        return self.size

    def pretty(self, value: Any, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', str(value)]
            return ''.join(parts)
        else:
            return str(value)


class IntType(BasicType):
    def __init__(self, name: str, size: int, signed: bool,
                 qualifiers: Optional[Set[str]] = None) -> None:
        super().__init__(name, size, qualifiers)
        self.signed = signed

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

    def read(self, buffer: bytes, offset: int = 0) -> int:
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return int.from_bytes(buffer[offset:offset + self.size], sys.byteorder,
                              signed=self.signed)


class BoolType(BasicType):
    def read(self, buffer: bytes, offset: int = 0) -> bool:
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return bool(int.from_bytes(buffer[offset:offset + self.size],
                                   sys.byteorder))

    def pretty(self, value: Any, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', str(int(value))]
            return ''.join(parts)
        else:
            return str(int(value))


class FloatType(BasicType):
    def read(self, buffer: bytes, offset: int = 0) -> float:
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        if self.size == 4:
            return struct.unpack_from('f', buffer, offset)[0]
        elif self.size == 8:
            return struct.unpack_from('d', buffer, offset)[0]
        else:
            raise ValueError(f"can't read float of size {self.size}")


# Not a real C type, but it needs a separate representation.
class BitFieldType(Type):
    def __init__(self, type: IntType, bit_offset: int, bit_size: int,
                 qualifiers: Optional[Set[str]] = None) -> None:
        self.type = type
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

    def __str__(self) -> str:
        parts = [str(self.type.type_name()), ':', repr(self.bit_size)]
        return ' '.join(parts)

    def type_name(self) -> TypeName:
        raise ValueError("can't get type of bit field")

    def sizeof(self) -> int:
        # Not really, but for convenience.
        return (self.bit_offset + self.bit_size + 7) // 8

    def read(self, buffer: bytes, offset: int = 0) -> int:
        if len(buffer) - offset < self.sizeof():
            raise ValueError(f'buffer must be at least {self.sizeof()} bytes')

        # XXX: this assumes little-endian
        offset += self.bit_offset // 8
        bit_offset = self.bit_offset % 8
        end = offset + (bit_offset + self.bit_size + 7) // 8
        value = int.from_bytes(buffer[offset:end], sys.byteorder)
        value >>= bit_offset
        value &= (1 << self.bit_size) - 1
        signed = self.type.signed if hasattr(self.type, 'signed') else False
        if signed and (value & (1 << (self.bit_size - 1))):
            value -= (1 << self.bit_size)
        return value

    def pretty(self, value: Dict, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type.type_name()), ')', str(value)]
            return ''.join(parts)
        else:
            return str(value)


_TypeThunk = Callable[[], Type]


class CompoundType(Type):
    def __init__(self, name: str, size: int,
                 members: Optional[List[Tuple[str, int, _TypeThunk]]],
                 qualifiers: Optional[Set[str]] = None) -> None:
        super().__init__(qualifiers)
        # List of name, offset, type_thunk. type_thunk is a callable taking no
        # parameters which returns the type of the member. This lets us lazily
        # evaluate member types, which is necessary because structs may be very
        # deeply nested.
        self.name = name
        self.size = size
        self._members = members
        # XXX
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
                if (isinstance(member_type, (StructType, UnionType, EnumType)) and
                        not member_type.name):
                    decl = re.sub('^', '\t', str(member_type), flags=re.MULTILINE)
                    parts.append(decl)
                    if name:
                        parts.append(' ')
                        parts.append(name)
                else:
                    if isinstance(member_type, BitFieldType):
                        member_type_name: TypeName = member_type.type.type_name()
                    else:
                        member_type_name = member_type.type_name()
                    parts.append('\t')
                    parts.append(member_type_name.declaration(name))
                    if isinstance(member_type, BitFieldType):
                        parts.append(' : ')
                        parts.append(str(member_type.bit_size))
                parts.append(';\n')
            parts.append('}')
        return ''.join(parts)

    def _eager_members(self) -> Optional[List[Tuple[str, int, Type]]]:
        if self._members is None:
            return None
        return [
            (name, offset, type_thunk()) for name, offset, type_thunk in
            self._members
        ]

    def _dict_for_eq(self) -> Dict:
        # Compare the result of the type thunks rather than the thunks
        # themselves. __eq__ is only used for testing, so it's okay to eagerly
        # evaluate the struct member types.
        d = dict(self.__dict__)
        d['_members'] = self._eager_members()
        del d['_members_by_name']
        return d

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, self.__class__) and
                self._dict_for_eq() == other._dict_for_eq())  # type: ignore
                                                              # mypy issue #3061

    def sizeof(self) -> int:
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size

    def read(self, buffer: bytes, offset: int = 0) -> Dict:
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return OrderedDict([
            (name, type_thunk().read(buffer, offset + member_offset))
            for name, (member_offset, type_thunk) in self._members_by_name.items()
        ])

    def pretty(self, value: Dict, cast: bool = True) -> str:
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
                member_pretty = type_thunk().pretty(value[name])
                parts.append(member_pretty.replace('\n', '\n\t'))
                parts.append(',\n')
            parts.append('}')
        else:
            parts.append('{}')
        return ''.join(parts)

    def members(self) -> List[str]:
        return list(self._members_by_name)

    def offsetof(self, member: str) -> int:
        try:
            return self._members_by_name[member][0]
        except KeyError:
            raise ValueError(f'{str(self.type_name())!r} has no member {member!r}') from None

    def typeof(self, member: str) -> Type:
        try:
            return self._members_by_name[member][1]()
        except KeyError:
            raise ValueError(f'{str(self.type_name())!r} has no member {member!r}') from None


class StructType(CompoundType):
    def type_name(self) -> StructTypeName:
        return StructTypeName(self.name, self.qualifiers)


class UnionType(CompoundType):
    def type_name(self) -> UnionTypeName:
        return UnionTypeName(self.name, self.qualifiers)


class EnumType(Type):
    def __init__(self, name: str, size: int, signed: bool,
                 enumerators: Optional[List[Tuple[str, int]]],
                 qualifiers: Optional[Set[str]] = None) -> None:
        super().__init__(qualifiers)
        self.name = name
        self.size = size
        self.signed = signed
        if enumerators is None:
            self._enum = None
        else:
            self._enum = enum.IntEnum('' if name is None else name, enumerators)  # type: ignore
                                                                                  # mypy issue #4865.

    def __repr__(self) -> str:
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.size), ', ',
            repr(self.signed), ', ',
            repr(None if self._enum is None else self._enum.__members__),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        parts = [str(self.type_name())]
        if self._enum is not None:
            parts.append(' {\n')
            for name, value in self._enum.__members__.items():
                parts.append('\t')
                parts.append(name)
                parts.append(' = ')
                parts.append(str(value._value_))
                parts.append(',\n')
            parts.append('}')
        return ''.join(parts)

    def _dict_for_eq(self) -> Dict:
        d = dict(self.__dict__)
        if d['_enum'] is not None:
            d['_enum'] = d['_enum'].__members__
        return d

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, self.__class__) and
                self._dict_for_eq() == other._dict_for_eq())  # type: ignore
                                                              # mypy issue #3061

    def type_name(self) -> EnumTypeName:
        return EnumTypeName(self.name, self.qualifiers)

    def sizeof(self) -> int:
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size

    def read(self, buffer: bytes, offset: int = 0) -> Union[enum.IntEnum, int]:
        if self._enum is None:
            raise ValueError("can't read incomplete enum type")
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        value = int.from_bytes(buffer[offset:offset + self.size],
                               sys.byteorder, signed=self.signed)
        try:
            return self._enum(value)
        except ValueError:
            return value

    def pretty(self, value: Any, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        if not isinstance(value, self._enum):
            value = int(value)
            try:
                value = self._enum(value)
            except ValueError:
                pass
        if isinstance(value, self._enum):
            parts.append(value._name_)
        else:
            parts.append(str(value))
        return ''.join(parts)


class TypedefType(Type):
    def __init__(self, name: str, type: Type,
                 qualifiers: Optional[Set[str]] = None) -> None:
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
        parts.append(self.type.type_name().declaration(self.name))
        return ' '.join(parts)

    def type_name(self) -> TypedefTypeName:
        return TypedefTypeName(self.name, self.qualifiers)

    def sizeof(self) -> int:
        return self.type.sizeof()

    def read(self, buffer: bytes, offset: int = 0) -> Any:
        return self.type.read(buffer, offset)

    def pretty(self, value: Any, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')',
                     self.type.pretty(value, cast=False)]
            return ''.join(parts)
        else:
            return self.type.pretty(value, cast=False)



class PointerType(Type):
    def __init__(self, size: int, type: Type,
                 qualifiers: Optional[Set[str]] = None) -> None:
        super().__init__(qualifiers)
        self.size = size
        self.type = type

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

    def read(self, buffer: bytes, offset: int = 0) -> int:
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return int.from_bytes(buffer[offset:offset + self.size], sys.byteorder)

    def pretty(self, value: Any, cast: bool = True) -> str:
        if cast:
            parts = ['(', str(self.type_name()), ')', hex(value)]
            return ''.join(parts)
        else:
            return hex(value)


class ArrayType(Type):
    def __init__(self, type: Type, size: Optional[int] = None) -> None:
        self.type = type
        self.size = size

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.type!r}, {self.size!r})'

    def type_name(self) -> ArrayTypeName:
        return ArrayTypeName(self.type.type_name(), self.size)

    def sizeof(self) -> int:
        if self.size is None:
            raise ValueError("can't get size of incomplete array type")
        return self.size * self.type.sizeof()

    def read(self, buffer: bytes, offset: int = 0) -> List:
        if not self.size:
            return []
        element_size = self.type.sizeof()
        size = self.size * element_size
        if len(buffer) - offset < size:
            raise ValueError(f'buffer must be at least {size} bytes')
        return [
            self.type.read(buffer, offset + i * element_size)
            for i in range(self.size)
        ]

    def pretty(self, value: List, cast: bool = True) -> str:
        if (self.size or 0) != len(value):
            raise ValueError('list size does not match type size')
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        if not self.size:
            parts.append('{}')
        else:
            elements = []
            format_element = False
            for element in reversed(value):
                format_element = format_element or bool(element)
                if format_element:
                    elements.append(self.type.pretty(element, cast=False))
            parts.append('{')
            if elements:
                parts.append('\n')
                for element in reversed(elements):
                    parts.append('\t')
                    parts.append(element)
                    parts.append(',\n')
            parts.append('}')
        return ''.join(parts)


class FunctionType(Type):
    def __init__(self, return_type: Type,
                 parameters: Optional[List[Tuple[Type, Optional[str]]]] = None,
                 variadic: bool = False) -> None:
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

    def read(self, buffer: bytes, offset: int = 0) -> Any:
        raise ValueError("can't read function")

    def pretty(self, value: Any, cast: bool = True) -> str:
        raise ValueError("can't format function")



def _from_dwarf_bit_field(dwarf_index: DwarfIndex, die: Die) -> Type:
    type_ = from_dwarf_type(dwarf_index, die.type())
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


def from_dwarf_type(dwarf_index: DwarfIndex, dwarf_type: Die,
                    qualifiers: Optional[Set[str]] = None) -> Type:
    if qualifiers is None:
        qualifiers = set()
    else:
        qualifiers = set(qualifiers)
    while True:
        if dwarf_type.tag == DW_TAG.const_type:
            qualifiers.add('const')
        elif dwarf_type.tag == DW_TAG.restrict_type:
            qualifiers.add('restrict')
        elif dwarf_type.tag == DW_TAG.volatile_type:
            qualifiers.add('volatile')
        elif dwarf_type.tag == DW_TAG.atomic_type:
            qualifiers.add('_Atomic')
        else:
            break
        dwarf_type = dwarf_type.type()

    if dwarf_type.find_flag(DW_AT.declaration):
        try:
            dwarf_type = dwarf_index.find(dwarf_type.name(), dwarf_type.tag)
        except (DwarfAttribNotFoundError, ValueError):
            pass

    if dwarf_type.tag == DW_TAG.base_type:
        encoding = dwarf_type.find_constant(DW_AT.encoding)
        size = dwarf_type.size()
        if encoding == DW_ATE.boolean:
            return BoolType(dwarf_type.name(), size, qualifiers)
        elif encoding == DW_ATE.float:
            return FloatType(dwarf_type.name(), size, qualifiers)
        elif (encoding == DW_ATE.signed or
              encoding == DW_ATE.signed_char):
            return IntType(dwarf_type.name(), size, True, qualifiers)
        elif (encoding == DW_ATE.unsigned or
              encoding == DW_ATE.unsigned_char):
            return IntType(dwarf_type.name(), size, False, qualifiers)
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
                    type_thunk = functools.partial(_from_dwarf_bit_field,
                                                   dwarf_index, child)
                else:
                    type_thunk = functools.partial(from_dwarf_type,
                                                   dwarf_index, child.type())
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
        try:
            name = dwarf_type.name()
        except DwarfAttribNotFoundError:
            name = None
        return EnumType(name, size, signed, enumerators, qualifiers)
    elif dwarf_type.tag == DW_TAG.typedef:
        return TypedefType(dwarf_type.name(),
                           from_dwarf_type(dwarf_index, dwarf_type.type()),
                           qualifiers)
    elif dwarf_type.tag == DW_TAG.pointer_type:
        size = dwarf_type.size()
        try:
            deref_type = dwarf_type.type()
        except DwarfAttribNotFoundError:
            type_: Type = VoidType()
        else:
            type_ = from_dwarf_type(dwarf_index, deref_type)
        return PointerType(size, type_, qualifiers)
    elif dwarf_type.tag == DW_TAG.array_type:
        type_ = from_dwarf_type(dwarf_index, dwarf_type.type())
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
            return_type = from_dwarf_type(dwarf_index, dwarf_type.type())
        except DwarfAttribNotFoundError:
            return_type = VoidType()
        parameters: Optional[List[Tuple[Type, Optional[str]]]] = []
        variadic = False
        for child in dwarf_type.children():
            if child.tag == DW_TAG.formal_parameter:
                if parameters is None or variadic:
                    raise DwarfFormatError('formal parameter after unspecified parameters')
                parameter_type = from_dwarf_type(dwarf_index, child.type())
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


def from_dwarf_type_name(dwarf_index: DwarfIndex,
                         type_name: Union[str, TypeName]) -> Type:
    if not isinstance(type_name, TypeName):
        type_name = parse_type_name(type_name)
    if isinstance(type_name, VoidTypeName):
        return VoidType(type_name.qualifiers)
    elif isinstance(type_name, PointerTypeName):
        type_ = from_dwarf_type_name(dwarf_index, type_name.type)
        return PointerType(dwarf_index.address_size, type_,
                           type_name.qualifiers)
    elif isinstance(type_name, ArrayTypeName):
        return ArrayType(from_dwarf_type_name(dwarf_index, type_name.type),
                         type_name.size)
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
    dwarf_type = dwarf_index.find(type_name.name, tag)
    return from_dwarf_type(dwarf_index, dwarf_type, type_name.qualifiers)
