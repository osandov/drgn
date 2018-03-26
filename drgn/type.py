from collections import OrderedDict
from drgn.dwarf import DwarfAttribNotFoundError, DW_AT, DW_ATE, DW_TAG
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    BasicTypeName,
    EnumTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    UnionTypeName,
    VoidTypeName,
)
import enum
import functools
import re
import struct
import sys


class Type:
    def __init__(self, qualifiers=None):
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self):
        parts = [self.__class__.__name__, '(']
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
        return str(self.type_name())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def type_name(self):
        raise NotImplementedError()

    def sizeof(self):
        raise NotImplementedError()

    def read(self, buffer, offset=0):
        raise NotImplementedError()

    def format(self, buffer, offset=0, *, cast=True):
        raise NotImplementedError()


class VoidType(Type):
    def type_name(self):
        return VoidTypeName(self.qualifiers)

    def sizeof(self):
        raise ValueError("can't get size of void")

    def read(self, buffer, offset=0):
        raise ValueError("can't read void")

    def format(self, buffer, offset=0, *, cast=True):
        raise ValueError("can't read void")


class BasicType(Type):
    def __init__(self, name, size, qualifiers=None):
        super().__init__(qualifiers)
        self.name = name
        self.size = size

    def __repr__(self):
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

    def type_name(self):
        return BasicTypeName(self.name, self.qualifiers)

    def sizeof(self):
        return self.size

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        parts.append(str(self.read(buffer, offset)))
        return ''.join(parts)


class IntType(BasicType):
    def __init__(self, name, size, signed, qualifiers=None):
        super().__init__(name, size, qualifiers)
        self.signed = signed

    def __repr__(self):
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

    def read(self, buffer, offset=0):
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return int.from_bytes(buffer[offset:offset + self.size], sys.byteorder,
                              signed=self.signed)


class BoolType(BasicType):
    def read(self, buffer, offset=0):
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return bool(int.from_bytes(buffer[offset:offset + self.size],
                                   sys.byteorder))

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self), ')']
        else:
            parts = []
        parts.append(str(int(self.read(buffer, offset))))
        return ''.join(parts)


class FloatType(BasicType):
    def read(self, buffer, offset=0):
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
    def __init__(self, type, bit_offset, bit_size):
        self.type = type
        self.bit_offset = bit_offset
        self.bit_size = bit_size

    def __repr__(self):
        parts = [
            self.__class__.__name__, '(',
            repr(self.type), ', ',
            repr(self.bit_offset), ', ',
            repr(self.bit_size), ')',
        ]
        return ''.join(parts)

    def __str__(self):
        parts = [str(self.type.type_name()), ':', repr(self.bit_size)]
        return ' '.join(parts)

    def type_name(self):
        raise ValueError("can't get type of bit field")

    def sizeof(self):
        # Not really, but for convenience.
        return (self.bit_offset + self.bit_size + 7) // 8

    def read(self, buffer, offset=0):
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

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self.type.type_name()), ')']
        else:
            parts = []
        parts.append(str(self.read(buffer, offset)))
        return ''.join(parts)


class CompoundType(Type):
    def __init__(self, name, size, members, qualifiers=None):
        super().__init__(qualifiers)
        # List of name, offset, type_thunk. type_thunk is a callable taking no
        # parameters which returns the type of the member. This lets us lazily
        # evaluate member types, which is necessary because structs may be very
        # deeply nested.
        self.name = name
        self.size = size
        self._members = members
        self._members_by_name = OrderedDict()
        if members:
            self._index_members_by_name(members, 0)

    def _index_members_by_name(self, members, offset):
        for name, member_offset, type_thunk in members:
            if name:
                self._members_by_name[name] = (offset + member_offset, type_thunk)
            else:
                self._index_members_by_name(type_thunk()._members,
                                            offset + member_offset)

    def _eager_members(self):
        if self._members is None:
            return None
        return [
            (name, offset, type_thunk()) for name, offset, type_thunk in
            self._members
        ]

    def __repr__(self):
        parts = [
            self.__class__.__name__, '(',
            repr(self.name), ', ',
            repr(self.size), ', ',
            repr(self._eager_members()),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
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
                        member_type_name = member_type.type.type_name()
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

    def _dict_for_eq(self):
        # Compare the result of the type thunks rather than the thunks
        # themselves. __eq__ is only used for testing, so it's okay to eagerly
        # evaluate the struct member types.
        d = dict(self.__dict__)
        d['_members'] = self._eager_members()
        del d['_members_by_name']
        return d

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._dict_for_eq() == other._dict_for_eq())

    def sizeof(self):
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size

    def read(self, buffer, offset=0):
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return OrderedDict([
            (name, type_thunk().read(buffer, offset + member_offset))
            for name, (member_offset, type_thunk) in self._members_by_name.items()
        ])

    def format(self, buffer, offset=0, *, cast=True):
        if cast and self.name:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        parts.append('{\n')
        for name, (member_offset, type_thunk) in self._members_by_name.items():
            parts.append('\t.')
            parts.append(name)
            parts.append(' = ')
            member_format = type_thunk().format(buffer, offset + member_offset)
            parts.append(member_format.replace('\n', '\n\t'))
            parts.append(',\n')
        parts.append('}')
        return ''.join(parts)

    def members(self):
        return list(self._members_by_name)

    def offsetof(self, member):
        return self._members_by_name[member][0]

    def typeof(self, member):
        return self._members_by_name[member][1]()


class StructType(CompoundType):
    def type_name(self):
        return StructTypeName(self.name, self.qualifiers)


class UnionType(CompoundType):
    def type_name(self):
        return UnionTypeName(self.name, self.qualifiers)


class EnumType(Type):
    def __init__(self, name, size, signed, enumerators, qualifiers=None):
        super().__init__(qualifiers)
        self.name = name
        self.size = size
        self.signed = signed
        if enumerators is None:
            self._enum = None
        else:
            self._enum = enum.IntEnum('' if name is None else name,
                                      OrderedDict(enumerators))

    def __repr__(self):
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

    def __str__(self):
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

    def _dict_for_eq(self):
        d = dict(self.__dict__)
        if d['_enum'] is not None:
            d['_enum'] = d['_enum'].__members__
        return d

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._dict_for_eq() == other._dict_for_eq())

    def type_name(self):
        return EnumTypeName(self.name, self.qualifiers)

    def sizeof(self):
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size

    def read(self, buffer, offset=0):
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

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        value = self.read(buffer, offset)
        if isinstance(value, self._enum):
            parts.append(value._name_)
        else:
            parts.append(str(value))
        return ''.join(parts)


class TypedefType(Type):
    def __init__(self, name, type, qualifiers=None):
        super().__init__(qualifiers)
        self.name = name
        self.type = type

    def __repr__(self):
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

    def __str__(self):
        parts = sorted(self.qualifiers)  # Not real C syntax, but it gets the point across
        parts.append('typedef')
        parts.append(self.type.type_name().declaration(self.name))
        return ' '.join(parts)

    def type_name(self):
        return TypedefTypeName(self.name, self.qualifiers)

    def sizeof(self):
        return self.type.sizeof()

    def read(self, buffer, offset=0):
        return self.type.read(buffer, offset)

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        parts.append(self.type.format(buffer, offset, cast=False))
        return ''.join(parts)


class PointerType(Type):
    def __init__(self, size, type, qualifiers=None):
        super().__init__(qualifiers)
        self.size = size
        self.type = type

    def __repr__(self):
        parts = [
            self.__class__.__name__, '(',
            repr(self.type), ', ',
            repr(self.size),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def type_name(self):
        return PointerTypeName(self.type.type_name(), self.qualifiers)

    def sizeof(self):
        return self.size

    def read(self, buffer, offset=0):
        if len(buffer) - offset < self.size:
            raise ValueError(f'buffer must be at least {self.size} bytes')
        return int.from_bytes(buffer[offset:offset + self.size], sys.byteorder)

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self), ')']
        else:
            parts = []
        parts.append(hex(self.read(buffer, offset)))
        return ''.join(parts)


class ArrayType(Type):
    def __init__(self, type, size=None):
        self.type = type
        self.size = size

    def __repr__(self):
        return f'{self.__class__.__name__}({self.type!r}, {self.size!r})'

    def type_name(self):
        return ArrayTypeName(self.type.type_name(), self.size)

    def sizeof(self):
        if self.size is None:
            raise ValueError("can't get size of incomplete array type")
        return self.size * self.type.sizeof()

    def read(self, buffer, offset=0):
        if self.size is None:
            raise ValueError("can't read incomplete array type")
        element_size = self.type.sizeof()
        size = self.size * element_size
        if len(buffer) - offset < size:
            raise ValueError(f'buffer must be at least {size} bytes')
        return [
            self.type.read(buffer, offset + i * element_size)
            for i in range(self.size)
        ]

    def format(self, buffer, offset=0, *, cast=True):
        if cast:
            parts = ['(', str(self.type_name()), ')']
        else:
            parts = []
        if self.size is None:
            parts.append('{}')
        else:
            element_size = self.type.sizeof()
            size = self.size * element_size
            if len(buffer) - offset < size:
                raise ValueError(f'buffer must be at least {size} bytes')
            elements = []
            format_element = False
            for i in range(self.size - 1, -1, -1):
                element_offset = offset + i * element_size
                if not format_element:
                    for byte_offset in range(element_offset,
                                             element_offset + element_size):
                        if buffer[byte_offset]:
                            format_element = True
                            break
                if format_element:
                    elements.append(self.type.format(buffer, element_offset,
                                                     cast=False))

            parts.append('{')
            if elements:
                parts.append('\n')
                for element in reversed(elements):
                    parts.append('\t')
                    parts.append(element)
                    parts.append(',\n')
            parts.append('}')
        return ''.join(parts)


class TypeFactory:
    def __init__(self, dwarf_index):
        self._dwarf_index = dwarf_index

    def _from_dwarf_bit_field(self, die):
        type_ = self.from_dwarf_type(die.type())
        bit_size = die.find_constant(DW_AT.bit_size)
        try:
            bit_offset = die.find_constant(DW_AT.data_bit_offset)
        except DwarfAttribNotFoundError:
            bit_offset = (8 * type_.sizeof() - bit_size -
                          die.find_constant(DW_AT.bit_offset))
        return BitFieldType(type_, bit_offset, bit_size)

    def from_dwarf_type(self, dwarf_type, qualifiers=None):
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
                dwarf_type = self._dwarf_index.find(dwarf_type.name(),
                                                    dwarf_type.tag)
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
                        type_thunk = functools.partial(self._from_dwarf_bit_field,
                                                       child)
                    else:
                        type_thunk = functools.partial(self.from_dwarf_type,
                                                       child.type())
                    members.append((name, offset, type_thunk))
            try:
                name = dwarf_type.name()
            except DwarfAttribNotFoundError:
                name = None
            if dwarf_type.tag == DW_TAG.structure_type:
                return StructType(name, size, members, qualifiers)
            else:
                return UnionType(name, size, members, qualifiers)
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
                               self.from_dwarf_type(dwarf_type.type()),
                               qualifiers)
        elif dwarf_type.tag == DW_TAG.pointer_type:
            size = dwarf_type.size()
            try:
                deref_type = dwarf_type.type()
            except DwarfAttribNotFoundError:
                type_ = VoidType()
            else:
                type_ = self.from_dwarf_type(deref_type)
            return PointerType(size, type_, qualifiers)
        elif dwarf_type.tag == DW_TAG.array_type:
            type_ = self.from_dwarf_type(dwarf_type.type())
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
            return PointerType(self._dwarf_index.address_size, VoidType(),
                               qualifiers)
        else:
            raise NotImplementedError(DW_TAG.str(dwarf_type.tag))

    def from_type_name(self, type_name):
        if isinstance(type_name, VoidTypeName):
            return VoidType(type_name.qualifiers)
        elif isinstance(type_name, PointerTypeName):
            type_ = self.from_type_name(type_name.type)
            return PointerType(self._dwarf_index.address_size, type_,
                               type_name.qualifiers)
        elif isinstance(type_name, ArrayTypeName):
            return ArrayType(self.from_type_name(type_name.type),
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
        dwarf_type = self._dwarf_index.find(type_name.name, tag)
        return self.from_dwarf_type(dwarf_type, type_name.qualifiers)

    def from_type_string(self, s):
        return self.from_type_name(parse_type_name(s))
