from collections import OrderedDict
from drgn.dwarf import DwarfAttribNotFoundError, DW_AT, DW_ATE, DW_TAG
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    EnumTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
)
import functools
import re


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


class VoidType(Type):
    def type_name(self):
        return TypeName('void')

    def sizeof(self):
        raise ValueError("can't get size of void")


class BaseType(Type):
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
        return TypeName(self.name, self.qualifiers)

    def sizeof(self):
        return self.size


class IntType(BaseType):
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


class BoolType(BaseType):
    pass


class FloatType(BaseType):
    pass


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
        raise ValueError("can't get size of bit field")


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
    def __init__(self, name, size, enumerators, qualifiers=None):
        super().__init__(qualifiers)
        self.name = name
        self.size = size
        self._enumerators = enumerators

    def __str__(self):
        parts = [str(self.type_name())]
        if self._enumerators is not None:
            parts.append(' {\n')
            for name, value in self._enumerators:
                parts.append('\t')
                parts.append(name)
                parts.append(' = ')
                parts.append(str(value))
                parts.append(',\n')
            parts.append('}')
        return ''.join(parts)

    def type_name(self):
        return EnumTypeName(self.name, self.qualifiers)

    def sizeof(self):
        if self.size is None:
            raise ValueError("can't get size of incomplete type")
        return self.size


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


class ArrayType(Type):
    def __init__(self, type, length=None):
        self.type = type
        self.length = length

    def __repr__(self):
        return f'{self.__class__.__name__}({self.type!r}, {self.length!r})'

    def type_name(self):
        return ArrayTypeName(self.type.type_name(), self.length)

    def sizeof(self):
        if self.length is None:
            raise ValueError("can't get size of incomplete array type")
        return self.length * self.type.sizeof()


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

    def from_dwarf_type(self, dwarf_type):
        qualifiers = set()
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
            except (DwarfAttribNotFoundError, KeyError):
                pass

        if dwarf_type.tag == DW_TAG.base_type:
            encoding = dwarf_type.find_constant(DW_AT.encoding)
            size = dwarf_type.find_constant(DW_AT.byte_size)
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
                size = dwarf_type.find_constant(DW_AT.byte_size)
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
                    if DW_AT.bit_size in child:
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
                enumerators = None
            else:
                size = dwarf_type.find_constant(DW_AT.byte_size)
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
            return EnumType(name, size, enumerators, qualifiers)
        elif dwarf_type.tag == DW_TAG.typedef:
            return TypedefType(dwarf_type.name(),
                               self.from_dwarf_type(dwarf_type.type()),
                               qualifiers)
        elif dwarf_type.tag == DW_TAG.pointer_type:
            size = dwarf_type.find_constant(DW_AT.byte_size)
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
        else:
            raise NotImplementedError(DW_TAG.str(dwarf_type.tag))
