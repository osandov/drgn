from collections import OrderedDict
from drgn.dwarf import DwarfAttribNotFoundError, DW_AT, DW_TAG
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
import operator
import re


class Type:
    def __init__(self, factory, dwarf_type, qualifiers=None):
        self._factory = factory
        self._dwarf_type = dwarf_type
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self):
        parts = [
            self.__class__.__name__, '(',
            repr(self._factory), ', ',
            repr(self._dwarf_type),
        ]
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
        return self._dwarf_type.find_constant(DW_AT.byte_size)


class BaseType(Type):
    def type_name(self):
        return TypeName(self._dwarf_type.name(), self.qualifiers)


class VoidType(Type):
    def __init__(self):
        pass

    def __repr__(self):
        return 'VoidType()'

    def __str__(self):
        return 'void'

    def type_name(self):
        return TypeName('void')

    def sizeof(self):
        raise ValueError("can't get size of void")


class CompoundType(Type):
    def __init__(self, factory, dwarf_type, qualifiers=None):
        super().__init__(factory, dwarf_type, qualifiers)
        self._members = OrderedDict()
        self._find_members(self._dwarf_type, 0)

    def _find_members(self, dwarf_type, offset):
        for child in dwarf_type.children():
            if child.tag == DW_TAG.member:
                child_type = child.type()
                try:
                    child_offset = child.find_constant(DW_AT.data_member_location)
                except DwarfAttribNotFoundError:
                    # TODO: bit offset
                    child_offset = 0
                try:
                    name = child.name()
                except DwarfAttribNotFoundError:
                    # Unnamed member.
                    self._find_members(child_type, child_offset)
                else:
                    self._members[name] = (offset + child_offset, child_type)

    def __str__(self):
        type_name = self.type_name()
        parts = sorted(type_name.qualifiers)
        if parts:
            parts.append(' ')
        parts.append(type_name.TAG)
        if type_name.name:
            parts.append(' ')
            parts.append(type_name.name)
        parts.append(' {\n')
        for child in self._dwarf_type.children():
            if child.tag != DW_TAG.member:
                continue
            try:
                name = child.name()
            except DwarfAttribNotFoundError:
                name = None
            dwarf_type = child.type()
            member_type = self._factory.from_dwarf_type(dwarf_type)
            member_type_name = member_type.type_name()
            if (isinstance(member_type, (StructType, UnionType, EnumType)) and
                    not member_type_name.name):
                decl = re.sub('^', '\t', str(member_type), flags=re.MULTILINE)
                parts.append(decl)
                if name:
                    parts.append(' ')
                    parts.append(name)
            else:
                parts.append('\t')
                parts.append(member_type_name.declaration(name))
            try:
                bit_size = child.find_constant(DW_AT.bit_size)
            except DwarfAttribNotFoundError:
                pass
            else:
                parts.append(' : ')
                parts.append(str(bit_size))
            parts.append(';\n')
        parts.append('}')
        return ''.join(parts)

    def members(self):
        return list(self._members)

    def offsetof(self, member):
        return self._members[member][0]

    def typeof(self, member):
        dwarf_type = self._members[member][1]
        return self._factory.from_dwarf_type(dwarf_type)


class StructType(CompoundType):
    def type_name(self):
        try:
            name = self._dwarf_type.name()
        except DwarfAttribNotFoundError:
            name = None
        return StructTypeName(name, self.qualifiers)


class UnionType(CompoundType):
    def type_name(self):
        try:
            name = self._dwarf_type.name()
        except DwarfAttribNotFoundError:
            name = None
        return UnionTypeName(name, self.qualifiers)


class EnumType(Type):
    def __str__(self):
        type_name = self.type_name()
        parts = sorted(type_name.qualifiers)
        if parts:
            parts.append(' ')
        parts.append('enum')
        if type_name.name:
            parts.append(' ')
            parts.append(type_name.name)
        parts.append(' {\n')
        for child in self._dwarf_type.children():
            if child.tag != DW_TAG.enumerator:
                continue
            name = child.name()
            value = child.find_constant(DW_AT.const_value)
            parts.append('\t')
            parts.append(name)
            parts.append(' = ')
            parts.append(str(value))
            parts.append(',\n')
        parts.append('}')
        return ''.join(parts)

    def type_name(self):
        try:
            name = self._dwarf_type.name()
        except DwarfAttribNotFoundError:
            name = None
        return EnumTypeName(name, self.qualifiers)


class TypedefType(Type):
    def __init__(self, type, name, qualifiers=None):
        self.type = type
        self.name = name
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self):
        parts = [
            self.__class__.__name__, '(',
            repr(self.type), ', ',
            repr(self.name),
        ]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
        return 'typedef ' + self.type.type_name().declaration(self.name)

    def type_name(self):
        return TypedefTypeName(self.name, self.qualifiers)

    def sizeof(self):
        return self.type.sizeof()


class PointerType(Type):
    def __init__(self, type, size, qualifiers=None):
        self.type = type
        self._size = size
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

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
        return self._size


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


class TypeFactory:
    def __init__(self, dwarf_index):
        self._dwarf_index = dwarf_index

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
        if dwarf_type.tag == DW_TAG.pointer_type:
            size = dwarf_type.find_constant(DW_AT.byte_size)
            try:
                deref_type = dwarf_type.type()
            except DwarfAttribNotFoundError:
                type_ = VoidType()
            else:
                type_ = self.from_dwarf_type(deref_type)
            return PointerType(type_, size, qualifiers)
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
        elif dwarf_type.tag == DW_TAG.typedef:
            return TypedefType(self.from_dwarf_type(dwarf_type.type()),
                               dwarf_type.name(), qualifiers)
        else:
            if dwarf_type.find_flag(DW_AT.declaration):
                try:
                    dwarf_type = self._dwarf_index.find(dwarf_type.name(),
                                                        dwarf_type.tag)
                except (DwarfAttribNotFoundError, KeyError):
                    pass
            if dwarf_type.tag == DW_TAG.base_type:
                return BaseType(self, dwarf_type, qualifiers)
            elif dwarf_type.tag == DW_TAG.structure_type:
                return StructType(self, dwarf_type, qualifiers)
            elif dwarf_type.tag == DW_TAG.union_type:
                return UnionType(self, dwarf_type, qualifiers)
            elif dwarf_type.tag == DW_TAG.enumeration_type:
                return EnumType(self, dwarf_type, qualifiers)
            else:
                raise NotImplementedError()
