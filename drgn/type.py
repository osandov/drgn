from drgn.typename import parse_type_name, ArrayType, PointerType, TypeSpecifier
from drgn.dwarf import DwarfAttribNotFoundError, DW_AT, DW_TAG
import re


class DrgnType:
    def __init__(self, factory, type):
        self._factory = factory
        self._type = type
        self._members = {}
        if isinstance(type, TypeSpecifier):
            assert type.dwarf_type.is_type() and not type.dwarf_type.is_qualified_type()
            # TODO: handle typedefs
            self._find_members(type.dwarf_type, 0)

    def _find_members(self, dwarf_type, offset):
        for child in dwarf_type.children():
            if child.tag == DW_TAG.member:
                child_type = child.type()
                if dwarf_type.tag == DW_TAG.union_type:
                    child_offset = 0
                else:
                    child_offset = child.find_constant(DW_AT.data_member_location)
                try:
                    name = child.name()
                except DwarfAttribNotFoundError:
                    # Anonymous struct/union
                    self._find_members(child_type, child_offset)
                else:
                    self._members[name] = (offset + child_offset, child_type)

    def __repr__(self):
        return f'DrgnType(<{self._type}>)'

    def is_pointer(self):
        return isinstance(self._type, PointerType)

    def is_array(self):
        return isinstance(self._type, ArrayType)

    def members(self):
        return [key for key, value in sorted(self._members.items(), key=lambda x: x[1][0])]

    def dereference(self):
        if isinstance(self._type, (PointerType, ArrayType)):
            return DrgnType(self._factory, self._type.type)
        else:
            raise ValueError('not a pointer or array type')

    def addressof(self):
        return DrgnType(self._factory, PointerType(self._type))

    @staticmethod
    def _sizeof(type_):
        if isinstance(type_, TypeSpecifier):
            return type_.dwarf_type.find_constant(DW_AT.byte_size)
        elif isinstance(type_, ArrayType) and type_.size is not None:
            return type_.size * DrgnType._sizeof(type_.type)
        else:
            assert isinstance(type_, (PointerType, ArrayType))
            while not isinstance(type_, TypeSpecifier):
                type_ = type_.type
            return type_.dwarf_type.cu.address_size

    def sizeof(self):
        return DrgnType._sizeof(self._type)

    def offsetof(self, member):
        return self._members[member][0]

    def typeof(self, member):
        dwarf_type = self._members[member][1]
        return self._factory.from_dwarf_type(dwarf_type)


class DrgnTypeFactory:
    def __init__(self, dwarf_index):
        self._dwarf_index = dwarf_index

    def from_name(self, name):
        type_ = parse_type_name(name)
        type_specifier = type_
        while not isinstance(type_specifier, TypeSpecifier):
            type_specifier = type_specifier.type
        match = re.fullmatch(r'(enum|struct|union) (\w+)',
                             type_specifier.data_type)
        if match:
            if match.group(1) == 'enum':
                tag = DW_TAG.enumeration_type
            elif match.group(1) == 'struct':
                tag = DW_TAG.structure_type
            else:
                tag = DW_TAG.union_type
            type_specifier.dwarf_type = self._dwarf_index.find(match.group(2), tag)
        elif type_specifier.data_type == 'void':
            type_specifier.dwarf_type = None
        else:
            try:
                type_specifier.dwarf_type = self._dwarf_index.find(type_specifier.data_type,
                                                                   DW_TAG.base_type)
            except KeyError:
                type_specifier.dwarf_type = self._dwarf_index.find(type_specifier.data_type,
                                                                   DW_TAG.typedef)
        return DrgnType(self, type_)

    def from_dwarf_type(self, dwarf_type):
        def aux(dwarf_type):
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
                return PointerType(aux(dwarf_type.type()), qualifiers)
            elif dwarf_type.tag == DW_TAG.array_type:
                assert False, 'TODO'
            else:
                if dwarf_type.find_flag(DW_AT.declaration):
                    try:
                        dwarf_type = self._dwarf_index.find(dwarf_type.name(),
                                                            dwarf_type.tag)
                    except (DwarfAttribNotFoundError, KeyError):
                        pass
                try:
                    data_type = dwarf_type.name()
                except DwarfAttribNotFoundError:
                    data_type = '<anonymous>'
                if dwarf_type.tag == DW_TAG.enumeration_type:
                    data_type = 'enum ' + data_type
                elif dwarf_type.tag == DW_TAG.structure_type:
                    data_type = 'struct ' + data_type
                elif dwarf_type.tag == DW_TAG.union_type:
                    data_type = 'union ' + data_type
                # TODO: size, sign
                type_ = TypeSpecifier(data_type, qualifiers=qualifiers)
                type_.dwarf_type = dwarf_type
                return type_
        return DrgnType(self, aux(dwarf_type))
