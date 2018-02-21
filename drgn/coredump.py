from drgn.dwarf import DwarfFile, DwarfAttribNotFoundError, DW_AT, DW_ATE, DW_TAG
from drgn.elf import ElfFile
from drgn.util import parse_symbol_file
import os


TYPE_QUALIFIERS = {
    DW_TAG.const_type: 'const',
    DW_TAG.restrict_type: 'restrict',
    DW_TAG.volatile_type: 'volatile',
}


STRUCTURE_TYPES = {
    DW_TAG.enumeration_type: 'enum',
    DW_TAG.structure_type: 'struct',
    DW_TAG.union_type: 'union',
}


def dwarf_type_str(dwarf_type):
    if dwarf_type.tag in TYPE_QUALIFIERS:
        return TYPE_QUALIFIERS[dwarf_type.tag] + ' ' + dwarf_type_str(dwarf_type.type())
    elif dwarf_type.tag == DW_TAG.pointer_type:
        return dwarf_type_str(dwarf_type.type()) + ' *'
    elif dwarf_type.tag == DW_TAG.base_type or dwarf_type.tag == DW_TAG.typedef:
        return dwarf_type.name()
    elif dwarf_type.tag in STRUCTURE_TYPES:
        keyword = STRUCTURE_TYPES[dwarf_type.tag]
        try:
            return f'{keyword} {dwarf_type.name()}'
        except DwarfAttribNotFoundError:
            return f'{keyword} <anonymous>'
    else:
        return 'TODO'


def _parse_members(members, dwarf_type, offset):
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
                _parse_members(members, child_type, child_offset)
            else:
                members[name] = (offset + child_offset, child_type)


class CoredumpObject:
    def __init__(self, coredump, address, dwarf_type):
        self.coredump = coredump
        self.address = address
        self.dwarf_type = dwarf_type
        self.unqualified_dwarf_type = dwarf_type.unqualified()
        self._members = {}
        members_type = self.unqualified_dwarf_type
        if members_type.tag == DW_TAG.pointer_type:
            members_type = coredump._resolve_type(members_type.type().unqualified())
        _parse_members(self._members, members_type, 0)

    def __repr__(self):
        return f'CoredumpObject(address=0x{self.address:x}, dwarf_type=<{dwarf_type_str(self.dwarf_type)}>)'

    def _read(self, offset, size):
        address = self.address + offset
        phdr = self.coredump._address_phdr(address)
        # TODO: check for EFAULT
        return os.pread(self.coredump.core_file.fileno(), size, phdr.p_offset + address - phdr.p_vaddr)

    def _value(self):
        # TODO: endianness
        if self.unqualified_dwarf_type.tag == DW_TAG.base_type:
            encoding = self.unqualified_dwarf_type.find_constant(DW_AT.encoding)
            if encoding == DW_ATE.signed:
                size = self.unqualified_dwarf_type.find_constant(DW_AT.byte_size)
                return int.from_bytes(self._read(0, size), 'little', signed=True)
            elif encoding == DW_ATE.unsigned:
                size = self.unqualified_dwarf_type.find_constant(DW_AT.byte_size)
                return int.from_bytes(self._read(0, size), 'little')
            else:
                raise NotImplementedError()
        elif self.unqualified_dwarf_type.tag == DW_TAG.pointer_type:
            size = self.unqualified_dwarf_type.find_constant(DW_AT.byte_size)
            address = int.from_bytes(self._read(0, size), 'little')
            return CoredumpObject(self.coredump, address, unqualified_type(self.unqualified_dwarf_type.type()))
        elif (self.unqualified_dwarf_type.tag == DW_TAG.structure_type or
                self.unqualified_dwarf_type.tag == DW_TAG.union_type):
            return self
        else:
            raise NotImplementedError()

    def _member(self, name):
        if self.unqualified_dwarf_type.tag == DW_TAG.pointer_type:
            size = self.unqualified_dwarf_type.find_constant(DW_AT.byte_size)
            address = int.from_bytes(self._read(0, size), 'little')
        else:
            address = self.address
        offset, dwarf_type = self._members[name]
        return CoredumpObject(self.coredump, address + offset, dwarf_type)

    def __getattr__(self, name):
        return self._member(name)


class Coredump:
    def __init__(self, core_file, program_file, symbols=None):
        self.core_file = core_file
        self.core_elf_file = ElfFile(core_file)
        self.program_file = program_file
        program_elf_file = ElfFile(program_file)
        self.program_dwarf_file = DwarfFile(program_file, program_elf_file.sections)
        self.symbols = symbols

        self.cu_headers = self.program_dwarf_file.cu_headers()
        self._global_variables = {}
        self._types = {}
        for cu in self.cu_headers:
            die = cu.die()
            for child in die.children():
                if child.tag == DW_TAG.variable:
                    try:
                        name = child.name()
                    except DwarfAttribNotFoundError:
                        continue
                    self._global_variables[name] = child
                elif child.is_type() and not child.find_flag(DW_AT.declaration):
                    try:
                        name = child.name()
                    except DwarfAttribNotFoundError:
                        continue
                    self._types[child.tag, name] = child

    def _address_phdr(self, address):
        # TODO: sort and binary search
        for phdr in self.core_elf_file.phdrs:
            if phdr.p_vaddr <= address <= phdr.p_vaddr + phdr.p_memsz:
                return phdr
        else:
            raise ValueError(f'could not find memory segment containing 0x{address:x}')

    def _resolve_type(self, dwarf_type):
        if dwarf_type.find_flag(DW_AT.declaration):
            try:
                dwarf_type = self._types[dwarf_type.tag, dwarf_type.name()]
            except (DwarfAttribNotFoundError, KeyError):
                pass
        return dwarf_type

    def __getitem__(self, key):
        address = self.symbols[key][-1].address
        dwarf_type = self._global_variables[key].type()
        return CoredumpObject(self, address, dwarf_type)


def kcore(vmlinux_path):
    # TODO: cleanup
    core_file = open('/proc/kcore', 'rb')
    program_file = open(vmlinux_path, 'rb')
    with open('/proc/kallsyms', 'r') as f:
        symbols = parse_symbol_file(f)
    return Coredump(core_file, program_file, symbols)
