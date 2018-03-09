from drgn.dwarf import DwarfFile, DwarfIndex
from drgn.elf import ElfFile
from drgn.type import (
    ArrayType,
    PointerType,
    TypedefType,
    TypeFactory,
)
from drgn.typename import TypeName
from drgn.util import parse_symbol_file
import itertools
import os


class CoredumpObject:
    def __init__(self, coredump, address, type_):
        self._coredump = coredump
        self._address = address
        self._type = type_
        while isinstance(type_, TypedefType):
            type_ = type_.type
        self._real_type = type_

    def __repr__(self):
        return f'CoredumpObject(address=0x{self._address:x}, type=<{self._type.type_name()}>)'

    def __str__(self):
        buffer = self._coredump.read(self._address, self._real_type.sizeof())
        return self._real_type.format(buffer)

    def _value(self):
        buffer = self._coredump.read(self._address, self._real_type.sizeof())
        return self._real_type.read(buffer)

    def _string(self):
        if isinstance(self._real_type, PointerType):
            addresses = itertools.count(self._value())
        elif isinstance(self._real_type, ArrayType):
            if self._real_type.size is None:
                addresses = itertools.count(self._address)
            else:
                addresses = range(self._address, self._address + self._real_type.size)
        else:
            raise ValueError('not an array or pointer')
        b = bytearray()
        for address in addresses:
            byte = self._coredump.read(address, 1)[0]
            if not byte:
                break
            b.append(byte)
        return bytes(b)

    def _member(self, name):
        if isinstance(self._real_type, PointerType):
            address = self._value()
            type_ = self._real_type.type
        else:
            address = self._address
            type_ = self._real_type
        member_type = type_.typeof(name)
        offset = type_.offsetof(name)
        return CoredumpObject(self._coredump, address + offset, member_type)

    def _cast(self, type):
        if isinstance(type, TypeName):
            type = self._coredump._type_factory.from_type_name(type)
        elif isinstance(type, str):
            type = self._coredump._type_factory.from_type_string(type)
        elif not isinstance(type, Type):
            raise ValueError('type must be Type, TypeName, or string')
        return CoredumpObject(self._coredump, self._address, type)

    def _containerof(self, type, member):
        if isinstance(type, TypeName):
            type = self._coredump._type_factory.from_type_name(type)
        elif isinstance(type, str):
            type = self._coredump._type_factory.from_type_string(type)
        elif not isinstance(type, Type):
            raise ValueError('type must be Type, TypeName, or string')
        if not isinstance(self._real_type, PointerType):
            raise ValueError('containerof is only valid on pointers')
        address = self._value() - type.offsetof(member)
        return CoredumpObject(self._coredump, address, type)

    def __getitem__(self, item):
        if isinstance(self._real_type, PointerType):
            buffer = self._coredump.read(self._address, self._real_type.sizeof())
            address = self._real_type.read(buffer)
            offset = item.__index__() * self._real_type.type.sizeof()
        elif isinstance(self._real_type, ArrayType):
            address = self._address
            offset = item.__index__() * self._real_type.type.sizeof()
        else:
            raise ValueError('not an array or pointer')
        return CoredumpObject(self._coredump, address + offset,
                              self._real_type.type)

    def __getattr__(self, name):
        return self._member(name)


class Coredump:
    def __init__(self, core_file, program_file, symbols=None):
        self._core_file = core_file
        self._core_elf_file = ElfFile(core_file)
        self._program_file = program_file
        self._program_dwarf_file = DwarfFile.from_file(program_file)
        self.symbols = symbols

        self._dwarf_index = DwarfIndex()
        for cu in self._program_dwarf_file.cu_headers():
            self._dwarf_index.index_cu(cu)
        self._type_factory = TypeFactory(self._dwarf_index)

    def read(self, address, size):
        for phdr in self._core_elf_file.phdrs():
            if phdr.p_vaddr <= address <= phdr.p_vaddr + phdr.p_memsz:
                break
        else:
            raise ValueError(f'could not find memory segment containing 0x{address:x}')
        return os.pread(self._core_file.fileno(), size,
                        phdr.p_offset + address - phdr.p_vaddr)

    def __getitem__(self, key):
        address = self.symbols[key][-1]
        dwarf_type = self._dwarf_index.find_variable(key).type()
        type_ = self._type_factory.from_dwarf_type(dwarf_type)
        return CoredumpObject(self, address, type_)


def kcore(vmlinux_path):
    # TODO: cleanup
    core_file = open('/proc/kcore', 'rb')
    program_file = open(vmlinux_path, 'rb')
    with open('/proc/kallsyms', 'r') as f:
        symbols = parse_symbol_file(f)
    return Coredump(core_file, program_file, symbols)
