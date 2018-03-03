from drgn.dwarf import (
    DwarfFile, DwarfIndex, DwarfAttribNotFoundError, DW_AT, DW_ATE, DW_TAG,
)
from drgn.elf import ElfFile
from drgn.type import (
    PointerType,
    TypeFactory,
)
from drgn.util import parse_symbol_file
import os


class CoredumpObject:
    def __init__(self, coredump, address, type_):
        self._coredump = coredump
        self._address = address
        self._type = type_

    def __repr__(self):
        return f'CoredumpObject(address=0x{self._address:x}, type=<{self._type.type_name()}>)'

    def _value(self):
        # TODO: this should be implemented by the Type classes
        if isinstance(self._type, PointerType):
            size = self._type.sizeof()
            address = int.from_bytes(self._coredump.read(self._address, size),
                                     'little')
            return CoredumpObject(self._coredump, address, self._type.type)
        else:
            # char, int, float, double, _Bool, _Complex: return as Python value
            dwarf_type = self._type._dwarf_type
            if dwarf_type.tag == DW_TAG.base_type:
                encoding = dwarf_type.find_constant(DW_AT.encoding)
                size = dwarf_type.find_constant(DW_AT.byte_size)
                b = self._coredump.read(self._address, size)
                if encoding == DW_ATE.signed:
                    return int.from_bytes(b, 'little', signed=True)
                elif encoding == DW_ATE.unsigned:
                    size = dwarf_type.find_constant(DW_AT.byte_size)
                    return int.from_bytes(b, 'little')
                else:
                    raise NotImplementedError()
            else:
                raise NotImplementedError()

    def _member(self, name):
        if isinstance(self._type, PointerType):
            size = self._type.sizeof()
            address = int.from_bytes(self._coredump.read(self._address, size),
                                     'little')
            type_ = self._type.type
        else:
            address = self._address
            type_ = self._type
        member_type = type_.typeof(name)
        offset = type_.offsetof(name)
        return CoredumpObject(self._coredump, address + offset, member_type)

    def __getattr__(self, name):
        return self._member(name)


class Coredump:
    def __init__(self, core_file, program_file, symbols=None):
        self._core_file = core_file
        self._core_elf_file = ElfFile(core_file)
        self._program_file = program_file
        program_elf_file = ElfFile(program_file)
        self._program_dwarf_file = DwarfFile(program_file, program_elf_file.sections)
        self.symbols = symbols

        self._dwarf_index = DwarfIndex()
        for cu in self._program_dwarf_file.cu_headers():
            self._dwarf_index.index_cu(cu)
        self._type_factory = TypeFactory(self._dwarf_index)

    def read(self, address, size):
        for phdr in self._core_elf_file.phdrs:
            if phdr.p_vaddr <= address <= phdr.p_vaddr + phdr.p_memsz:
                break
        else:
            raise ValueError(f'could not find memory segment containing 0x{address:x}')
        return os.pread(self._core_file.fileno(), size,
                        phdr.p_offset + address - phdr.p_vaddr)


    def __getitem__(self, key):
        address = self.symbols[key][-1].address
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
