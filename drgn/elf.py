# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import struct
from typing import BinaryIO, List, NamedTuple


class ElfFormatError(Exception):
    pass


EI_MAG0 = 0
ELFMAG0 = 0x7f
EI_MAG1 = 1
ELFMAG1 = 0x45
EI_MAG2 = 2
ELFMAG2 = 0x4c
EI_MAG3 = 3
ELFMAG3 = 0x46
EI_CLASS = 4
ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASSNUM = 3
EI_DATA = 5
ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2
ELFDATANUM = 3
EI_VERSION = 6
EV_CURRENT = 1


class Elf_Ehdr(NamedTuple):
    e_ident: bytes
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


class Elf_Phdr(NamedTuple):
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


def parse_elf_phdrs(file: BinaryIO) -> List[Elf_Phdr]:
    file.seek(0)
    buf = file.read(64)  # sizeof(struct Elf64_Ehdr)

    if (buf[EI_MAG0] != ELFMAG0 or buf[EI_MAG1] != ELFMAG1 or
        buf[EI_MAG2] != ELFMAG2 or buf[EI_MAG3] != ELFMAG3):
        raise ValueError('not an ELF file')

    if buf[EI_VERSION] != EV_CURRENT:
        raise ValueError('ELF version is not EV_CURRENT')

    if buf[EI_DATA] == ELFDATA2LSB:
        fmt = '<'
    elif buf[EI_DATA] == ELFDATA2MSB:
        fmt = '>'
    else:
        raise ValueError(f'unknown ELF data encoding {buf[EI_DATA]}')

    if buf[EI_CLASS] == ELFCLASS64:
        fmt += '16sHHLQQQLHHHHHH'
    elif buf[EI_CLASS] == ELFCLASS32:
        raise NotImplementedError('32-bit ELF is not implemented')
    else:
        raise ValueError(f'unknown ELF class {buf[EI_CLASS]}')

    ehdr =  Elf_Ehdr._make(struct.unpack_from(fmt, buf))

    file.seek(ehdr.e_phoff)
    buf = file.read(ehdr.e_phnum * ehdr.e_phentsize)

    if ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
        fmt = '<'
    else:
        fmt = '>'

    if ehdr.e_ident[EI_CLASS] == ELFCLASS64:
        fmt += 'LLQQQQQQ'
    else:
        assert False
    return [Elf_Phdr._make(x) for x in struct.iter_unpack(fmt, buf)]
