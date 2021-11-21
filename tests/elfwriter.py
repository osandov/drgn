# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import struct
from typing import List, NamedTuple, Optional, Sequence

from tests.elf import ET, PT, SHN, SHT, STB, STT, STV


class ElfSection:
    def __init__(
        self,
        data: bytes,
        name: Optional[str] = None,
        sh_type: Optional[SHT] = None,
        p_type: Optional[PT] = None,
        vaddr: int = 0,
        paddr: int = 0,
        memsz: Optional[int] = None,
        p_align: int = 0,
        sh_link: int = 0,
        sh_info: int = 0,
        sh_entsize: int = 0,
    ):
        self.data = data
        self.name = name
        self.sh_type = sh_type
        self.p_type = p_type
        self.vaddr = vaddr
        self.paddr = paddr
        self.memsz = memsz
        self.p_align = p_align
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_entsize = sh_entsize

        assert (self.name is not None) or (self.p_type is not None)
        assert (self.name is None) == (self.sh_type is None)
        if self.p_type is None:
            assert self.memsz is None
        elif self.memsz is None:
            self.memsz = len(self.data)


class ElfSymbol(NamedTuple):
    name: str
    value: int
    size: int
    type: STT
    binding: STB
    shindex: Optional[int] = None
    visibility: STV = STV.DEFAULT

    def st_info(self) -> int:
        return (self.binding << 4) + (self.type & 0xF)


def _create_symtab(
    sections: List[ElfSection],
    symbols: Sequence[ElfSymbol],
    little_endian: bool,
    bits: int,
):
    assert not any(section.name in (".symtab", ".strtab") for section in sections)

    endian = "<" if little_endian else ">"
    if bits == 64:
        symbol_struct = struct.Struct(endian + "IBBHQQ")

        def symbol_fields(sym: ElfSymbol):
            return (
                sym.st_info(),
                sym.visibility,
                SHN.UNDEF if sym.shindex is None else sym.shindex,
                sym.value,
                sym.size,
            )

    else:
        symbol_struct = struct.Struct(endian + "IIIBBH")

        def symbol_fields(sym: ElfSymbol):
            return (
                sym.value,
                sym.size,
                sym.st_info(),
                sym.visibility,
                SHN.UNDEF if sym.shindex is None else sym.shindex,
            )

    symtab_data = bytearray((len(symbols) + 1) * symbol_struct.size)
    strtab_data = bytearray(1)
    sh_info = 1
    for i, sym in enumerate(symbols, 1):
        symbol_struct.pack_into(
            symtab_data, i * symbol_struct.size, len(strtab_data), *symbol_fields(sym)
        )
        strtab_data.extend(sym.name.encode())
        strtab_data.append(0)
        if sym.binding == STB.LOCAL:
            assert sh_info == i, "local symbol after non-local symbol"
            sh_info = i + 1

    sections.append(
        ElfSection(
            name=".symtab",
            sh_type=SHT.SYMTAB,
            data=symtab_data,
            sh_link=sum((1 for section in sections if section.name is not None), 2),
            sh_info=sh_info,
            sh_entsize=symbol_struct.size,
        )
    )
    sections.append(ElfSection(name=".strtab", sh_type=SHT.STRTAB, data=strtab_data))


def create_elf_file(
    type: ET,
    sections: Sequence[ElfSection],
    symbols: Sequence[ElfSymbol] = (),
    little_endian: bool = True,
    bits: int = 64,
):
    endian = "<" if little_endian else ">"
    if bits == 64:
        ehdr_struct = struct.Struct(endian + "16BHHIQQQIHHHHHH")
        shdr_struct = struct.Struct(endian + "IIQQQQIIQQ")
        phdr_struct = struct.Struct(endian + "IIQQQQQQ")
        e_machine = 62 if little_endian else 43  # EM_X86_64 or EM_SPARCV9
    else:
        assert bits == 32
        ehdr_struct = struct.Struct(endian + "16BHHIIIIIHHHHHH")
        shdr_struct = struct.Struct(endian + "10I")
        phdr_struct = struct.Struct(endian + "8I")
        e_machine = 3 if little_endian else 8  # EM_386 or EM_MIPS

    sections = list(sections)
    if symbols:
        _create_symtab(sections, symbols, little_endian=little_endian, bits=bits)
    shnum = 0
    phnum = 0
    shstrtab = bytearray(1)
    for section in sections:
        if section.name is not None:
            shstrtab.extend(section.name.encode())
            shstrtab.append(0)
            shnum += 1
        if section.p_type is not None:
            phnum += 1
    if shnum > 0:
        shnum += 2  # One for the SHT_NULL section, one for .shstrtab.
        shstrtab.extend(b".shstrtab\0")
        sections = list(sections)
        sections.append(ElfSection(name=".shstrtab", sh_type=SHT.STRTAB, data=shstrtab))

    shdr_offset = ehdr_struct.size
    phdr_offset = shdr_offset + shdr_struct.size * shnum
    headers_size = phdr_offset + phdr_struct.size * phnum
    buf = bytearray(headers_size)
    ehdr_struct.pack_into(
        buf,
        0,
        0x7F,  # ELFMAG0
        ord("E"),  # ELFMAG1
        ord("L"),  # ELFMAG2
        ord("F"),  # ELFMAG3
        2 if bits == 64 else 1,  # EI_CLASS = ELFCLASS64 or ELFCLASS32
        1 if little_endian else 2,  # EI_DATA = ELFDATA2LSB or ELFDATA2MSB
        1,  # EI_VERSION = EV_CURRENT
        0,  # EI_OSABI = ELFOSABI_NONE
        0,  # EI_ABIVERSION
        0,
        0,
        0,
        0,
        0,
        0,
        0,  # EI_PAD
        type,  # e_type
        e_machine,
        1,  # e_version = EV_CURRENT
        0,  # e_entry
        phdr_offset if phnum else 0,  # e_phoff
        shdr_offset if shnum else 0,  # e_shoff
        0,  # e_flags
        ehdr_struct.size,  # e_ehsize
        phdr_struct.size,  # e_phentsize
        phnum,  # e_phnum
        shdr_struct.size,  # e_shentsize
        shnum,  # e_shnum
        shnum - 1 if shnum else 0,  # e_shstrndx
    )

    shdr_offset += shdr_struct.size
    for section in sections:
        if section.p_align:
            padding = section.vaddr % section.p_align - len(buf) % section.p_align
            buf.extend(bytes(padding))
        if section.name is not None:
            shdr_struct.pack_into(
                buf,
                shdr_offset,
                shstrtab.index(section.name.encode()),  # sh_name
                section.sh_type,  # sh_type
                0,  # sh_flags
                section.vaddr,  # sh_addr
                len(buf),  # sh_offset
                len(section.data),  # sh_size
                section.sh_link,  # sh_link
                section.sh_info,  # sh_info
                1 if section.p_type is None else bits // 8,  # sh_addralign
                section.sh_entsize,  # sh_entsize
            )
            shdr_offset += shdr_struct.size
        if section.p_type is not None:
            flags = 7  # PF_R | PF_W | PF_X
            if bits == 64:
                phdr_struct.pack_into(
                    buf,
                    phdr_offset,
                    section.p_type,  # p_type
                    flags,  # p_flags
                    len(buf),  # p_offset
                    section.vaddr,  # p_vaddr
                    section.paddr,  # p_paddr
                    len(section.data),  # p_filesz
                    section.memsz,  # p_memsz
                    section.p_align,  # p_align
                )
            else:
                phdr_struct.pack_into(
                    buf,
                    phdr_offset,
                    section.p_type,  # p_type
                    len(buf),  # p_offset
                    section.vaddr,  # p_vaddr
                    section.paddr,  # p_paddr
                    len(section.data),  # p_filesz
                    section.memsz,  # p_memsz
                    flags,  # p_flags
                    section.p_align,  # p_align
                )
            phdr_offset += phdr_struct.size
        buf.extend(section.data)

    return buf
