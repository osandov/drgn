# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

from collections import namedtuple
import os
import struct
from typing import BinaryIO, Dict, List, NamedTuple, Optional, Tuple

from drgn.util import FileMapping


# Automatically generated from elf.h
EI_NIDENT = (16)
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
EI_OSABI = 7
EI_ABIVERSION = 8
EI_PAD = 9
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_NUM = 5
ET_LOOS = 0xfe00
ET_HIOS = 0xfeff
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff
EV_NONE = 0
EV_CURRENT = 1
EV_NUM = 2
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_BEFORE = 0xff00
SHN_AFTER = 0xff01
SHN_HIPROC = 0xff1f
SHN_LOOS = 0xff20
SHN_HIOS = 0xff3f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_XINDEX = 0xffff
SHN_HIRESERVE = 0xffff
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP = 17
SHT_SYMTAB_SHNDX = 18
SHT_NUM = 19
SHT_LOOS = 0x60000000
SHT_GNU_ATTRIBUTES = 0x6ffffff5
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_LIBLIST = 0x6ffffff7
SHT_CHECKSUM = 0x6ffffff8
SHT_LOSUNW = 0x6ffffffa
SHT_SUNW_move = 0x6ffffffa
SHT_SUNW_COMDAT = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff
SHT_HISUNW = 0x6fffffff
SHT_HIOS = 0x6fffffff
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0x8fffffff
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_NUM = 8
PT_LOOS = 0x60000000
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552
PT_LOSUNW = 0x6ffffffa
PT_SUNWBSS = 0x6ffffffa
PT_SUNWSTACK = 0x6ffffffb
PT_HISUNW = 0x6fffffff
PT_HIOS = 0x6fffffff
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
NT_PRSTATUS = 1
NT_FPREGSET = 2
NT_PRPSINFO = 3
NT_PRXREG = 4
NT_TASKSTRUCT = 4
NT_PLATFORM = 5
NT_AUXV = 6
NT_GWINDOWS = 7
NT_ASRS = 8
NT_PSTATUS = 10
NT_PSINFO = 13
NT_PRCRED = 14
NT_UTSNAME = 15
NT_LWPSTATUS = 16
NT_LWPSINFO = 17
NT_PRFPXREG = 20
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_PRXFPREG = 0x46e62b7f
NT_PPC_VMX = 0x100
NT_PPC_SPE = 0x101
NT_PPC_VSX = 0x102
NT_PPC_TAR = 0x103
NT_PPC_PPR = 0x104
NT_PPC_DSCR = 0x105
NT_PPC_EBB = 0x106
NT_PPC_PMU = 0x107
NT_PPC_TM_CGPR = 0x108
NT_PPC_TM_CFPR = 0x109
NT_PPC_TM_CVMX = 0x10a
NT_PPC_TM_CVSX = 0x10b
NT_PPC_TM_SPR = 0x10c
NT_PPC_TM_CTAR = 0x10d
NT_PPC_TM_CPPR = 0x10e
NT_PPC_TM_CDSCR = 0x10f
NT_386_TLS = 0x200
NT_386_IOPERM = 0x201
NT_X86_XSTATE = 0x202
NT_S390_HIGH_GPRS = 0x300
NT_S390_TIMER = 0x301
NT_S390_TODCMP = 0x302
NT_S390_TODPREG = 0x303
NT_S390_CTRS = 0x304
NT_S390_PREFIX = 0x305
NT_S390_LAST_BREAK = 0x306
NT_S390_SYSTEM_CALL = 0x307
NT_S390_TDB = 0x308
NT_ARM_VFP = 0x400
NT_ARM_TLS = 0x401
NT_ARM_HW_BREAK = 0x402
NT_ARM_HW_WATCH = 0x403
NT_ARM_SYSTEM_CALL = 0x404
NT_ARM_SVE = 0x405
NT_VERSION = 1
NT_GNU_ABI_TAG = 1
NT_GNU_HWCAP = 2
NT_GNU_BUILD_ID = 3
NT_GNU_GOLD_VERSION = 4
NT_GNU_PROPERTY_TYPE_0 = 5
SHN_MIPS_ACOMMON = 0xff00
SHN_MIPS_TEXT = 0xff01
SHN_MIPS_DATA = 0xff02
SHN_MIPS_SCOMMON = 0xff03
SHN_MIPS_SUNDEFINED = 0xff04
SHT_MIPS_LIBLIST = 0x70000000
SHT_MIPS_MSYM = 0x70000001
SHT_MIPS_CONFLICT = 0x70000002
SHT_MIPS_GPTAB = 0x70000003
SHT_MIPS_UCODE = 0x70000004
SHT_MIPS_DEBUG = 0x70000005
SHT_MIPS_REGINFO = 0x70000006
SHT_MIPS_PACKAGE = 0x70000007
SHT_MIPS_PACKSYM = 0x70000008
SHT_MIPS_RELD = 0x70000009
SHT_MIPS_IFACE = 0x7000000b
SHT_MIPS_CONTENT = 0x7000000c
SHT_MIPS_OPTIONS = 0x7000000d
SHT_MIPS_SHDR = 0x70000010
SHT_MIPS_FDESC = 0x70000011
SHT_MIPS_EXTSYM = 0x70000012
SHT_MIPS_DENSE = 0x70000013
SHT_MIPS_PDESC = 0x70000014
SHT_MIPS_LOCSYM = 0x70000015
SHT_MIPS_AUXSYM = 0x70000016
SHT_MIPS_OPTSYM = 0x70000017
SHT_MIPS_LOCSTR = 0x70000018
SHT_MIPS_LINE = 0x70000019
SHT_MIPS_RFDESC = 0x7000001a
SHT_MIPS_DELTASYM = 0x7000001b
SHT_MIPS_DELTAINST = 0x7000001c
SHT_MIPS_DELTACLASS = 0x7000001d
SHT_MIPS_DWARF = 0x7000001e
SHT_MIPS_DELTADECL = 0x7000001f
SHT_MIPS_SYMBOL_LIB = 0x70000020
SHT_MIPS_EVENTS = 0x70000021
SHT_MIPS_TRANSLATE = 0x70000022
SHT_MIPS_PIXIE = 0x70000023
SHT_MIPS_XLATE = 0x70000024
SHT_MIPS_XLATE_DEBUG = 0x70000025
SHT_MIPS_WHIRL = 0x70000026
SHT_MIPS_EH_REGION = 0x70000027
SHT_MIPS_XLATE_OLD = 0x70000028
SHT_MIPS_PDR_EXCEPTION = 0x70000029
PT_MIPS_REGINFO = 0x70000000
PT_MIPS_RTPROC = 0x70000001
PT_MIPS_OPTIONS = 0x70000002
PT_MIPS_ABIFLAGS = 0x70000003
SHN_PARISC_ANSI_COMMON = 0xff00
SHN_PARISC_HUGE_COMMON = 0xff01
SHT_PARISC_EXT = 0x70000000
SHT_PARISC_UNWIND = 0x70000001
SHT_PARISC_DOC = 0x70000002
PT_HP_TLS = (PT_LOOS + 0x0)
PT_HP_CORE_NONE = (PT_LOOS + 0x1)
PT_HP_CORE_VERSION = (PT_LOOS + 0x2)
PT_HP_CORE_KERNEL = (PT_LOOS + 0x3)
PT_HP_CORE_COMM = (PT_LOOS + 0x4)
PT_HP_CORE_PROC = (PT_LOOS + 0x5)
PT_HP_CORE_LOADABLE = (PT_LOOS + 0x6)
PT_HP_CORE_STACK = (PT_LOOS + 0x7)
PT_HP_CORE_SHM = (PT_LOOS + 0x8)
PT_HP_CORE_MMF = (PT_LOOS + 0x9)
PT_HP_PARALLEL = (PT_LOOS + 0x10)
PT_HP_FASTBIND = (PT_LOOS + 0x11)
PT_HP_OPT_ANNOT = (PT_LOOS + 0x12)
PT_HP_HSL_ANNOT = (PT_LOOS + 0x13)
PT_HP_STACK = (PT_LOOS + 0x14)
PT_PARISC_ARCHEXT = 0x70000000
PT_PARISC_UNWIND = 0x70000001
SHT_ALPHA_DEBUG = 0x70000001
SHT_ALPHA_REGINFO = 0x70000002
PT_ARM_EXIDX = (PT_LOPROC + 1)
SHT_ARM_EXIDX = (SHT_LOPROC + 1)
SHT_ARM_PREEMPTMAP = (SHT_LOPROC + 2)
SHT_ARM_ATTRIBUTES = (SHT_LOPROC + 3)
PT_IA_64_ARCHEXT = (PT_LOPROC + 0)
PT_IA_64_UNWIND = (PT_LOPROC + 1)
PT_IA_64_HP_OPT_ANOT = (PT_LOOS + 0x12)
PT_IA_64_HP_HSL_ANOT = (PT_LOOS + 0x13)
PT_IA_64_HP_STACK = (PT_LOOS + 0x14)
SHT_IA_64_EXT = (SHT_LOPROC + 0)
SHT_IA_64_UNWIND = (SHT_LOPROC + 1)


class ElfFormatError(Exception):
    pass


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


class Elf_Shdr(NamedTuple):
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    name: str


class Elf_Sym(NamedTuple):
    st_name: int
    st_info: int
    st_other: int
    st_shndx: int
    st_value: int
    st_size: int


class Elf_Note(NamedTuple):
    name: bytes
    type: int
    data: bytes


class ElfFile:
    def __init__(self, file: BinaryIO) -> None:
        self.file = file
        self.ehdr = self._ehdr()
        self._phdrs: Optional[List[Elf_Phdr]] = None
        self._shdrs: Optional[List[Elf_Shdr]] = None
        self._sections: Optional[Dict[str, Elf_Shdr]] = None
        self._symbols: Optional[Dict[str, List[Elf_Sym]]] = None

    def _ehdr(self) -> Elf_Ehdr:
        self.file.seek(0)
        e_ident = self.file.read(16)
        if (e_ident[EI_MAG0] != ELFMAG0 or e_ident[EI_MAG1] != ELFMAG1 or
                e_ident[EI_MAG2] != ELFMAG2 or e_ident[EI_MAG3] != ELFMAG3):
            raise ElfFormatError('not an ELF file')

        if e_ident[EI_VERSION] != EV_CURRENT:
            raise ElfFormatError('ELF version is not EV_CURRENT')

        if e_ident[EI_DATA] == ELFDATA2LSB:
            fmt = '<'
        elif e_ident[EI_DATA] == ELFDATA2MSB:
            fmt = '>'
        else:
            raise ElfFormatError(f'unknown ELF data encoding {e_ident[EI_DATA]}')

        if e_ident[EI_CLASS] == ELFCLASS64:
            fmt += 'HHLQQQLHHHHHH'
        elif e_ident[EI_CLASS] == ELFCLASS32:
            raise NotImplementedError('32-bit ELF is not implemented')
        else:
            raise ElfFormatError(f'unknown ELF class {e_ident[EI_CLASS]}')
        buf = self.file.read(struct.calcsize(fmt))
        return Elf_Ehdr(e_ident, *struct.unpack(fmt, buf))

    def notes(self) -> List[Elf_Note]:
        if self.ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
            fmt = '<'
        else:
            fmt = '>'
        fmt += 'III'  # Same for Elf32 and Elf64

        list = []
        for phdr in self.phdrs:
            if phdr.p_type != PT_NOTE:
                continue
            self.file.seek(phdr.p_offset)
            buf = self.file.read(phdr.p_filesz)
            off = 0
            while off < len(buf):
                namesz, descsz, type_ = struct.unpack_from(fmt, buf, off)
                off += 12
                if namesz:
                    name = buf[off:off + namesz - 1]
                    off += (namesz + 3) & ~3
                else:
                    name = b''
                if descsz:
                    desc = buf[off:off + descsz - 1]
                    off += (descsz + 3) & ~3
                else:
                    desc = b''
                list.append(Elf_Note(name, type_, desc))
        return list

    @property
    def phdrs(self) -> List[Elf_Phdr]:
        if self._phdrs is None:
            if self.ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if self.ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LLQQQQQQ'
            else:
                assert False

            self.file.seek(self.ehdr.e_phoff)
            buf = self.file.read(self.ehdr.e_phnum * self.ehdr.e_phentsize)
            self._phdrs = [Elf_Phdr._make(x) for x in struct.iter_unpack(fmt, buf)]
        return self._phdrs

    def _parse_shdrs(self) -> None:
        if self.ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
            fmt = '<'
        else:
            fmt = '>'

        if self.ehdr.e_ident[EI_CLASS] == ELFCLASS64:
            fmt += 'LLQQQQLLQQ'
        else:
            assert False

        # TODO: e_shnum == 0
        self.file.seek(self.ehdr.e_shoff)
        buf = self.file.read(self.ehdr.e_shnum * self.ehdr.e_shentsize)
        raw_shdrs = list(struct.iter_unpack(fmt, buf))

        if self.ehdr.e_shstrndx == SHN_UNDEF:
            raise ElfFormatError('no string table index in ELF header')
        elif self.ehdr.e_shstrndx == SHN_XINDEX:
            sh_link = raw_shdrs[0][6]
            shstrtab_shdr = raw_shdrs[sh_link]
        else:
            if self.ehdr.e_shstrndx >= SHN_LORESERVE:
                raise ElfFormatError('invalid string table index in ELF header')
            shstrtab_shdr = raw_shdrs[self.ehdr.e_shstrndx]
        sh_offset = shstrtab_shdr[4]
        sh_size = shstrtab_shdr[5]
        self.file.seek(sh_offset)
        # We call bytes() here because self.file might actually be a
        # MemoryViewIO, which returns a memoryview, which doesn't have an
        # index() method.
        shstrtab = bytes(self.file.read(sh_size))

        shdrs = []
        for raw_shdr in raw_shdrs:
            sh_name = raw_shdr[0]
            if sh_name:
                end = shstrtab.index(b'\0', sh_name)
                section_name = shstrtab[sh_name:end].decode()
            else:
                section_name = ''
            # mypy claims 'Too many arguments for "Elf_Shdr"'
            shdrs.append(Elf_Shdr(*raw_shdr, section_name))  # type: ignore

        self._shdrs = shdrs
        self._sections = {shdr.name: shdr for shdr in shdrs}

    @property
    def shdrs(self) -> List[Elf_Shdr]:
        if self._shdrs is None:
            self._parse_shdrs()
            assert self._shdrs is not None
        return self._shdrs

    @property
    def sections(self) -> Dict[str, Elf_Shdr]:
        if self._sections is None:
            self._parse_shdrs()
            assert self._sections is not None
        return self._sections

    @property
    def symbols(self) -> Dict[str, List[Elf_Sym]]:
        if self._symbols is None:
            if self.ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if self.ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LBBHQQ'
            else:
                assert False

            shdr = self.sections['.symtab']
            self.file.seek(shdr.sh_offset)
            buf = self.file.read(shdr.sh_size)
            symtab = [Elf_Sym._make(sym) for sym in struct.iter_unpack(fmt, buf)]

            strtab_shdr = self.sections['.strtab']
            self.file.seek(strtab_shdr.sh_offset)
            # See comment in shdrs() about why we call bytes().
            strtab = bytes(self.file.read(strtab_shdr.sh_size))
            symbols: Dict[str, List[Elf_Sym]] = {}
            for sym in symtab:
                if not sym.st_name:
                    continue
                end = strtab.index(b'\0', sym.st_name)
                symbol_name = strtab[sym.st_name:end].decode()
                try:
                    symbols[symbol_name].append(sym)
                except KeyError:
                    symbols[symbol_name] = [sym]
            self._symbols = symbols
        return self._symbols

    def parse_nt_file(self, data: bytes) -> List[FileMapping]:
        if self.ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
            fmt = '<'
        else:
            fmt = '>'

        if self.ehdr.e_ident[EI_CLASS] == ELFCLASS64:
            header_fmt = fmt + 'QQ'
            fmt += 'QQQ'
        else:
            header_fmt = fmt + 'II'
            fmt += 'III'
        header_size = struct.calcsize(header_fmt)

        count, page_size = struct.unpack_from(header_fmt, data)
        i = header_size + struct.calcsize(fmt) * count
        list = []
        for start, end, offset in struct.iter_unpack('=QQQ', data[header_size:i]):
            if i >= len(data):
                raise ElfFormatError('invalid NT_FILE note')
            try:
                j = data.index(b'\0', i)
            except ValueError:
                j = len(data)
            path = os.fsdecode(data[i:j])
            i = j + 1
            list.append(FileMapping(path, start, end, page_size * offset))
        return list
