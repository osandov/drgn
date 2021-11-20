# Automatically generated from elf.h

import enum
from typing import Text


class ET(enum.IntEnum):
    NONE = 0x0
    REL = 0x1
    EXEC = 0x2
    DYN = 0x3
    CORE = 0x4
    NUM = 0x5
    LOOS = 0xFE00
    HIOS = 0xFEFF
    LOPROC = 0xFF00
    HIPROC = 0xFFFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"ET_{cls(value).name}"
        except ValueError:
            return hex(value)


class PT(enum.IntEnum):
    NULL = 0x0
    LOAD = 0x1
    DYNAMIC = 0x2
    INTERP = 0x3
    NOTE = 0x4
    SHLIB = 0x5
    PHDR = 0x6
    TLS = 0x7
    NUM = 0x8
    LOOS = 0x60000000
    GNU_EH_FRAME = 0x6474E550
    GNU_STACK = 0x6474E551
    GNU_RELRO = 0x6474E552
    GNU_PROPERTY = 0x6474E553
    LOSUNW = 0x6FFFFFFA
    SUNWBSS = 0x6FFFFFFA
    SUNWSTACK = 0x6FFFFFFB
    HISUNW = 0x6FFFFFFF
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7FFFFFFF
    MIPS_REGINFO = 0x70000000
    MIPS_RTPROC = 0x70000001
    MIPS_OPTIONS = 0x70000002
    MIPS_ABIFLAGS = 0x70000003
    PARISC_ARCHEXT = 0x70000000
    PARISC_UNWIND = 0x70000001

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"PT_{cls(value).name}"
        except ValueError:
            return hex(value)


class SHN(enum.IntEnum):
    UNDEF = 0x0
    LORESERVE = 0xFF00
    LOPROC = 0xFF00
    BEFORE = 0xFF00
    AFTER = 0xFF01
    HIPROC = 0xFF1F
    LOOS = 0xFF20
    HIOS = 0xFF3F
    ABS = 0xFFF1
    COMMON = 0xFFF2
    XINDEX = 0xFFFF
    HIRESERVE = 0xFFFF
    MIPS_ACOMMON = 0xFF00
    MIPS_TEXT = 0xFF01
    MIPS_DATA = 0xFF02
    MIPS_SCOMMON = 0xFF03
    MIPS_SUNDEFINED = 0xFF04
    PARISC_ANSI_COMMON = 0xFF00
    PARISC_HUGE_COMMON = 0xFF01

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"SHN_{cls(value).name}"
        except ValueError:
            return hex(value)


class SHT(enum.IntEnum):
    NULL = 0x0
    PROGBITS = 0x1
    SYMTAB = 0x2
    STRTAB = 0x3
    RELA = 0x4
    HASH = 0x5
    DYNAMIC = 0x6
    NOTE = 0x7
    NOBITS = 0x8
    REL = 0x9
    SHLIB = 0xA
    DYNSYM = 0xB
    INIT_ARRAY = 0xE
    FINI_ARRAY = 0xF
    PREINIT_ARRAY = 0x10
    GROUP = 0x11
    SYMTAB_SHNDX = 0x12
    NUM = 0x13
    LOOS = 0x60000000
    GNU_ATTRIBUTES = 0x6FFFFFF5
    GNU_HASH = 0x6FFFFFF6
    GNU_LIBLIST = 0x6FFFFFF7
    CHECKSUM = 0x6FFFFFF8
    LOSUNW = 0x6FFFFFFA
    SUNW_move = 0x6FFFFFFA
    SUNW_COMDAT = 0x6FFFFFFB
    SUNW_syminfo = 0x6FFFFFFC
    GNU_verdef = 0x6FFFFFFD
    GNU_verneed = 0x6FFFFFFE
    GNU_versym = 0x6FFFFFFF
    HISUNW = 0x6FFFFFFF
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7FFFFFFF
    LOUSER = 0x80000000
    HIUSER = 0x8FFFFFFF
    MIPS_LIBLIST = 0x70000000
    MIPS_MSYM = 0x70000001
    MIPS_CONFLICT = 0x70000002
    MIPS_GPTAB = 0x70000003
    MIPS_UCODE = 0x70000004
    MIPS_DEBUG = 0x70000005
    MIPS_REGINFO = 0x70000006
    MIPS_PACKAGE = 0x70000007
    MIPS_PACKSYM = 0x70000008
    MIPS_RELD = 0x70000009
    MIPS_IFACE = 0x7000000B
    MIPS_CONTENT = 0x7000000C
    MIPS_OPTIONS = 0x7000000D
    MIPS_SHDR = 0x70000010
    MIPS_FDESC = 0x70000011
    MIPS_EXTSYM = 0x70000012
    MIPS_DENSE = 0x70000013
    MIPS_PDESC = 0x70000014
    MIPS_LOCSYM = 0x70000015
    MIPS_AUXSYM = 0x70000016
    MIPS_OPTSYM = 0x70000017
    MIPS_LOCSTR = 0x70000018
    MIPS_LINE = 0x70000019
    MIPS_RFDESC = 0x7000001A
    MIPS_DELTASYM = 0x7000001B
    MIPS_DELTAINST = 0x7000001C
    MIPS_DELTACLASS = 0x7000001D
    MIPS_DWARF = 0x7000001E
    MIPS_DELTADECL = 0x7000001F
    MIPS_SYMBOL_LIB = 0x70000020
    MIPS_EVENTS = 0x70000021
    MIPS_TRANSLATE = 0x70000022
    MIPS_PIXIE = 0x70000023
    MIPS_XLATE = 0x70000024
    MIPS_XLATE_DEBUG = 0x70000025
    MIPS_WHIRL = 0x70000026
    MIPS_EH_REGION = 0x70000027
    MIPS_XLATE_OLD = 0x70000028
    MIPS_PDR_EXCEPTION = 0x70000029
    MIPS_XHASH = 0x7000002B
    PARISC_EXT = 0x70000000
    PARISC_UNWIND = 0x70000001
    PARISC_DOC = 0x70000002
    ALPHA_DEBUG = 0x70000001
    ALPHA_REGINFO = 0x70000002
    X86_64_UNWIND = 0x70000001

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"SHT_{cls(value).name}"
        except ValueError:
            return hex(value)


class STB(enum.IntEnum):
    LOCAL = 0x0
    GLOBAL = 0x1
    WEAK = 0x2
    NUM = 0x3
    LOOS = 0xA
    GNU_UNIQUE = 0xA
    HIOS = 0xC
    LOPROC = 0xD
    HIPROC = 0xF
    MIPS_SPLIT_COMMON = 0xD

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"STB_{cls(value).name}"
        except ValueError:
            return hex(value)


class STT(enum.IntEnum):
    NOTYPE = 0x0
    OBJECT = 0x1
    FUNC = 0x2
    SECTION = 0x3
    FILE = 0x4
    COMMON = 0x5
    TLS = 0x6
    NUM = 0x7
    LOOS = 0xA
    GNU_IFUNC = 0xA
    HIOS = 0xC
    LOPROC = 0xD
    HIPROC = 0xF
    SPARC_REGISTER = 0xD
    PARISC_MILLICODE = 0xD

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"STT_{cls(value).name}"
        except ValueError:
            return hex(value)


class STV(enum.IntEnum):
    DEFAULT = 0x0
    INTERNAL = 0x1
    HIDDEN = 0x2
    PROTECTED = 0x3

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"STV_{cls(value).name}"
        except ValueError:
            return hex(value)
