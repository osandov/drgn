from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, Py_buffer, PyBUF_SIMPLE, PyBUF_WRITABLE
from drgn.readwrite cimport *

from collections import namedtuple, OrderedDict
import struct
import sys
from types import SimpleNamespace
import zlib


cdef extern from "stdint.h":
    uint32_t UINT32_C(uint32_t)


# Automatically generated from elf.h
cdef enum:
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
    ELFOSABI_NONE = 0
    ELFOSABI_SYSV = 0
    ELFOSABI_HPUX = 1
    ELFOSABI_NETBSD = 2
    ELFOSABI_GNU = 3
    ELFOSABI_LINUX = ELFOSABI_GNU
    ELFOSABI_SOLARIS = 6
    ELFOSABI_AIX = 7
    ELFOSABI_IRIX = 8
    ELFOSABI_FREEBSD = 9
    ELFOSABI_TRU64 = 10
    ELFOSABI_MODESTO = 11
    ELFOSABI_OPENBSD = 12
    ELFOSABI_ARM_AEABI = 64
    ELFOSABI_ARM = 97
    ELFOSABI_STANDALONE = 255
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
    EM_NONE = 0
    EM_M32 = 1
    EM_SPARC = 2
    EM_386 = 3
    EM_68K = 4
    EM_88K = 5
    EM_IAMCU = 6
    EM_860 = 7
    EM_MIPS = 8
    EM_S370 = 9
    EM_MIPS_RS3_LE = 10
    EM_PARISC = 15
    EM_VPP500 = 17
    EM_SPARC32PLUS = 18
    EM_960 = 19
    EM_PPC = 20
    EM_PPC64 = 21
    EM_S390 = 22
    EM_SPU = 23
    EM_V800 = 36
    EM_FR20 = 37
    EM_RH32 = 38
    EM_RCE = 39
    EM_ARM = 40
    EM_FAKE_ALPHA = 41
    EM_SH = 42
    EM_SPARCV9 = 43
    EM_TRICORE = 44
    EM_ARC = 45
    EM_H8_300 = 46
    EM_H8_300H = 47
    EM_H8S = 48
    EM_H8_500 = 49
    EM_IA_64 = 50
    EM_MIPS_X = 51
    EM_COLDFIRE = 52
    EM_68HC12 = 53
    EM_MMA = 54
    EM_PCP = 55
    EM_NCPU = 56
    EM_NDR1 = 57
    EM_STARCORE = 58
    EM_ME16 = 59
    EM_ST100 = 60
    EM_TINYJ = 61
    EM_X86_64 = 62
    EM_PDSP = 63
    EM_PDP10 = 64
    EM_PDP11 = 65
    EM_FX66 = 66
    EM_ST9PLUS = 67
    EM_ST7 = 68
    EM_68HC16 = 69
    EM_68HC11 = 70
    EM_68HC08 = 71
    EM_68HC05 = 72
    EM_SVX = 73
    EM_ST19 = 74
    EM_VAX = 75
    EM_CRIS = 76
    EM_JAVELIN = 77
    EM_FIREPATH = 78
    EM_ZSP = 79
    EM_MMIX = 80
    EM_HUANY = 81
    EM_PRISM = 82
    EM_AVR = 83
    EM_FR30 = 84
    EM_D10V = 85
    EM_D30V = 86
    EM_V850 = 87
    EM_M32R = 88
    EM_MN10300 = 89
    EM_MN10200 = 90
    EM_PJ = 91
    EM_OPENRISC = 92
    EM_ARC_COMPACT = 93
    EM_XTENSA = 94
    EM_VIDEOCORE = 95
    EM_TMM_GPP = 96
    EM_NS32K = 97
    EM_TPC = 98
    EM_SNP1K = 99
    EM_ST200 = 100
    EM_IP2K = 101
    EM_MAX = 102
    EM_CR = 103
    EM_F2MC16 = 104
    EM_MSP430 = 105
    EM_BLACKFIN = 106
    EM_SE_C33 = 107
    EM_SEP = 108
    EM_ARCA = 109
    EM_UNICORE = 110
    EM_EXCESS = 111
    EM_DXP = 112
    EM_ALTERA_NIOS2 = 113
    EM_CRX = 114
    EM_XGATE = 115
    EM_C166 = 116
    EM_M16C = 117
    EM_DSPIC30F = 118
    EM_CE = 119
    EM_M32C = 120
    EM_TSK3000 = 131
    EM_RS08 = 132
    EM_SHARC = 133
    EM_ECOG2 = 134
    EM_SCORE7 = 135
    EM_DSP24 = 136
    EM_VIDEOCORE3 = 137
    EM_LATTICEMICO32 = 138
    EM_SE_C17 = 139
    EM_TI_C6000 = 140
    EM_TI_C2000 = 141
    EM_TI_C5500 = 142
    EM_TI_ARP32 = 143
    EM_TI_PRU = 144
    EM_MMDSP_PLUS = 160
    EM_CYPRESS_M8C = 161
    EM_R32C = 162
    EM_TRIMEDIA = 163
    EM_QDSP6 = 164
    EM_8051 = 165
    EM_STXP7X = 166
    EM_NDS32 = 167
    EM_ECOG1X = 168
    EM_MAXQ30 = 169
    EM_XIMO16 = 170
    EM_MANIK = 171
    EM_CRAYNV2 = 172
    EM_RX = 173
    EM_METAG = 174
    EM_MCST_ELBRUS = 175
    EM_ECOG16 = 176
    EM_CR16 = 177
    EM_ETPU = 178
    EM_SLE9X = 179
    EM_L10M = 180
    EM_K10M = 181
    EM_AARCH64 = 183
    EM_AVR32 = 185
    EM_STM8 = 186
    EM_TILE64 = 187
    EM_TILEPRO = 188
    EM_MICROBLAZE = 189
    EM_CUDA = 190
    EM_TILEGX = 191
    EM_CLOUDSHIELD = 192
    EM_COREA_1ST = 193
    EM_COREA_2ND = 194
    EM_ARC_COMPACT2 = 195
    EM_OPEN8 = 196
    EM_RL78 = 197
    EM_VIDEOCORE5 = 198
    EM_78KOR = 199
    EM_56800EX = 200
    EM_BA1 = 201
    EM_BA2 = 202
    EM_XCORE = 203
    EM_MCHP_PIC = 204
    EM_KM32 = 210
    EM_KMX32 = 211
    EM_EMX16 = 212
    EM_EMX8 = 213
    EM_KVARC = 214
    EM_CDP = 215
    EM_COGE = 216
    EM_COOL = 217
    EM_NORC = 218
    EM_CSR_KALIMBA = 219
    EM_Z80 = 220
    EM_VISIUM = 221
    EM_FT32 = 222
    EM_MOXIE = 223
    EM_AMDGPU = 224
    EM_RISCV = 243
    EM_BPF = 247
    EM_NUM = 248
    EM_ARC_A5 = EM_ARC_COMPACT
    EM_ALPHA = 0x9026
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
    SHF_WRITE = (1 << 0)
    SHF_ALLOC = (1 << 1)
    SHF_EXECINSTR = (1 << 2)
    SHF_MERGE = (1 << 4)
    SHF_STRINGS = (1 << 5)
    SHF_INFO_LINK = (1 << 6)
    SHF_LINK_ORDER = (1 << 7)
    SHF_OS_NONCONFORMING = (1 << 8)
    SHF_GROUP = (1 << 9)
    SHF_TLS = (1 << 10)
    SHF_COMPRESSED = (1 << 11)
    SHF_MASKOS = 0x0ff00000
    SHF_MASKPROC = 0xf0000000
    SHF_ORDERED = (1 << 30)
    SHF_EXCLUDE = (1U << 31)
    ELFCOMPRESS_ZLIB = 1
    ELFCOMPRESS_LOOS = 0x60000000
    ELFCOMPRESS_HIOS = 0x6fffffff
    ELFCOMPRESS_LOPROC = 0x70000000
    ELFCOMPRESS_HIPROC = 0x7fffffff
    GRP_COMDAT = 0x1
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_NUM = 3
    STB_LOOS = 10
    STB_GNU_UNIQUE = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    STT_NUM = 7
    STT_LOOS = 10
    STT_GNU_IFUNC = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15
    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3
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
    PF_X = (1 << 0)
    PF_W = (1 << 1)
    PF_R = (1 << 2)
    PF_MASKOS = 0x0ff00000
    PF_MASKPROC = 0xf0000000
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_BIND_NOW = 24
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_RUNPATH = 29
    DT_FLAGS = 30
    DT_ENCODING = 32
    DT_PREINIT_ARRAY = 32
    DT_PREINIT_ARRAYSZ = 33
    DT_NUM = 34
    DT_LOOS = 0x6000000d
    DT_HIOS = 0x6ffff000
    DT_LOPROC = 0x70000000
    DT_HIPROC = 0x7fffffff
    DT_PROCNUM = 0x36
    DT_VALRNGLO = 0x6ffffd00
    DT_GNU_PRELINKED = 0x6ffffdf5
    DT_GNU_CONFLICTSZ = 0x6ffffdf6
    DT_GNU_LIBLISTSZ = 0x6ffffdf7
    DT_CHECKSUM = 0x6ffffdf8
    DT_PLTPADSZ = 0x6ffffdf9
    DT_MOVEENT = 0x6ffffdfa
    DT_MOVESZ = 0x6ffffdfb
    DT_FEATURE_1 = 0x6ffffdfc
    DT_POSFLAG_1 = 0x6ffffdfd
    DT_SYMINSZ = 0x6ffffdfe
    DT_SYMINENT = 0x6ffffdff
    DT_VALRNGHI = 0x6ffffdff
    DT_VALNUM = 12
    DT_ADDRRNGLO = 0x6ffffe00
    DT_GNU_HASH = 0x6ffffef5
    DT_TLSDESC_PLT = 0x6ffffef6
    DT_TLSDESC_GOT = 0x6ffffef7
    DT_GNU_CONFLICT = 0x6ffffef8
    DT_GNU_LIBLIST = 0x6ffffef9
    DT_CONFIG = 0x6ffffefa
    DT_DEPAUDIT = 0x6ffffefb
    DT_AUDIT = 0x6ffffefc
    DT_PLTPAD = 0x6ffffefd
    DT_MOVETAB = 0x6ffffefe
    DT_SYMINFO = 0x6ffffeff
    DT_ADDRRNGHI = 0x6ffffeff
    DT_ADDRNUM = 11
    DT_VERSYM = 0x6ffffff0
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
    DT_FLAGS_1 = 0x6ffffffb
    DT_VERDEF = 0x6ffffffc
    DT_VERDEFNUM = 0x6ffffffd
    DT_VERNEED = 0x6ffffffe
    DT_VERNEEDNUM = 0x6fffffff
    DT_VERSIONTAGNUM = 16
    DT_AUXILIARY = 0x7ffffffd
    DT_FILTER = 0x7fffffff
    DT_EXTRANUM = 3
    STT_SPARC_REGISTER = 13
    DT_SPARC_REGISTER = 0x70000001
    DT_SPARC_NUM = 2
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
    SHF_MIPS_GPREL = 0x10000000
    SHF_MIPS_MERGE = 0x20000000
    SHF_MIPS_ADDR = 0x40000000
    SHF_MIPS_STRINGS = 0x80000000
    SHF_MIPS_NOSTRIP = 0x08000000
    SHF_MIPS_LOCAL = 0x04000000
    SHF_MIPS_NAMES = 0x02000000
    SHF_MIPS_NODUPE = 0x01000000
    STB_MIPS_SPLIT_COMMON = 13
    PT_MIPS_REGINFO = 0x70000000
    PT_MIPS_RTPROC = 0x70000001
    PT_MIPS_OPTIONS = 0x70000002
    PT_MIPS_ABIFLAGS = 0x70000003
    PF_MIPS_LOCAL = 0x10000000
    DT_MIPS_RLD_VERSION = 0x70000001
    DT_MIPS_TIME_STAMP = 0x70000002
    DT_MIPS_ICHECKSUM = 0x70000003
    DT_MIPS_IVERSION = 0x70000004
    DT_MIPS_FLAGS = 0x70000005
    DT_MIPS_BASE_ADDRESS = 0x70000006
    DT_MIPS_MSYM = 0x70000007
    DT_MIPS_CONFLICT = 0x70000008
    DT_MIPS_LIBLIST = 0x70000009
    DT_MIPS_LOCAL_GOTNO = 0x7000000a
    DT_MIPS_CONFLICTNO = 0x7000000b
    DT_MIPS_LIBLISTNO = 0x70000010
    DT_MIPS_SYMTABNO = 0x70000011
    DT_MIPS_UNREFEXTNO = 0x70000012
    DT_MIPS_GOTSYM = 0x70000013
    DT_MIPS_HIPAGENO = 0x70000014
    DT_MIPS_RLD_MAP = 0x70000016
    DT_MIPS_DELTA_CLASS = 0x70000017
    DT_MIPS_DELTA_CLASS_NO = 0x70000018
    DT_MIPS_DELTA_INSTANCE = 0x70000019
    DT_MIPS_DELTA_INSTANCE_NO = 0x7000001a
    DT_MIPS_DELTA_RELOC = 0x7000001b
    DT_MIPS_DELTA_RELOC_NO = 0x7000001c
    DT_MIPS_DELTA_SYM = 0x7000001d
    DT_MIPS_DELTA_SYM_NO = 0x7000001e
    DT_MIPS_DELTA_CLASSSYM = 0x70000020
    DT_MIPS_DELTA_CLASSSYM_NO = 0x70000021
    DT_MIPS_CXX_FLAGS = 0x70000022
    DT_MIPS_PIXIE_INIT = 0x70000023
    DT_MIPS_SYMBOL_LIB = 0x70000024
    DT_MIPS_LOCALPAGE_GOTIDX = 0x70000025
    DT_MIPS_LOCAL_GOTIDX = 0x70000026
    DT_MIPS_HIDDEN_GOTIDX = 0x70000027
    DT_MIPS_PROTECTED_GOTIDX = 0x70000028
    DT_MIPS_OPTIONS = 0x70000029
    DT_MIPS_INTERFACE = 0x7000002a
    DT_MIPS_DYNSTR_ALIGN = 0x7000002b
    DT_MIPS_INTERFACE_SIZE = 0x7000002c
    DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002d
    DT_MIPS_PERF_SUFFIX = 0x7000002e
    DT_MIPS_COMPACT_SIZE = 0x7000002f
    DT_MIPS_GP_VALUE = 0x70000030
    DT_MIPS_AUX_DYNAMIC = 0x70000031
    DT_MIPS_PLTGOT = 0x70000032
    DT_MIPS_RWPLT = 0x70000034
    DT_MIPS_RLD_MAP_REL = 0x70000035
    DT_MIPS_NUM = 0x36
    SHN_PARISC_ANSI_COMMON = 0xff00
    SHN_PARISC_HUGE_COMMON = 0xff01
    SHT_PARISC_EXT = 0x70000000
    SHT_PARISC_UNWIND = 0x70000001
    SHT_PARISC_DOC = 0x70000002
    SHF_PARISC_SHORT = 0x20000000
    SHF_PARISC_HUGE = 0x40000000
    SHF_PARISC_SBP = 0x80000000
    STT_PARISC_MILLICODE = 13
    STT_HP_OPAQUE = (STT_LOOS + 0x1)
    STT_HP_STUB = (STT_LOOS + 0x2)
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
    PF_PARISC_SBP = 0x08000000
    PF_HP_PAGE_SIZE = 0x00100000
    PF_HP_FAR_SHARED = 0x00200000
    PF_HP_NEAR_SHARED = 0x00400000
    PF_HP_CODE = 0x01000000
    PF_HP_MODIFY = 0x02000000
    PF_HP_LAZYSWAP = 0x04000000
    PF_HP_SBP = 0x08000000
    SHT_ALPHA_DEBUG = 0x70000001
    SHT_ALPHA_REGINFO = 0x70000002
    SHF_ALPHA_GPREL = 0x10000000
    DT_ALPHA_PLTRO = (DT_LOPROC + 0)
    DT_ALPHA_NUM = 1
    DT_PPC_GOT = (DT_LOPROC + 0)
    DT_PPC_OPT = (DT_LOPROC + 1)
    DT_PPC_NUM = 2
    DT_PPC64_GLINK = (DT_LOPROC + 0)
    DT_PPC64_OPD = (DT_LOPROC + 1)
    DT_PPC64_OPDSZ = (DT_LOPROC + 2)
    DT_PPC64_OPT = (DT_LOPROC + 3)
    DT_PPC64_NUM = 4
    STT_ARM_TFUNC = STT_LOPROC
    STT_ARM_16BIT = STT_HIPROC
    SHF_ARM_ENTRYSECT = 0x10000000
    SHF_ARM_COMDEF = 0x80000000
    PF_ARM_SB = 0x10000000
    PF_ARM_PI = 0x20000000
    PF_ARM_ABS = 0x40000000
    PT_ARM_EXIDX = (PT_LOPROC + 1)
    SHT_ARM_EXIDX = (SHT_LOPROC + 1)
    SHT_ARM_PREEMPTMAP = (SHT_LOPROC + 2)
    SHT_ARM_ATTRIBUTES = (SHT_LOPROC + 3)
    PT_IA_64_ARCHEXT = (PT_LOPROC + 0)
    PT_IA_64_UNWIND = (PT_LOPROC + 1)
    PT_IA_64_HP_OPT_ANOT = (PT_LOOS + 0x12)
    PT_IA_64_HP_HSL_ANOT = (PT_LOOS + 0x13)
    PT_IA_64_HP_STACK = (PT_LOOS + 0x14)
    PF_IA_64_NORECOV = 0x80000000
    SHT_IA_64_EXT = (SHT_LOPROC + 0)
    SHT_IA_64_UNWIND = (SHT_LOPROC + 1)
    SHF_IA_64_SHORT = 0x10000000
    SHF_IA_64_NORECOV = 0x20000000
    DT_IA_64_PLT_RESERVE = (DT_LOPROC + 0)
    DT_IA_64_NUM = 1
    R_X86_64_NONE = 0
    R_X86_64_64 = 1
    R_X86_64_PC32 = 2
    R_X86_64_GOT32 = 3
    R_X86_64_PLT32 = 4
    R_X86_64_COPY = 5
    R_X86_64_GLOB_DAT = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE = 8
    R_X86_64_GOTPCREL = 9
    R_X86_64_32 = 10
    R_X86_64_32S = 11
    R_X86_64_16 = 12
    R_X86_64_PC16 = 13
    R_X86_64_8 = 14
    R_X86_64_PC8 = 15
    R_X86_64_DTPMOD64 = 16
    R_X86_64_DTPOFF64 = 17
    R_X86_64_TPOFF64 = 18
    R_X86_64_TLSGD = 19
    R_X86_64_TLSLD = 20
    R_X86_64_DTPOFF32 = 21
    R_X86_64_GOTTPOFF = 22
    R_X86_64_TPOFF32 = 23
    R_X86_64_PC64 = 24
    R_X86_64_GOTOFF64 = 25
    R_X86_64_GOTPC32 = 26
    R_X86_64_GOT64 = 27
    R_X86_64_GOTPCREL64 = 28
    R_X86_64_GOTPC64 = 29
    R_X86_64_GOTPLT64 = 30
    R_X86_64_PLTOFF64 = 31
    R_X86_64_SIZE32 = 32
    R_X86_64_SIZE64 = 33
    R_X86_64_GOTPC32_TLSDESC = 34
    R_X86_64_TLSDESC_CALL = 35
    R_X86_64_TLSDESC = 36
    R_X86_64_IRELATIVE = 37
    R_X86_64_RELATIVE64 = 38
    R_X86_64_GOTPCRELX = 41
    R_X86_64_REX_GOTPCRELX = 42
    R_X86_64_NUM = 43
    DT_NIOS2_GP = 0x70000002


Elf_Ehdr = namedtuple('Elf_Ehdr', [
    'e_ident',
    'e_type',
    'e_machine',
    'e_version',
    'e_entry',
    'e_phoff',
    'e_shoff',
    'e_flags',
    'e_ehsize',
    'e_phentsize',
    'e_phnum',
    'e_shentsize',
    'e_shnum',
    'e_shstrndx',
])


Elf_Shdr = namedtuple('Elf_Shdr', [
    'sh_name',
    'sh_type',
    'sh_flags',
    'sh_addr',
    'sh_offset',
    'sh_size',
    'sh_link',
    'sh_info',
    'sh_addralign',
    'sh_entsize',
])


Elf_Sym = namedtuple('Elf_Sym', [
    'st_name',
    'st_info',
    'st_other',
    'st_shndx',
    'st_value',
    'st_size',
])


Elf_Phdr = namedtuple('Elf_Phdr', [
    'p_type',
    'p_flags',
    'p_offset',
    'p_vaddr',
    'p_paddr',
    'p_filesz',
    'p_memsz',
    'p_align',
])


Elf_Rela = namedtuple('Elf_Rela', [
    'r_offset',
    'r_sym',
    'r_type',
    'r_addend',
])


class ElfFile:
    def __init__(self, file):
        self.file = file
        self._ehdr = None
        self._shdrs = None
        self._shstrtab_shdr = None
        self._shdrs_by_name = None
        self._phdrs = None
        self._symbols = None
        self._symbols_by_name = None

    def ehdr(self):
        if self._ehdr is None:
            self.file.seek(0)
            buf = self.file.read(64)  # sizeof(struct Elf64_Ehdr)

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
            self._ehdr = Elf_Ehdr._make(struct.unpack_from(fmt, buf))
        return self._ehdr

    def shdrs(self):
        if self._shdrs is None:
            ehdr = self.ehdr()
            self.file.seek(ehdr.e_shoff)
            # TODO: e_shnum == 0
            buf = self.file.read(ehdr.e_shnum * ehdr.e_shentsize)

            if ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LLQQQQLLQQ'
            else:
                assert False
            self._shdrs = [Elf_Shdr._make(x) for x in struct.iter_unpack(fmt, buf)]
        return self._shdrs

    def shstrtab_shdr(self):
        if self._shstrtab_shdr is None:
            ehdr = self.ehdr()
            shdrs = self.shdrs()
            if ehdr.e_shstrndx == SHN_UNDEF:
                raise ValueError('no string table index in ELF header')
            elif ehdr.e_shstrndx == SHN_XINDEX:
                shdr = shdrs[shdrs[0].sh_link]
            else:
                if ehdr.e_shstrndx >= SHN_LORESERVE:
                    raise ValueError('invalid string table index in ELF header')
                shdr = shdrs[ehdr.e_shstrndx]
            if shdr.sh_type != SHT_STRTAB or shdr.sh_size == 0:
                raise ValueError('invalid string table section')
            self._shstrtab_shdr = shdr
        return self._shstrtab_shdr

    def shdrs_by_name(self):
        if self._shdrs_by_name is None:
            shstrtab_shdr = self.shstrtab_shdr()
            self.file.seek(shstrtab_shdr.sh_offset)
            shstrtab = self.file.read(shstrtab_shdr.sh_size)
            shdrs = self.shdrs()
            shdrs_by_name = {}
            for shdr in shdrs:
                if not shdr.sh_name:
                    continue
                end = shstrtab.index(b'\0', shdr.sh_name)
                name = shstrtab[shdr.sh_name:end].decode()
                if name in shdrs_by_name:
                    raise ValueError(f'duplicate section name {name!r}')
                shdrs_by_name[name] = shdr
            self._shdrs_by_name = shdrs_by_name
        return self._shdrs_by_name

    def shdr(self, name):
        return self.shdrs_by_name()[name]

    def phdrs(self):
        if self._phdrs is None:
            ehdr = self.ehdr()
            self.file.seek(ehdr.e_phoff)
            buf = self.file.read(ehdr.e_phnum * ehdr.e_phentsize)

            if ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LLQQQQQQ'
            else:
                assert False
            self._phdrs = [Elf_Phdr._make(x) for x in struct.iter_unpack(fmt, buf)]
        return self._phdrs

    def symbols(self):
        if self._symbols is None:
            ehdr = self.ehdr()
            shdr = self.shdr('.symtab')
            self.file.seek(shdr.sh_offset)
            buf = self.file.read(shdr.sh_size)

            if ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LBBHQQ'
            else:
                assert False
            self._symbols = [Elf_Sym._make(x) for x in struct.iter_unpack(fmt, buf)]
        return self._symbols

    def symbols_by_name(self):
        if self._symbols_by_name is None:
            strtab_shdr = self.shdr('.strtab')
            self.file.seek(strtab_shdr.sh_offset)
            strtab = self.file.read(strtab_shdr.sh_size)
            symbols = self.symbols()
            symbols_by_name = {}
            for symbol in symbols_by_name:
                if symbol.st_name:
                    end = strtab.index(b'\0', symbol.st_name)
                    name = strtab[symbol.st_name:end].decode()
                else:
                    name = ''
                try:
                    symbols_by_name[name].append(symbol)
                except KeyError:
                    symbols_by_name[name] = [symbol]
            self._symbols_by_name = symbols_by_name
        return self._symbols_by_name

    def read_section(self, shdr):
        ehdr = self.ehdr()
        self.file.seek(shdr.sh_offset)
        if shdr.sh_flags & SHF_COMPRESSED:
            if ehdr.e_ident[EI_DATA] == ELFDATA2LSB:
                fmt = '<'
            else:
                fmt = '>'

            if ehdr.e_ident[EI_CLASS] == ELFCLASS64:
                fmt += 'LxxxxQQ'
                ch_size = 24
            else:
                assert False
            buf = self.file.read(struct.calcsize(fmt))
            ch_type, ch_size, ch_addralign = struct.unpack(fmt, buf)
            buf = self.file.read(shdr.sh_size - len(buf))
            if ch_type == ELFCOMPRESS_ZLIB:
                buf = zlib.decompress(buf)
            else:
                raise NotImplementedError(f'unknown compression type {ch_type}')
        else:
            buf = self.file.read(shdr.sh_size)

        shdrs = self.shdrs()
        index = shdrs.index(shdr)
        for reloc_shdr in self.shdrs():
            if reloc_shdr.sh_info == index:
                break
        else:
            return buf

        buf = bytearray(buf)
        self.apply_relocations(reloc_shdr, buf)

        return buf

    def apply_relocations(self, reloc_shdr, buf):
        if self.ehdr().e_machine != EM_X86_64:
            raise NotImplementedError('only x86_64 relocations are implemented')

        if reloc_shdr.sh_type == SHT_REL:
            raise NotImplementedError('SHT_REL is not implemented')
        elif reloc_shdr.sh_type != SHT_RELA:
            raise ValueError('not a relocation section')

        cdef Py_buffer buffer
        cdef Py_buffer reloc_buffer
        cdef Py_buffer symtab_buffer
        cdef Py_ssize_t offset = 0
        cdef Py_ssize_t end = reloc_shdr.sh_size
        cdef Py_ssize_t symtab_offset
        cdef uint64_t r_offset
        cdef uint64_t r_info
        cdef uint32_t r_sym
        cdef uint32_t r_type
        cdef int64_t r_addend
        cdef uint32_t reloc_value32
        cdef uint64_t reloc_value64

        PyObject_GetBuffer(buf, &buffer, PyBUF_WRITABLE)
        try:
            reloc_buf = self.read_section(reloc_shdr)
            PyObject_GetBuffer(reloc_buf, &reloc_buffer, PyBUF_SIMPLE)
            try:
                symtab_shdr = self.shdrs()[reloc_shdr.sh_link]
                symtab_buf = self.read_section(symtab_shdr)
                PyObject_GetBuffer(symtab_buf, &symtab_buffer, PyBUF_SIMPLE)
                try:
                    offset = 0
                    while offset < end:
                        read_u64(&reloc_buffer, &offset, &r_offset)
                        read_u64(&reloc_buffer, &offset, &r_info)
                        read_s64(&reloc_buffer, &offset, &r_addend)
                        r_sym = r_info >> 32
                        r_type = r_info & UINT32_C(0xffffffff)

                        # sizeof(Elf64_Sym) * r_sym + offsetof(Elf64_Sym, st_value)
                        symtab_offset = 24 * r_sym + 8
                        if r_type == R_X86_64_NONE:
                            continue
                        elif r_type == R_X86_64_32:
                            read_u32(&symtab_buffer, &symtab_offset, &reloc_value32)
                            reloc_value32 += r_addend
                            write_u32(&buffer, r_offset, reloc_value32)
                        elif r_type == R_X86_64_64:
                            read_u64(&symtab_buffer, &symtab_offset, &reloc_value64)
                            reloc_value64 += r_addend
                            write_u64(&buffer, r_offset, reloc_value64)
                        else:
                            raise NotImplementedError(r_type)
                finally:
                    PyBuffer_Release(&symtab_buffer)
            finally:
                PyBuffer_Release(&reloc_buffer)
        finally:
            PyBuffer_Release(&buffer)
