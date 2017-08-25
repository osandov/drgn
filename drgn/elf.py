"""
Minimal ELF format parser implementing only what's needed for DWARF.
"""

import ctypes
from collections import namedtuple, OrderedDict

# e_ident
EI_MAG0    = 0 # File identification
EI_MAG1    = 1 # File identification
EI_MAG2    = 2 # File identification
EI_MAG3    = 3 # File identification
EI_CLASS   = 4 # File class
EI_DATA    = 5 # Data encoding
EI_VERSION = 6 # File version
EI_PAD     = 7 # Start of padding byte
EI_NIDENT  = 16

# e_ident[EI_MAG*]
ELFMAG0   = 0x7f
ELFMAG1   = ord('E')
ELFMAG2   = ord('L')
ELFMAG3   = ord('F')

# e_ident[EI_CLASS]
ELFCLASSNONE = 0  # Invalid class
ELFCLASS32   = 1  # 32-bit objects
ELFCLASS64   = 2  # 64-bit objects

# e_ident[EI_DATA]
ELFDATANONE = 0  # Invalid data encoding
ELFDATA2LSB = 1  # Little-endian
ELFDATA2MSB = 2  # Big-endian

# e_type
ET_NONE   = 0       # No file type
ET_REL    = 1       # Relocatable file
ET_EXEC   = 2       # Executable file
ET_DYN    = 3       # Shared object file
ET_CORE   = 4       # Core file
ET_LOPROC = 0xff00  # Processor-specific
ET_HIPROC = 0xffff  # Processor-specific

# e_machine
EM_NONE  = 0  # No machine
EM_M32   = 1  # AT&T WE 32100
EM_SPARC = 2  # SPARC
EM_386   = 3  # Intel 80386
EM_68K   = 4  # Motorola 68000
EM_88K   = 5  # Motorola 88000
EM_860   = 7  # Intel 80860
EM_MIPS  = 8  # MIPS RS3000

# e_version
EV_NONE    = 0  # Invalid version
EV_CURRENT = 1  # Current version

SHN_UNDEF     = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC    = 0xff00
SHN_HIPROC    = 0xff1f
SHN_LOOS      = 0xff20
SHN_HIOS      = 0xff3f
SHN_ABS       = 0xfff1
SHN_COMMON    = 0xfff2
SHN_XINDEX    = 0xffff
SHN_HIRESERVE = 0xffff

SHT_NULL          = 0
SHT_PROGBITS      = 1
SHT_SYMTAB        = 2
SHT_STRTAB        = 3
SHT_RELA          = 4
SHT_HASH          = 5
SHT_DYNAMIC       = 6
SHT_NOTE          = 7
SHT_NOBITS        = 8
SHT_REL           = 9
SHT_SHLIB         = 10
SHT_DYNSYM        = 11
SHT_INIT_ARRAY    = 14
SHT_FINI_ARRAY    = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP         = 17
SHT_SYMTAB_SHNDX  = 18
SHT_LOOS          = 0x60000000
SHT_HIOS          = 0x6fffffff
SHT_LOPROC        = 0x70000000
SHT_HIPROC        = 0x7fffffff
SHT_LOUSER        = 0x80000000
SHT_HIUSER        = 0xffffffff

Elf64_Addr = ctypes.c_uint64
Elf64_Half = ctypes.c_uint16
Elf64_Off = ctypes.c_uint64
Elf64_Sword = ctypes.c_int32
Elf64_Word = ctypes.c_uint32
Elf64_Sxword = ctypes.c_int64
Elf64_Xword = ctypes.c_uint64
Elf64_Section = ctypes.c_uint16


class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [
        ('e_ident', ctypes.c_ubyte * EI_NIDENT),
        ('e_type', Elf64_Half),
        ('e_machine', Elf64_Half),
        ('e_version', Elf64_Word),
        ('e_entry', Elf64_Addr),
        ('e_phoff', Elf64_Off),
        ('e_shoff', Elf64_Off),
        ('e_flags', Elf64_Word),
        ('e_ehsize', Elf64_Half),
        ('e_phentsize', Elf64_Half),
        ('e_phnum', Elf64_Half),
        ('e_shentsize', Elf64_Half),
        ('e_shnum', Elf64_Half),
        ('e_shstrndx', Elf64_Half),
    ]


class Elf64_Shdr(ctypes.Structure):
    _fields_ = [
        ('sh_name', Elf64_Word),
        ('sh_type', Elf64_Word),
        ('sh_flags', Elf64_Xword),
        ('sh_addr', Elf64_Addr),
        ('sh_offset', Elf64_Off),
        ('sh_size', Elf64_Xword),
        ('sh_link', Elf64_Word),
        ('sh_info', Elf64_Word),
        ('sh_addralign', Elf64_Xword),
        ('sh_entsize', Elf64_Xword),
    ]


class Elf64_Sym(ctypes.Structure):
    _fields_ = [
        ('st_name', Elf64_Word),
        ('st_info', ctypes.c_ubyte),
        ('st_other', ctypes.c_ubyte),
        ('st_shndx', Elf64_Section),
        ('st_value', Elf64_Addr),
        ('st_size', Elf64_Xword),
    ]


def parse_elf_header(buffer):
    e_ident = buffer[:EI_NIDENT]
    if (len(e_ident) < EI_NIDENT or
        e_ident[EI_MAG0] != ELFMAG0 or e_ident[EI_MAG1] != ELFMAG1 or
        e_ident[EI_MAG2] != ELFMAG2 or e_ident[EI_MAG3] != ELFMAG3):
        raise ValueError('not an ELF file')

    ehdr = Elf64_Ehdr.from_buffer_copy(buffer)
    assert ehdr.e_ident[EI_CLASS] == ELFCLASS64
    assert ehdr.e_ident[EI_DATA] == ELFDATA2LSB
    assert ehdr.e_ident[EI_VERSION] == EV_CURRENT
    assert ehdr.e_shentsize == ctypes.sizeof(Elf64_Shdr)
    return ehdr


def parse_elf_sections(buffer, ehdr):
    if ehdr.e_shnum == 0:
        shnum = Elf64_Shdr.from_buffer_copy(buffer, ehdr.e_shoff).sh_size
    else:
        shnum = ehdr.e_shnum
    shdrs = (Elf64_Shdr * shnum).from_buffer_copy(buffer, ehdr.e_shoff)

    sections = OrderedDict()

    assert ehdr.e_shstrndx != SHN_UNDEF
    if ehdr.e_shstrndx == SHN_XINDEX:
        strtab_section = shdrs[shdrs[0].sh_link]
    else:
        assert ehdr.e_shstrndx < SHN_LORESERVE
        strtab_section = shdrs[ehdr.e_shstrndx]
    assert strtab_section.sh_type == SHT_STRTAB
    assert strtab_section.sh_size > 0
    strtab_offset = strtab_section.sh_offset

    for shdr in shdrs:
        if shdr.sh_name:
            offset = strtab_offset + shdr.sh_name
            nul = buffer.find(b'\0', offset)
            section_name = buffer[offset:nul].decode('ascii')
        else:
            section_name = ''
        assert section_name not in sections
        sections[section_name] = shdr
    return sections


"""
    def symtab(self):
        try:
            return self._symtab
        except AttributeError:
            pass

        shdr = self.section(b'.symtab')

        symnum = shdr.sh_size // ctypes.sizeof(Elf64_Sym)
        self._symtab = (Elf64_Sym * symnum).from_buffer_copy(self._mm, shdr.sh_offset)
        return self._symtab

    def symbol(self, name, *, all=False):
        try:
            syms = self._symtab_by_name[name]
            if all:
                return syms
            else:
                if len(syms) > 1:
                    raise ValueError('multiple symbols with given name')
                return syms[0]
        except AttributeError:
            pass

        strtab_offset = self.section(b'.strtab').sh_offset

        symtab_by_name = {}
        for sym in self.symtab():
            if sym.st_name:
                sym_name = string_at(self._mm, strtab_offset + sym.st_name)
            else:
                sym_name = b''
            try:
                symtab_by_name[sym_name].append(sym)
            except KeyError:
                symtab_by_name[sym_name] = [sym]
        self._symtab_by_name = symtab_by_name
        return self.symbol(name, all=all)
"""
