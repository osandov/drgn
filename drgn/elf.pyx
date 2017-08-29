from collections import OrderedDict
from drgn.read cimport *
from libc.string cimport memchr


cdef extern from *:

    cdef int __BYTE_ORDER__
    cdef int __ORDER_LITTLE_ENDIAN__
    cdef int __ORDER_BIG_ENDIAN__


cdef extern from "<elf.h>":

    cdef int EI_MAG0
    cdef int EI_MAG1
    cdef int EI_MAG2
    cdef int EI_MAG3
    cdef int EI_CLASS
    cdef int EI_DATA
    cdef int EI_VERSION
    cdef int EI_PAD
    cdef int EI_NIDENT

    cdef int ELFMAG0
    cdef int ELFMAG1
    cdef int ELFMAG2
    cdef int ELFMAG3

    cdef int ELFCLASSNONE
    cdef int ELFCLASS32
    cdef int ELFCLASS64

    cdef int ELFDATANONE
    cdef int ELFDATA2LSB
    cdef int ELFDATA2MSB

    cdef int EV_NONE
    cdef int EV_CURRENT

    cdef int SHN_UNDEF
    cdef int SHN_LORESERVE
    cdef int SHN_LOPROC
    cdef int SHN_HIPROC
    cdef int SHN_LOOS
    cdef int SHN_HIOS
    cdef int SHN_ABS
    cdef int SHN_COMMON
    cdef int SHN_XINDEX
    cdef int SHN_HIRESERVE

    cdef int SHT_NULL
    cdef int SHT_PROGBITS
    cdef int SHT_SYMTAB
    cdef int SHT_STRTAB
    cdef int SHT_RELA
    cdef int SHT_HASH
    cdef int SHT_DYNAMIC
    cdef int SHT_NOTE
    cdef int SHT_NOBITS
    cdef int SHT_REL
    cdef int SHT_SHLIB
    cdef int SHT_DYNSYM
    cdef int SHT_INIT_ARRAY
    cdef int SHT_FINI_ARRAY
    cdef int SHT_PREINIT_ARRAY
    cdef int SHT_GROUP
    cdef int SHT_SYMTAB_SHNDX
    cdef int SHT_LOOS
    cdef int SHT_HIOS
    cdef int SHT_LOPROC
    cdef int SHT_HIPROC
    cdef int SHT_LOUSER
    cdef int SHT_HIUSER


cdef class Elf_Ehdr:
    pass


cdef class Elf_Shdr:
    pass


cdef class Elf_Sym:
    pass


cdef Elf_Ehdr parse_elf_header(Py_buffer *buffer):
    cdef Py_ssize_t offset = 0
    cdef Elf_Ehdr ehdr = Elf_Ehdr.__new__(Elf_Ehdr)

    read_buffer(buffer, &offset, &ehdr.e_ident, EI_NIDENT)

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 or ehdr.e_ident[EI_MAG1] != ELFMAG1 or
        ehdr.e_ident[EI_MAG2] != ELFMAG2 or ehdr.e_ident[EI_MAG3] != ELFMAG3):
        raise ValueError('not an ELF file')

    if ehdr.e_ident[EI_CLASS] != ELFCLASS64:
        raise NotImplementedError('32-bit ELF is not implemented')

    cdef int data
    if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__:
        data = ELFDATA2LSB
    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__:
        data = ELFDATA2MSB
    else:
        assert False
    if ehdr.e_ident[EI_DATA] != data:
        raise NotImplementedError('byte-swapping is not implemented')

    if ehdr.e_ident[EI_VERSION] != EV_CURRENT:
        raise ValueError('ELF version is not EV_CURRENT')

    read_u16(buffer, &offset, &ehdr.e_type)
    read_u16(buffer, &offset, &ehdr.e_machine)
    read_u32(buffer, &offset, &ehdr.e_version)
    read_u64(buffer, &offset, &ehdr.e_entry)
    read_u64(buffer, &offset, &ehdr.e_phoff)
    read_u64(buffer, &offset, &ehdr.e_shoff)
    read_u32(buffer, &offset, &ehdr.e_flags)
    read_u16(buffer, &offset, &ehdr.e_ehsize)
    read_u16(buffer, &offset, &ehdr.e_phentsize)
    read_u16(buffer, &offset, &ehdr.e_phnum)
    read_u16(buffer, &offset, &ehdr.e_shentsize)
    read_u16(buffer, &offset, &ehdr.e_shnum)
    read_u16(buffer, &offset, &ehdr.e_shstrndx)

    return ehdr


cdef Elf_Shdr parse_elf64_shdr(Py_buffer *buffer, Py_ssize_t *offset):
    cdef Elf_Shdr shdr = Elf_Shdr.__new__(Elf_Shdr)

    read_u32(buffer, offset, &shdr.sh_name)
    read_u32(buffer, offset, &shdr.sh_type)
    read_u64(buffer, offset, &shdr.sh_flags)
    read_u64(buffer, offset, &shdr.sh_addr)
    read_u64(buffer, offset, &shdr.sh_offset)
    read_u64(buffer, offset, &shdr.sh_size)
    read_u32(buffer, offset, &shdr.sh_link)
    read_u32(buffer, offset, &shdr.sh_info)
    read_u64(buffer, offset, &shdr.sh_addralign)
    read_u64(buffer, offset, &shdr.sh_entsize)

    return shdr


cdef object parse_elf_sections(Py_buffer *buffer, Elf_Ehdr ehdr):
    cdef uint64_t shnum
    cdef Py_ssize_t offset

    if ehdr.e_shnum == 0:
        offset = ehdr.e_shoff + 32
        read_u64(buffer, &offset, &shnum)
    else:
        shnum = ehdr.e_shnum

    offset = ehdr.e_shoff
    shdrs = []
    for i in range(shnum):
        shdrs.append(parse_elf64_shdr(buffer, &offset))

    sections = OrderedDict()

    cdef Elf_Shdr strtab_section
    if ehdr.e_shstrndx == SHN_UNDEF:
        raise ValueError('no string table index in ELF header')
    elif ehdr.e_shstrndx == SHN_XINDEX:
        strtab_section = shdrs[shdrs[0].sh_link]
    else:
        if ehdr.e_shstrndx >= SHN_LORESERVE:
            raise ValueError('invalid string table index in ELF header')
        strtab_section = shdrs[ehdr.e_shstrndx]
    if strtab_section.sh_type != SHT_STRTAB or strtab_section.sh_size == 0:
            raise ValueError('invalid string table section')
    strtab_offset = strtab_section.sh_offset

    cdef Elf_Shdr shdr
    for shdr in shdrs:
        if shdr.sh_name:
            offset = strtab_offset + shdr.sh_name
            section_name = read_str(buffer, &offset)
        else:
            section_name = ''
        if section_name in sections:
                raise ValueError('duplicate section name')
        sections[section_name] = shdr
    return sections


cdef Elf_Sym parse_elf64_sym(Py_buffer *buffer, Py_ssize_t *offset):
    cdef Elf_Sym sym = Elf_Sym.__new__(Elf_Sym)

    read_u32(buffer, offset, &sym.st_name)
    read_u8(buffer, offset, &sym.st_info)
    read_u8(buffer, offset, &sym.st_other)
    read_u16(buffer, offset, &sym.st_shndx)
    read_u64(buffer, offset, &sym.st_value)
    read_u64(buffer, offset, &sym.st_size)

    return sym


cdef list parse_elf_symtab(Py_buffer *buffer, Elf_Shdr shdr):
    cdef uint64_t symnum = shdr.sh_size / 24  # XXX: sizeof(Elf64_Sym)
    cdef Py_ssize_t offset = shdr.sh_offset

    cdef list syms = []
    for i in range(symnum):
        syms.append(parse_elf64_sym(buffer, &offset))
    return syms
