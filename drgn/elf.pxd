from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t


cdef class Elf_Ehdr:
    cdef public unsigned char e_ident[16]
    cdef public uint16_t e_type
    cdef public uint16_t e_machine
    cdef public uint32_t e_version
    cdef public uint64_t e_entry
    cdef public uint64_t e_phoff
    cdef public uint64_t e_shoff
    cdef public uint32_t e_flags
    cdef public uint16_t e_ehsize
    cdef public uint16_t e_phentsize
    cdef public uint16_t e_phnum
    cdef public uint16_t e_shentsize
    cdef public uint16_t e_shnum
    cdef public uint16_t e_shstrndx


cdef class Elf_Shdr:
    cdef public uint32_t sh_name
    cdef public uint32_t sh_type
    cdef public uint64_t sh_flags
    cdef public uint64_t sh_addr
    cdef public uint64_t sh_offset
    cdef public uint64_t sh_size
    cdef public uint32_t sh_link
    cdef public uint32_t sh_info
    cdef public uint64_t sh_addralign
    cdef public uint64_t sh_entsize


cdef class Elf_Sym:
    cdef public uint32_t st_name
    cdef public uint8_t st_info
    cdef public uint8_t st_other
    cdef public uint16_t st_shndx
    cdef public uint64_t st_value
    cdef public uint64_t st_size


cdef Elf_Ehdr parse_elf_header(Py_buffer *buffer)
cdef object parse_elf_sections(Py_buffer *buffer, Elf_Ehdr ehdr)
cdef list parse_elf_symtab(Py_buffer *buffer, Elf_Shdr shdr)
