from collections import namedtuple
import os.path
import struct

from tests.dwarf import DW_AT, DW_FORM, DW_TAG


DwarfAttrib = namedtuple('DwarfAttrib', ['name', 'form', 'value'])
DwarfDie = namedtuple('DwarfAttrib', ['tag', 'attribs', 'children'])
DwarfDie.__new__.__defaults__ = (None,)


def _append_uleb128(buf, value):
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            buf.append(byte | 0x80)
        else:
            buf.append(byte)
            break


def _append_sleb128(buf, value):
    while True:
        byte = value & 0x7f
        value >>= 7
        if (not value and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            buf.append(byte)
            break
        else:
            buf.append(byte | 0x80)


def _compile_debug_abbrev(buf, cu_die):
    code = 1
    def aux(die):
        nonlocal code
        _append_uleb128(buf, code)
        code += 1
        _append_uleb128(buf, die.tag)
        buf.append(bool(die.children))
        for attrib in die.attribs:
            _append_uleb128(buf, attrib.name)
            _append_uleb128(buf, attrib.form)
        buf.append(0)
        buf.append(0)
        if die.children:
            for child in die.children:
                aux(child)
    aux(cu_die)
    buf.append(0)


def _compile_debug_info(buf, cu_die, little_endian, bits):
    cu_offset = len(buf)
    byteorder = 'little' if little_endian else 'big'

    buf.extend(b'\0\0\0\0')  # unit_length
    buf.extend((4).to_bytes(2, byteorder))  # version
    buf.extend((0).to_bytes(4, byteorder))  # debug_abbrev_offset
    buf.append(bits // 8)  # address_size

    die_offsets = []
    relocations = []
    code = 1
    decl_file = 1
    def aux(die, depth):
        nonlocal code, decl_file
        if depth == 1:
            die_offsets.append(len(buf) - cu_offset)
        _append_uleb128(buf, code)
        code += 1
        for attrib in die.attribs:
            if attrib.name == DW_AT.decl_file:
                value = decl_file
                decl_file += 1
            else:
                value = attrib.value
            if attrib.form == DW_FORM.addr:
                buf.extend(value.to_bytes(bits // 8, byteorder))
            elif attrib.form == DW_FORM.data1:
                buf.append(value)
            elif attrib.form == DW_FORM.udata:
                _append_uleb128(buf, value)
            elif attrib.form == DW_FORM.sdata:
                _append_sleb128(buf, value)
            elif attrib.form == DW_FORM.string:
                buf.extend(value.encode())
                buf.append(0)
            elif attrib.form == DW_FORM.ref4:
                relocations.append((len(buf), value))
                buf.extend(b'\0\0\0\0')
            elif attrib.form == DW_FORM.sec_offset:
                buf.extend(b'\0\0\0\0')
            elif attrib.form == DW_FORM.flag_present:
                pass
            elif attrib.form == DW_FORM.exprloc:
                _append_uleb128(buf, len(value))
                buf.extend(value)
            else:
                assert False, attrib.form
        if die.children:
            for child in die.children:
                aux(child, depth + 1)
            buf.append(0)
    aux(cu_die, 0)

    unit_length = len(buf) - cu_offset - 4
    buf[cu_offset:cu_offset + 4] = unit_length.to_bytes(4, byteorder)

    for offset, index in relocations:
        buf[offset:offset + 4] = die_offsets[index].to_bytes(4, byteorder)


def _compile_debug_line(buf, cu_die, little_endian):
    offset = len(buf)
    byteorder = 'little' if little_endian else 'big'

    buf.extend(b'\0\0\0\0') # unit_length
    buf.extend((4).to_bytes(2, byteorder))  # version
    buf.extend(b'\0\0\0\0') # header_length
    buf.append(1)  # minimum_instruction_length
    buf.append(1)  # maximum_operations_per_instruction
    buf.append(1)  # default_is_stmt
    buf.append(1)  # line_base
    buf.append(1)  # line_range
    buf.append(1)  # opcode_base
    # Don't need standard_opcode_length

    def compile_include_directories(die):
        for attrib in die.attribs:
            if attrib.name != DW_AT.decl_file:
                continue
            dirname = os.path.dirname(attrib.value)
            if dirname:
                buf.extend(dirname.encode('ascii'))
                buf.append(0)
        if die.children:
            for child in die.children:
                compile_include_directories(child)
    compile_include_directories(cu_die)
    buf.append(0)

    decl_file = 1
    directory = 1
    def compile_file_names(die):
        nonlocal decl_file, directory
        for attrib in die.attribs:
            if attrib.name != DW_AT.decl_file:
                continue
            dirname, basename = os.path.split(attrib.value)
            buf.extend(basename.encode('ascii'))
            buf.append(0)
            # directory index
            if dirname:
                _append_uleb128(buf, directory)
                directory += 1
            else:
                _append_uleb128(buf, 0)
            _append_uleb128(buf, 0)  # mtime
            _append_uleb128(buf, 0)  # size
        if die.children:
            for child in die.children:
                compile_file_names(child)
    compile_file_names(cu_die)
    buf.append(0)

    unit_length = len(buf) - offset - 4
    buf[offset:offset + 4] = unit_length.to_bytes(4, byteorder)
    header_length = unit_length - 6
    buf[offset + 6:offset + 10] = header_length.to_bytes(4, byteorder)


def _align_dwarf(buf, bits):
    align = bits // 8
    if len(buf) % align != 0:
        buf.extend(b'\0' * (align - len(buf) % align))


def compile_dwarf(dies, little_endian=True, bits=64):
    if isinstance(dies, DwarfDie):
        dies = (dies,)
    assert all(isinstance(die, DwarfDie) for die in dies)
    cu_die = DwarfDie(DW_TAG.compile_unit, [
        DwarfAttrib(DW_AT.stmt_list, DW_FORM.sec_offset, 0),
    ], dies)

    endian = '<' if little_endian else '>'
    if bits == 64:
        ehdr_struct = struct.Struct(endian + '16BHHIQQQIHHHHHH')
        shdr_struct = struct.Struct(endian + 'IIQQQQIIQQ')
        e_machine = 62 if little_endian else 43  # EM_X86_64 or EM_SPARCV9
    else:
        assert bits == 32
        ehdr_struct = struct.Struct(endian + '16BHHIIIIIHHHHHH')
        shdr_struct = struct.Struct(endian + '10I')
        e_machine = 3 if little_endian else 8  # EM_386 or EM_MIPS

    sections = [
        '.shstrtab',
        '.debug_abbrev',
        '.debug_info',
        '.debug_line',
        '.debug_str',
    ]
    buf = bytearray(ehdr_struct.size + shdr_struct.size * (len(sections) + 1))
    ehdr_struct.pack_into(
        buf, 0,
        0x7f,  # ELFMAG0
        ord('E'),  # ELFMAG1
        ord('L'),  # ELFMAG2
        ord('F'),  # ELFMAG3
        2 if bits == 64 else 1,  # EI_CLASS = ELFCLASS64 or ELFCLASS32
        1 if little_endian else 2,  # EI_DATA = ELFDATA2LSB or ELFDATA2MSB
        1,  # EI_VERSION = EV_CURRENT
        0,  # EI_OSABI = ELFOSABI_NONE
        0,  # EI_ABIVERSION
        0, 0, 0, 0, 0, 0, 0,  # EI_PAD
        2,  # e_type = ET_EXEC
        e_machine,
        1,  # e_version = EV_CURRENT
        0,  # e_entry
        0,  # e_phoff
        ehdr_struct.size,  # e_shoff
        0,  # e_flags
        ehdr_struct.size,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        shdr_struct.size,  # e_shentsize,
        len(sections) + 1,  # e_shnum,
        1,  # e_shstrndix
    )

    shnum = 1

    sh_offset = len(buf)
    buf.append(0)
    section_names = {}
    for section in sections:
        section_names[section] = len(buf) - sh_offset
        buf.extend(section.encode())
        buf.append(0)
    shdr_struct.pack_into(
        buf, ehdr_struct.size + shnum * shdr_struct.size,
        section_names['.shstrtab'],  # sh_name
        3,  # sh_type = SHT_STRTAB
        0,  # sh_flags
        0,  # sh_addr
        sh_offset,  # sh_offset
        len(buf) - sh_offset,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    shnum += 1

    _align_dwarf(buf, bits)
    sh_offset = len(buf)
    _compile_debug_abbrev(buf, cu_die)
    shdr_struct.pack_into(
        buf, ehdr_struct.size + shnum * shdr_struct.size,
        section_names['.debug_abbrev'],  # sh_name
        1,  # sh_type = SHT_PROGBITS
        0,  # sh_flags
        0,  # sh_addr
        sh_offset,  # sh_offset
        len(buf) - sh_offset,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    shnum += 1

    _align_dwarf(buf, bits)
    sh_offset = len(buf)
    _compile_debug_info(buf, cu_die, little_endian, bits)
    shdr_struct.pack_into(
        buf, ehdr_struct.size + shnum * shdr_struct.size,
        section_names['.debug_info'],  # sh_name
        1,  # sh_type = SHT_PROGBITS
        0,  # sh_flags
        0,  # sh_addr
        sh_offset,  # sh_offset
        len(buf) - sh_offset,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    shnum += 1

    _align_dwarf(buf, bits)
    sh_offset = len(buf)
    _compile_debug_line(buf, cu_die, little_endian)
    shdr_struct.pack_into(
        buf, ehdr_struct.size + shnum * shdr_struct.size,
        section_names['.debug_line'],  # sh_name
        1,  # sh_type = SHT_PROGBITS
        0,  # sh_flags
        0,  # sh_addr
        sh_offset,  # sh_offset
        len(buf) - sh_offset,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    shnum += 1

    sh_offset = len(buf)
    buf.append(0)
    shdr_struct.pack_into(
        buf, ehdr_struct.size + shnum * shdr_struct.size,
        section_names['.debug_str'],  # sh_name
        1,  # sh_type = SHT_PROGBITS
        0,  # sh_flags
        0,  # sh_addr
        sh_offset,  # sh_offset
        len(buf) - sh_offset,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    shnum += 1

    assert shnum == len(sections) + 1

    return bytes(buf)
