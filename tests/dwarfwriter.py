# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import namedtuple
import os.path

from tests.dwarf import DW_AT, DW_FORM, DW_TAG
from tests.elf import ET, PT, SHT
from tests.elfwriter import ElfSection, create_elf_file

DwarfAttrib = namedtuple("DwarfAttrib", ["name", "form", "value"])
DwarfDie = namedtuple("DwarfAttrib", ["tag", "attribs", "children"])
DwarfDie.__new__.__defaults__ = (None,)


def _append_uleb128(buf, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            buf.append(byte | 0x80)
        else:
            buf.append(byte)
            break


def _append_sleb128(buf, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if (not value and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            buf.append(byte)
            break
        else:
            buf.append(byte | 0x80)


def _compile_debug_abbrev(cu_die):
    buf = bytearray()
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
    return buf


def _compile_debug_info(cu_die, little_endian, bits):
    buf = bytearray()
    byteorder = "little" if little_endian else "big"

    buf.extend(b"\0\0\0\0")  # unit_length
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
            die_offsets.append(len(buf))
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
            elif attrib.form == DW_FORM.data2:
                buf.extend(value.to_bytes(2, byteorder))
            elif attrib.form == DW_FORM.data4:
                buf.extend(value.to_bytes(4, byteorder))
            elif attrib.form == DW_FORM.data8:
                buf.extend(value.to_bytes(8, byteorder))
            elif attrib.form == DW_FORM.udata:
                _append_uleb128(buf, value)
            elif attrib.form == DW_FORM.sdata:
                _append_sleb128(buf, value)
            elif attrib.form == DW_FORM.block1:
                buf.append(len(value))
                buf.extend(value)
            elif attrib.form == DW_FORM.string:
                buf.extend(value.encode())
                buf.append(0)
            elif attrib.form == DW_FORM.ref4:
                relocations.append((len(buf), value))
                buf.extend(b"\0\0\0\0")
            elif attrib.form == DW_FORM.sec_offset:
                buf.extend(b"\0\0\0\0")
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

    unit_length = len(buf) - 4
    buf[:4] = unit_length.to_bytes(4, byteorder)

    for offset, index in relocations:
        buf[offset : offset + 4] = die_offsets[index].to_bytes(4, byteorder)
    return buf


def _compile_debug_line(cu_die, little_endian):
    buf = bytearray()
    byteorder = "little" if little_endian else "big"

    buf.extend(b"\0\0\0\0")  # unit_length
    buf.extend((4).to_bytes(2, byteorder))  # version
    buf.extend(b"\0\0\0\0")  # header_length
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
                buf.extend(dirname.encode("ascii"))
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
            buf.extend(basename.encode("ascii"))
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

    unit_length = len(buf) - 4
    buf[:4] = unit_length.to_bytes(4, byteorder)
    header_length = unit_length - 6
    buf[6:10] = header_length.to_bytes(4, byteorder)
    return buf


def compile_dwarf(dies, little_endian=True, bits=64, *, lang=None):
    if isinstance(dies, DwarfDie):
        dies = (dies,)
    assert all(isinstance(die, DwarfDie) for die in dies)
    cu_attribs = [
        DwarfAttrib(DW_AT.comp_dir, DW_FORM.string, "/usr/src"),
        DwarfAttrib(DW_AT.stmt_list, DW_FORM.sec_offset, 0),
    ]
    if lang is not None:
        cu_attribs.append(DwarfAttrib(DW_AT.language, DW_FORM.data1, lang))
    cu_die = DwarfDie(DW_TAG.compile_unit, cu_attribs, dies)

    return create_elf_file(
        ET.EXEC,
        [
            ElfSection(p_type=PT.LOAD, vaddr=0xFFFF0000, data=b""),
            ElfSection(
                name=".debug_abbrev",
                sh_type=SHT.PROGBITS,
                data=_compile_debug_abbrev(cu_die),
            ),
            ElfSection(
                name=".debug_info",
                sh_type=SHT.PROGBITS,
                data=_compile_debug_info(cu_die, little_endian, bits),
            ),
            ElfSection(
                name=".debug_line",
                sh_type=SHT.PROGBITS,
                data=_compile_debug_line(cu_die, little_endian),
            ),
            ElfSection(name=".debug_str", sh_type=SHT.PROGBITS, data=b"\0"),
        ],
        little_endian=little_endian,
        bits=bits,
    )
