# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os.path
from typing import Any, NamedTuple, Optional, Sequence, Union

from tests.assembler import _append_sleb128, _append_uleb128
from tests.dwarf import DW_AT, DW_FORM, DW_TAG
from tests.elf import ET, SHT
from tests.elfwriter import ElfSection, create_elf_file


class DwarfAttrib(NamedTuple):
    name: str
    form: DW_FORM
    value: Any


class DwarfLabel(NamedTuple):
    name: str


class DwarfDie(NamedTuple):
    tag: DW_TAG
    attribs: Sequence[DwarfAttrib]
    children: Sequence[Union["DwarfDie", DwarfLabel]] = ()
    type_signature: Optional[int] = None
    type_offset: Optional[str] = None


def _compile_debug_abbrev(unit_dies, use_dw_form_indirect):
    buf = bytearray()
    code = 1

    def aux(die):
        if isinstance(die, DwarfLabel):
            return
        nonlocal code
        _append_uleb128(buf, code)
        code += 1
        _append_uleb128(buf, die.tag)
        buf.append(bool(die.children))
        for attrib in die.attribs:
            _append_uleb128(buf, attrib.name)
            _append_uleb128(
                buf, DW_FORM.indirect if use_dw_form_indirect else attrib.form
            )
        buf.append(0)
        buf.append(0)
        if die.children:
            for child in die.children:
                aux(child)

    for die in unit_dies:
        aux(die)
    buf.append(0)
    return buf


def _compile_debug_info(unit_dies, little_endian, bits, use_dw_form_indirect):
    byteorder = "little" if little_endian else "big"
    all_labels = set()
    labels = {}
    relocations = []
    code = 1
    decl_file = 1

    def aux(buf, die, depth):
        if isinstance(die, DwarfLabel):
            # For now, labels are only supported within a unit, but make sure
            # they're unique across all units.
            if die.name in all_labels:
                raise ValueError(f"duplicate label {die.name!r}")
            all_labels.add(die.name)
            labels[die.name] = len(buf)
            return

        nonlocal code, decl_file
        _append_uleb128(buf, code)
        code += 1
        for attrib in die.attribs:
            if use_dw_form_indirect:
                _append_uleb128(buf, attrib.form)
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
            elif attrib.form == DW_FORM.block:
                _append_uleb128(buf, len(value))
                buf.extend(value)
            elif attrib.form == DW_FORM.block1:
                buf.append(len(value))
                buf.extend(value)
            elif attrib.form == DW_FORM.string:
                buf.extend(value.encode())
                buf.append(0)
            elif attrib.form == DW_FORM.ref4:
                relocations.append((len(buf), value))
                buf.extend(b"\0\0\0\0")
            elif attrib.form == DW_FORM.ref_sig8:
                buf.extend(value.to_bytes(8, byteorder))
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
                aux(buf, child, depth + 1)
            buf.append(0)

    debug_info = bytearray()
    debug_types = bytearray()
    for die in unit_dies:
        labels.clear()
        relocations.clear()
        buf = debug_info if die.tag == DW_TAG.compile_unit else debug_types
        orig_len = len(buf)
        buf.extend(b"\0\0\0\0")  # unit_length
        buf.extend((4).to_bytes(2, byteorder))  # version
        buf.extend((0).to_bytes(4, byteorder))  # debug_abbrev_offset
        buf.append(bits // 8)  # address_size

        if die.tag == DW_TAG.type_unit:
            buf.extend(die.type_signature.to_bytes(8, byteorder))
            relocations.append((len(buf), die.type_offset))
            buf.extend(b"\0\0\0\0")  # type_offset
        else:
            assert die.type_signature is None
            assert die.type_offset is None

        aux(buf, die, 0)

        unit_length = len(buf) - orig_len - 4
        buf[orig_len : orig_len + 4] = unit_length.to_bytes(4, byteorder)

        for offset, label in relocations:
            die_offset = labels[label] - orig_len
            buf[offset : offset + 4] = die_offset.to_bytes(4, byteorder)
    return debug_info, debug_types


def _compile_debug_line(unit_dies, little_endian):
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
        if isinstance(die, DwarfLabel):
            return
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

    for die in unit_dies:
        compile_include_directories(die)
    buf.append(0)

    decl_file = 1
    directory = 1

    def compile_file_names(die):
        if isinstance(die, DwarfLabel):
            return
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

    for die in unit_dies:
        compile_file_names(die)
    buf.append(0)

    unit_length = len(buf) - 4
    buf[:4] = unit_length.to_bytes(4, byteorder)
    header_length = unit_length - 6
    buf[6:10] = header_length.to_bytes(4, byteorder)
    return buf


_UNIT_TAGS = frozenset({DW_TAG.type_unit, DW_TAG.compile_unit})


def dwarf_sections(
    dies, little_endian=True, bits=64, *, lang=None, use_dw_form_indirect=False
):
    if isinstance(dies, DwarfDie):
        dies = (dies,)
    assert all(isinstance(die, (DwarfDie, DwarfLabel)) for die in dies)

    if any(isinstance(die, DwarfDie) and die.tag in _UNIT_TAGS for die in dies):
        assert all(isinstance(die, DwarfLabel) or die.tag in _UNIT_TAGS for die in dies)
        unit_dies = dies
    else:
        unit_dies = (DwarfDie(DW_TAG.compile_unit, (), dies),)

    unit_attribs = [DwarfAttrib(DW_AT.stmt_list, DW_FORM.sec_offset, 0)]
    if lang is not None:
        unit_attribs.append(DwarfAttrib(DW_AT.language, DW_FORM.data1, lang))
    cu_attribs = unit_attribs + [
        DwarfAttrib(DW_AT.comp_dir, DW_FORM.string, "/usr/src")
    ]

    unit_dies = [
        die._replace(
            attribs=list(die.attribs)
            + (cu_attribs if die.tag == DW_TAG.compile_unit else unit_attribs)
        )
        for die in unit_dies
    ]

    debug_info, debug_types = _compile_debug_info(
        unit_dies, little_endian, bits, use_dw_form_indirect
    )

    sections = [
        ElfSection(
            name=".debug_abbrev",
            sh_type=SHT.PROGBITS,
            data=_compile_debug_abbrev(unit_dies, use_dw_form_indirect),
        ),
        ElfSection(name=".debug_info", sh_type=SHT.PROGBITS, data=debug_info),
        ElfSection(
            name=".debug_line",
            sh_type=SHT.PROGBITS,
            data=_compile_debug_line(unit_dies, little_endian),
        ),
        ElfSection(name=".debug_str", sh_type=SHT.PROGBITS, data=b"\0"),
    ]
    if debug_types:
        sections.append(
            ElfSection(name=".debug_types", sh_type=SHT.PROGBITS, data=debug_types)
        )
    return sections


def compile_dwarf(
    dies, little_endian=True, bits=64, *, lang=None, use_dw_form_indirect=False
):
    return create_elf_file(
        ET.EXEC,
        dwarf_sections(
            dies,
            little_endian=little_endian,
            bits=bits,
            lang=lang,
            use_dw_form_indirect=use_dw_form_indirect,
        ),
        little_endian=little_endian,
        bits=bits,
    )
