# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from collections import OrderedDict
import os.path
from typing import Any, NamedTuple, Optional, Sequence, Union
import zlib

from tests.assembler import _append_sleb128, _append_uleb128
from tests.dwarf import DW_AT, DW_FORM, DW_LNCT, DW_TAG, DW_UT
from tests.elf import ET, SHT
from tests.elfwriter import ElfSection, create_elf_file


class DwarfAttrib(NamedTuple):
    name: DW_AT
    form: DW_FORM
    value: Any


class DwarfLabel(NamedTuple):
    name: str


class DwarfDie(NamedTuple):
    tag: DW_TAG
    attribs: Sequence[DwarfAttrib]
    children: Sequence[Union["DwarfDie", DwarfLabel]] = ()


class DwarfUnit(NamedTuple):
    type: DW_UT
    die: DwarfDie
    dwo_id: Optional[int] = None
    type_signature: Optional[int] = None
    type_offset: Optional[str] = None


def _compile_debug_abbrev(units, use_dw_form_indirect):
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

    for unit in units:
        aux(unit.die)
    buf.append(0)
    return buf


def _compile_debug_info(units, little_endian, bits, version, use_dw_form_indirect):
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
    for unit in units:
        labels.clear()
        relocations.clear()
        decl_file = 1
        if version == 4 and unit.type in (DW_UT.type, DW_UT.split_type):
            buf = debug_types
        else:
            buf = debug_info
        orig_len = len(buf)
        buf.extend(b"\0\0\0\0")  # unit_length
        buf.extend(version.to_bytes(2, byteorder))  # version
        if version >= 5:
            buf.append(unit.type)  # unit_type
            buf.append(bits // 8)  # address_size
        buf.extend((0).to_bytes(4, byteorder))  # debug_abbrev_offset
        if version < 5:
            buf.append(bits // 8)  # address_size

        if version >= 5 and unit.type in (DW_UT.skeleton, DW_UT.split_compile):
            buf.extend(unit.dwo_id.to_bytes(8, byteorder))  # dwo_id
        else:
            assert unit.dwo_id is None
        if unit.type in (DW_UT.type, DW_UT.split_type):
            buf.extend(unit.type_signature.to_bytes(8, byteorder))  # type_signature
            relocations.append((len(buf), unit.type_offset))
            buf.extend(b"\0\0\0\0")  # type_offset
        else:
            assert unit.type_signature is None
            assert unit.type_offset is None

        aux(buf, unit.die, 0)

        unit_length = len(buf) - orig_len - 4
        buf[orig_len : orig_len + 4] = unit_length.to_bytes(4, byteorder)

        for offset, label in relocations:
            die_offset = labels[label] - orig_len
            buf[offset : offset + 4] = die_offset.to_bytes(4, byteorder)
    return debug_info, debug_types


def _compile_debug_line(units, little_endian, bits, version):
    byteorder = "little" if little_endian else "big"

    if not units:
        units = [DwarfUnit(DW_UT.compile, DwarfDie(DW_TAG.compile_unit, []))]

    buf = bytearray()
    for unit in units:
        unit.die.attribs.append(
            DwarfAttrib(DW_AT.stmt_list, DW_FORM.sec_offset, len(buf))
        )
        if unit.type in (DW_UT.compile, DW_UT.partial, DW_UT.skeleton):
            unit.die.attribs.append(DwarfAttrib(DW_AT.name, DW_FORM.string, "main.c"))
            unit.die.attribs.append(
                DwarfAttrib(DW_AT.comp_dir, DW_FORM.string, "/usr/src")
            )

        unit_length_start = len(buf)
        buf.extend(b"\0\0\0\0")  # unit_length
        unit_length_end = len(buf)
        buf.extend(version.to_bytes(2, byteorder))  # version
        if version >= 5:
            buf.append(bits // 8)  # address_size
            buf.append(0)  # segment_selector_size
        header_length_start = len(buf)
        buf.extend(b"\0\0\0\0")  # header_length
        header_length_end = len(buf)
        buf.append(1)  # minimum_instruction_length
        buf.append(1)  # maximum_operations_per_instruction
        buf.append(1)  # default_is_stmt
        buf.append(1)  # line_base
        buf.append(1)  # line_range
        buf.append(1)  # opcode_base
        # Don't need standard_opcode_lengths
        if version >= 5:
            buf.append(1)  # directory_entry_format_count
            # directory_entry_format
            _append_uleb128(buf, DW_LNCT.path)
            _append_uleb128(buf, DW_FORM.string)

        directories = OrderedDict([("/usr/src", 0)])

        def collect_directories(die):
            if isinstance(die, DwarfLabel):
                return
            for attrib in die.attribs:
                if attrib.name != DW_AT.decl_file:
                    continue
                dirname = os.path.dirname(attrib.value)
                if dirname:
                    directories.setdefault(dirname, len(directories))
            for child in die.children:
                collect_directories(child)

        collect_directories(unit.die)

        if version >= 5:
            _append_uleb128(buf, len(directories))  # directories_count

        # directories (or include_directories in version <= 4)
        for directory, index in directories.items():
            if index > 0 or version >= 5:
                buf.extend(directory.encode("ascii"))
                buf.append(0)
        if version < 5:
            buf.append(0)

        if version >= 5:
            buf.append(2)  # file_name_entry_format_count
            # file_name_entry_format
            _append_uleb128(buf, DW_LNCT.path)
            _append_uleb128(buf, DW_FORM.string)
            _append_uleb128(buf, DW_LNCT.directory_index)
            _append_uleb128(buf, DW_FORM.udata)

        file_names = [("main.c", 0)]

        def collect_file_names(die):
            if isinstance(die, DwarfLabel):
                return
            for attrib in die.attribs:
                if attrib.name != DW_AT.decl_file:
                    continue
                dirname, basename = os.path.split(attrib.value)
                directory_index = directories[dirname] if dirname else 0
                file_names.append((basename, directory_index))
            for child in die.children:
                collect_file_names(child)

        collect_file_names(unit.die)

        if version >= 5:
            _append_uleb128(buf, len(file_names))  # file_names_count

        # file_names
        for path, directory_index in file_names[0 if version >= 5 else 1 :]:
            # path
            buf.extend(path.encode("ascii"))
            buf.append(0)
            _append_uleb128(buf, directory_index)  # directory_index
            if version < 5:
                _append_uleb128(buf, 0)  # mtime
                _append_uleb128(buf, 0)  # size

        if version < 5:
            buf.append(0)

        buf[unit_length_start:unit_length_end] = (len(buf) - unit_length_end).to_bytes(
            unit_length_end - unit_length_start, byteorder
        )
        buf[header_length_start:header_length_end] = (
            len(buf) - header_length_end
        ).to_bytes(header_length_end - header_length_start, byteorder)
    return buf


_UNIT_TAGS = frozenset({DW_TAG.type_unit, DW_TAG.compile_unit})


def dwarf_sections(
    units_or_dies,
    little_endian=True,
    bits=64,
    *,
    version=4,
    lang=None,
    use_dw_form_indirect=False,
    compress=None,
    split=None,
):
    assert compress in (None, "zlib-gnu", "zlib-gabi")
    assert split in (None, "dwo")

    if isinstance(units_or_dies, (DwarfDie, DwarfUnit)):
        units_or_dies = (units_or_dies,)
    if not units_or_dies or isinstance(units_or_dies[0], DwarfUnit):
        units = units_or_dies
    else:
        assert all(isinstance(die, (DwarfDie, DwarfLabel)) for die in units_or_dies)
        assert all(
            not isinstance(die, DwarfDie) or die.tag not in _UNIT_TAGS
            for die in units_or_dies
        )
        units = (
            DwarfUnit(DW_UT.compile, DwarfDie(DW_TAG.compile_unit, (), units_or_dies)),
        )
    assert all(isinstance(unit, DwarfUnit) for unit in units)
    assert all(unit.die.tag in _UNIT_TAGS for unit in units)

    unit_attribs = []
    if lang is not None:
        unit_attribs.append(DwarfAttrib(DW_AT.language, DW_FORM.data1, lang))

    units = [
        unit._replace(
            die=unit.die._replace(attribs=list(unit.die.attribs) + unit_attribs)
        )
        for unit in units
    ]

    # TODO: line number information for a split file is in the skeleton file.
    # We don't have any test cases yet that use line number information from a
    # split file, but when we do, we'll have to add a way to include the split
    # file's line number information in the skeleton file.
    if not split:
        debug_line = _compile_debug_line(units, little_endian, bits, version)

    debug_info, debug_types = _compile_debug_info(
        units, little_endian, bits, version, use_dw_form_indirect
    )

    def debug_section(name, data):
        assert name.startswith(".debug")
        if compress == "zlib-gnu":
            name = ".z" + name[1:]
            compressed_data = bytearray(b"ZLIB")
            compressed_data.extend(len(data).to_bytes(8, "big"))
            compressed_data.extend(zlib.compress(data))
            data = compressed_data
        if split:
            name += ".dwo"
        return ElfSection(
            name=name,
            sh_type=SHT.PROGBITS,
            data=data,
            compressed=(compress == "zlib-gabi"),
        )
        return name

    sections = [
        debug_section(
            ".debug_abbrev", _compile_debug_abbrev(units, use_dw_form_indirect)
        ),
        debug_section(".debug_info", debug_info),
        debug_section(".debug_str", b"\0"),
    ]
    if not split:
        sections.append(debug_section(".debug_line", debug_line))
    if debug_types:
        sections.append(debug_section(".debug_types", debug_types))
    return sections


def compile_dwarf(
    dies,
    little_endian=True,
    bits=64,
    *,
    version=4,
    lang=None,
    use_dw_form_indirect=False,
    compress=None,
    split=None,
):
    return create_elf_file(
        ET.EXEC,
        dwarf_sections(
            dies,
            little_endian=little_endian,
            bits=bits,
            version=version,
            lang=lang,
            use_dw_form_indirect=use_dw_form_indirect,
            compress=compress,
            split=split,
        ),
        little_endian=little_endian,
        bits=bits,
    )
