# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os.path
from typing import Any, Dict, NamedTuple, Optional, Sequence, Union
import zlib

from _drgn_util.elf import ET, SHF, SHT
from tests.assembler import _append_sleb128, _append_uleb128
from tests.dwarf import DW_AT, DW_FORM, DW_LNCT, DW_LNE, DW_LNS, DW_TAG, DW_UT
from tests.elfwriter import ElfSection, create_elf_file


class DwarfAttrib(NamedTuple):
    name: DW_AT
    form: DW_FORM
    value: Any


class DwarfLabel(NamedTuple):
    name: str


class DwarfDie(NamedTuple):
    tag: DW_TAG
    attribs: Sequence[DwarfAttrib] = ()
    children: Sequence[Union["DwarfDie", DwarfLabel]] = ()


class DwarfLnp(NamedTuple):
    instructions: Sequence[Sequence[Any]]
    comp_dir: str
    file_names: Sequence[str]
    default_is_stmt: bool = True


class DwarfUnit(NamedTuple):
    type: DW_UT
    die: DwarfDie
    die_label: Optional[str] = None
    dwo_id: Optional[int] = None
    type_signature: Optional[int] = None
    type_offset: Optional[str] = None
    lnp: Optional[DwarfLnp] = None


def create_dwarf_lnp(rows, comp_dir: str, file_name: str) -> DwarfLnp:
    instructions = []
    file_names = {file_name: 1}
    current_pc = 0
    current_file = 1
    current_line = 1
    current_column = 0
    for pc, file_name, line, column in rows:
        if pc > current_pc:
            instructions.append((DW_LNS.advance_pc, pc - current_pc))
        else:
            assert pc == 0 and current_pc == 0

        if file_name is None:
            assert line is None
            assert column is None
            instructions.append((DW_LNE.end_sequence,))
        else:
            file = file_names.setdefault(file_name, len(file_names) + 1)
            if file != current_file:
                instructions.append((DW_LNS.set_file, file))
            if line != current_line:
                instructions.append((DW_LNS.advance_line, line - current_line))
            if column != current_column:
                instructions.append((DW_LNS.set_column, column))
            instructions.append((DW_LNS.copy,))
        current_pc = pc
        current_file = file
        current_line = line
        current_column = column
    assert instructions[-1] == (DW_LNE.end_sequence,)

    return DwarfLnp(
        instructions=instructions, comp_dir=comp_dir, file_names=list(file_names)
    )


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


def _compile_debug_info(
    units, little_endian, bits, version, file_names, use_dw_form_indirect
):
    offset_size = 4  # We only emit the 32-bit format for now.
    byteorder = "little" if little_endian else "big"
    labels = {}
    references = []
    unit_references = []
    code = 1

    def aux(buf, die, depth):
        if isinstance(die, DwarfLabel):
            if die.name in labels:
                raise ValueError(f"duplicate label {die.name!r}")
            labels[die.name] = len(buf)
            return

        nonlocal code
        _append_uleb128(buf, code)
        code += 1
        for attrib in die.attribs:
            if use_dw_form_indirect:
                _append_uleb128(buf, attrib.form)
            if attrib.name == DW_AT.decl_file or attrib.name == DW_AT.call_file:
                value = file_names[attrib.value]
            else:
                value = attrib.value
            if attrib.form == DW_FORM.addr:
                buf.extend(value.to_bytes(bits // 8, byteorder))
            elif attrib.form == DW_FORM.data1:
                buf.append(value)
            elif attrib.form == DW_FORM.data2:
                buf.extend(value.to_bytes(2, byteorder))
            elif attrib.form in (DW_FORM.data4, DW_FORM.ref_sup4):
                buf.extend(value.to_bytes(4, byteorder))
            elif attrib.form in (DW_FORM.data8, DW_FORM.ref_sup8):
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
            elif attrib.form in (DW_FORM.strp, DW_FORM.GNU_ref_alt):
                buf.extend(value.to_bytes(offset_size, byteorder))
            elif attrib.form == DW_FORM.string:
                buf.extend(value.encode())
                buf.append(0)
            elif attrib.form == DW_FORM.ref1:
                if isinstance(value, str):
                    unit_references.append((len(buf), 1, value))
                    buf.append(0)
                else:
                    buf.extend(value.to_bytes(1, byteorder))
            elif attrib.form == DW_FORM.ref2:
                if isinstance(value, str):
                    unit_references.append((len(buf), 2, value))
                    buf.extend(bytes(2))
                else:
                    buf.extend(value.to_bytes(2, byteorder))
            elif attrib.form == DW_FORM.ref4:
                if isinstance(value, str):
                    unit_references.append((len(buf), 4, value))
                    buf.extend(bytes(4))
                else:
                    buf.extend(value.to_bytes(4, byteorder))
            elif attrib.form == DW_FORM.ref8:
                if isinstance(value, str):
                    unit_references.append((len(buf), 8, value))
                    buf.extend(bytes(8))
                else:
                    buf.extend(value.to_bytes(8, byteorder))
            elif attrib.form == DW_FORM.ref_udata:
                if isinstance(value, str):
                    assert (
                        value in labels
                    ), "DW_FORM_ref_udata can only be used for backreferences"
                    _append_uleb128(buf, labels[value] - unit_offset)
                else:
                    _append_uleb128(buf, value)
            elif attrib.form == DW_FORM.ref_addr:
                if isinstance(value, str):
                    references.append((len(buf), offset_size, value))
                    buf.extend(bytes(offset_size))
                else:
                    buf.extend(value.to_bytes(offset_size, byteorder))
            elif attrib.form == DW_FORM.ref_sig8:
                buf.extend(value.to_bytes(8, byteorder))
            elif attrib.form == DW_FORM.sec_offset:
                buf.extend(bytes(offset_size))
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
        unit_references.clear()
        if version == 4 and unit.type in (DW_UT.type, DW_UT.split_type):
            buf = debug_types
        else:
            buf = debug_info
        unit_offset = len(buf)
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
            unit_references.append((len(buf), offset_size, unit.type_offset))
            buf.extend(bytes(offset_size))  # type_offset
        else:
            assert unit.type_signature is None
            assert unit.type_offset is None

        if unit.die_label is not None:
            aux(buf, DwarfLabel(unit.die_label), 0)
        aux(buf, unit.die, 0)

        unit_length = len(buf) - unit_offset - 4
        buf[unit_offset : unit_offset + 4] = unit_length.to_bytes(4, byteorder)

        for offset, size, label in unit_references:
            die_offset = labels[label] - unit_offset
            buf[offset : offset + size] = die_offset.to_bytes(size, byteorder)

    for offset, size, label in references:
        buf[offset : offset + size] = labels[label].to_bytes(size, byteorder)

    return debug_info, debug_types, labels


def _compile_debug_line(units, little_endian, bits, version):
    byteorder = "little" if little_endian else "big"

    if not units:
        units = [DwarfUnit(DW_UT.compile, DwarfDie(DW_TAG.compile_unit, []))]

    buf = bytearray()
    for unit in units:
        lnp = unit.lnp
        if lnp is None:
            lnp = DwarfLnp(
                instructions=(),
                comp_dir="/usr/src",
                file_names=("main.c",),
            )

        unit.die.attribs.append(
            DwarfAttrib(DW_AT.stmt_list, DW_FORM.sec_offset, len(buf))
        )
        if unit.type in (DW_UT.compile, DW_UT.partial, DW_UT.skeleton):
            unit.die.attribs.append(
                DwarfAttrib(DW_AT.name, DW_FORM.string, lnp.file_names[0])
            )
            unit.die.attribs.append(
                DwarfAttrib(DW_AT.comp_dir, DW_FORM.string, lnp.comp_dir)
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
        buf.append(lnp.default_is_stmt)  # default_is_stmt
        buf.append(1)  # line_base
        buf.append(1)  # line_range
        buf.append(13)  # opcode_base
        buf.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])  # standard_opcode_lengths
        if version >= 5:
            buf.append(1)  # directory_entry_format_count
            # directory_entry_format
            _append_uleb128(buf, DW_LNCT.path)
            _append_uleb128(buf, DW_FORM.string)

        directories = {lnp.comp_dir: 0}
        file_names = {}
        file_name_entries = []

        for file_name in lnp.file_names:
            assert file_name not in file_names

            file_names[file_name] = len(file_names) + 1

            dirname, basename = os.path.split(file_name)
            if dirname:
                directory_index = directories.setdefault(dirname, len(directories))
            else:
                directory_index = 0
            file_name_entries.append((basename, directory_index))

        def collect_file_names(die):
            if isinstance(die, DwarfLabel):
                return
            for attrib in die.attribs:
                if attrib.name not in (DW_AT.decl_file, DW_AT.call_file):
                    continue

                if attrib.value in file_names:
                    continue

                file_names[attrib.value] = len(file_names) + 1

                dirname, basename = os.path.split(attrib.value)
                if dirname:
                    directory_index = directories.setdefault(dirname, len(directories))
                else:
                    directory_index = 0
                file_name_entries.append((basename, directory_index))
            for child in die.children:
                collect_file_names(child)

        collect_file_names(unit.die)

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

        if version >= 5:
            file_name_entries.insert(0, file_name_entries[0])
            _append_uleb128(buf, len(file_names))  # file_names_count

        # file_names
        for path, directory_index in file_name_entries:
            # path
            buf.extend(path.encode("ascii"))
            buf.append(0)
            _append_uleb128(buf, directory_index)  # directory_index
            if version < 5:
                _append_uleb128(buf, 0)  # mtime
                _append_uleb128(buf, 0)  # size

        if version < 5:
            buf.append(0)

        buf[header_length_start:header_length_end] = (
            len(buf) - header_length_end
        ).to_bytes(header_length_end - header_length_start, byteorder)

        for instruction in lnp.instructions:
            opcode = instruction[0]
            buf.append(opcode)
            if opcode in {DW_LNS.copy, DW_LNE.end_sequence}:
                assert len(instruction) == 1
            elif opcode == DW_LNS.advance_pc:
                assert len(instruction) == 2
                _append_uleb128(buf, instruction[1])
            elif opcode == DW_LNS.advance_line:
                assert len(instruction) == 2
                _append_sleb128(buf, instruction[1])
            elif opcode == DW_LNS.set_file:
                assert len(instruction) == 2
                _append_uleb128(buf, instruction[1])
            elif opcode == DW_LNS.set_column:
                assert len(instruction) == 2
                _append_uleb128(buf, instruction[1])
            else:
                assert False, opcode

        buf[unit_length_start:unit_length_end] = (len(buf) - unit_length_end).to_bytes(
            unit_length_end - unit_length_start, byteorder
        )
    return buf, file_names


_UNIT_TAGS = frozenset({DW_TAG.type_unit, DW_TAG.compile_unit, DW_TAG.partial_unit})


class DwarfResult(NamedTuple):
    data: bytes
    labels: Dict[str, int]


def compile_dwarf(
    units_or_dies,
    *,
    version=4,
    lang=None,
    use_dw_form_indirect=False,
    compress=None,
    split=None,
    sections=(),
    little_endian=True,
    bits=64,
    allow_any_unit_die=False,
    **kwargs,
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
    assert allow_any_unit_die or all(unit.die.tag in _UNIT_TAGS for unit in units)

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
    if split:
        file_names = {}
    else:
        debug_line, file_names = _compile_debug_line(
            units, little_endian, bits, version
        )

    debug_info, debug_types, labels = _compile_debug_info(
        units, little_endian, bits, version, file_names, use_dw_form_indirect
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
            sh_flags=SHF.COMPRESSED if compress == "zlib-gabi" else SHF(0),
        )
        return name

    dwarf_sections = [
        debug_section(
            ".debug_abbrev", _compile_debug_abbrev(units, use_dw_form_indirect)
        ),
        debug_section(".debug_info", debug_info),
        debug_section(".debug_str", b"\0"),
    ]
    if not split:
        dwarf_sections.append(debug_section(".debug_line", debug_line))
    if debug_types:
        dwarf_sections.append(debug_section(".debug_types", debug_types))

    return DwarfResult(
        data=create_elf_file(
            ET.EXEC,
            sections=[*sections, *dwarf_sections],
            little_endian=little_endian,
            bits=bits,
            **kwargs,
        ),
        labels=labels,
    )


def create_dwarf_file(*args, **kwargs):
    return compile_dwarf(*args, **kwargs).data
