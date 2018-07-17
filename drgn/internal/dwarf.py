# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""DWARF parsing library"""

import enum
import functools
import os
import os.path
import struct
import sys
from typing import (
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Text,
    Tuple,
    Union,
)

from drgn.internal.elf import ElfFile
from drgn.internal.thunk import thunk


# Automatically generated from dwarf.h
class DW_AT(enum.IntEnum):
    sibling = 0x1
    location = 0x2
    name = 0x3  # type: ignore
    ordering = 0x9
    byte_size = 0xb
    bit_offset = 0xc
    bit_size = 0xd
    stmt_list = 0x10
    low_pc = 0x11
    high_pc = 0x12
    language = 0x13
    discr = 0x15
    discr_value = 0x16
    visibility = 0x17
    import_ = 0x18
    string_length = 0x19
    common_reference = 0x1a
    comp_dir = 0x1b
    const_value = 0x1c
    containing_type = 0x1d
    default_value = 0x1e
    inline = 0x20
    is_optional = 0x21
    lower_bound = 0x22
    producer = 0x25
    prototyped = 0x27
    return_addr = 0x2a
    start_scope = 0x2c
    bit_stride = 0x2e
    upper_bound = 0x2f
    abstract_origin = 0x31
    accessibility = 0x32
    address_class = 0x33
    artificial = 0x34
    base_types = 0x35
    calling_convention = 0x36
    count = 0x37
    data_member_location = 0x38
    decl_column = 0x39
    decl_file = 0x3a
    decl_line = 0x3b
    declaration = 0x3c
    discr_list = 0x3d
    encoding = 0x3e
    external = 0x3f
    frame_base = 0x40
    friend = 0x41
    identifier_case = 0x42
    macro_info = 0x43
    namelist_item = 0x44
    priority = 0x45
    segment = 0x46
    specification = 0x47
    static_link = 0x48
    type = 0x49
    use_location = 0x4a
    variable_parameter = 0x4b
    virtuality = 0x4c
    vtable_elem_location = 0x4d
    allocated = 0x4e
    associated = 0x4f
    data_location = 0x50
    byte_stride = 0x51
    entry_pc = 0x52
    use_UTF8 = 0x53
    extension = 0x54
    ranges = 0x55
    trampoline = 0x56
    call_column = 0x57
    call_file = 0x58
    call_line = 0x59
    description = 0x5a
    binary_scale = 0x5b
    decimal_scale = 0x5c
    small = 0x5d
    decimal_sign = 0x5e
    digit_count = 0x5f
    picture_string = 0x60
    mutable = 0x61
    threads_scaled = 0x62
    explicit = 0x63
    object_pointer = 0x64
    endianity = 0x65
    elemental = 0x66
    pure = 0x67
    recursive = 0x68
    signature = 0x69
    main_subprogram = 0x6a
    data_bit_offset = 0x6b
    const_expr = 0x6c
    enum_class = 0x6d
    linkage_name = 0x6e
    string_length_bit_size = 0x6f
    string_length_byte_size = 0x70
    rank = 0x71
    str_offsets_base = 0x72
    addr_base = 0x73
    rnglists_base = 0x74
    dwo_name = 0x76
    reference = 0x77
    rvalue_reference = 0x78
    macros = 0x79
    call_all_calls = 0x7a
    call_all_source_calls = 0x7b
    call_all_tail_calls = 0x7c
    call_return_pc = 0x7d
    call_value = 0x7e
    call_origin = 0x7f
    call_parameter = 0x80
    call_pc = 0x81
    call_tail_call = 0x82
    call_target = 0x83
    call_target_clobbered = 0x84
    call_data_location = 0x85
    call_data_value = 0x86
    noreturn = 0x87
    alignment = 0x88
    export_symbols = 0x89
    deleted = 0x8a
    defaulted = 0x8b
    loclists_base = 0x8c
    lo_user = 0x2000
    MIPS_fde = 0x2001
    MIPS_loop_begin = 0x2002
    MIPS_tail_loop_begin = 0x2003
    MIPS_epilog_begin = 0x2004
    MIPS_loop_unroll_factor = 0x2005
    MIPS_software_pipeline_depth = 0x2006
    MIPS_linkage_name = 0x2007
    MIPS_stride = 0x2008
    MIPS_abstract_name = 0x2009
    MIPS_clone_origin = 0x200a
    MIPS_has_inlines = 0x200b
    MIPS_stride_byte = 0x200c
    MIPS_stride_elem = 0x200d
    MIPS_ptr_dopetype = 0x200e
    MIPS_allocatable_dopetype = 0x200f
    MIPS_assumed_shape_dopetype = 0x2010
    MIPS_assumed_size = 0x2011
    sf_names = 0x2101
    src_info = 0x2102
    mac_info = 0x2103
    src_coords = 0x2104
    body_begin = 0x2105
    body_end = 0x2106
    GNU_vector = 0x2107
    GNU_guarded_by = 0x2108
    GNU_pt_guarded_by = 0x2109
    GNU_guarded = 0x210a
    GNU_pt_guarded = 0x210b
    GNU_locks_excluded = 0x210c
    GNU_exclusive_locks_required = 0x210d
    GNU_shared_locks_required = 0x210e
    GNU_odr_signature = 0x210f
    GNU_template_name = 0x2110
    GNU_call_site_value = 0x2111
    GNU_call_site_data_value = 0x2112
    GNU_call_site_target = 0x2113
    GNU_call_site_target_clobbered = 0x2114
    GNU_tail_call = 0x2115
    GNU_all_tail_call_sites = 0x2116
    GNU_all_call_sites = 0x2117
    GNU_all_source_call_sites = 0x2118
    GNU_locviews = 0x2137
    GNU_entry_view = 0x2138
    GNU_macros = 0x2119
    GNU_deleted = 0x211a
    GNU_dwo_name = 0x2130
    GNU_dwo_id = 0x2131
    GNU_ranges_base = 0x2132
    GNU_addr_base = 0x2133
    GNU_pubnames = 0x2134
    GNU_pubtypes = 0x2135
    hi_user = 0x3fff

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_AT_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_ATE(enum.IntEnum):
    void = 0x0
    address = 0x1
    boolean = 0x2
    complex_float = 0x3
    float = 0x4
    signed = 0x5
    signed_char = 0x6
    unsigned = 0x7
    unsigned_char = 0x8
    imaginary_float = 0x9
    packed_decimal = 0xa
    numeric_string = 0xb
    edited = 0xc
    signed_fixed = 0xd
    unsigned_fixed = 0xe
    decimal_float = 0xf
    UTF = 0x10
    UCS = 0x11
    ASCII = 0x12
    lo_user = 0x80
    hi_user = 0xff

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_ATE_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_CHILDREN(enum.IntEnum):
    no = 0x0
    yes = 0x1

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_CHILDREN_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_FORM(enum.IntEnum):
    addr = 0x1
    block2 = 0x3
    block4 = 0x4
    data2 = 0x5
    data4 = 0x6
    data8 = 0x7
    string = 0x8
    block = 0x9
    block1 = 0xa
    data1 = 0xb
    flag = 0xc
    sdata = 0xd
    strp = 0xe
    udata = 0xf
    ref_addr = 0x10
    ref1 = 0x11
    ref2 = 0x12
    ref4 = 0x13
    ref8 = 0x14
    ref_udata = 0x15
    indirect = 0x16
    sec_offset = 0x17
    exprloc = 0x18
    flag_present = 0x19
    strx = 0x1a
    addrx = 0x1b
    ref_sup4 = 0x1c
    strp_sup = 0x1d
    data16 = 0x1e
    line_strp = 0x1f
    ref_sig8 = 0x20
    implicit_const = 0x21
    loclistx = 0x22
    rnglistx = 0x23
    ref_sup8 = 0x24
    strx1 = 0x25
    strx2 = 0x26
    strx3 = 0x27
    strx4 = 0x28
    addrx1 = 0x29
    addrx2 = 0x2a
    addrx3 = 0x2b
    addrx4 = 0x2c
    GNU_addr_index = 0x1f01
    GNU_str_index = 0x1f02
    GNU_ref_alt = 0x1f20
    GNU_strp_alt = 0x1f21

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_FORM_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_LNE(enum.IntEnum):
    end_sequence = 0x1
    set_address = 0x2
    define_file = 0x3
    set_discriminator = 0x4
    lo_user = 0x80
    hi_user = 0xff

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_LNE_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_LNS(enum.IntEnum):
    copy = 0x1
    advance_pc = 0x2
    advance_line = 0x3
    set_file = 0x4
    set_column = 0x5
    negate_stmt = 0x6
    set_basic_block = 0x7
    const_add_pc = 0x8
    fixed_advance_pc = 0x9
    set_prologue_end = 0xa
    set_epilogue_begin = 0xb
    set_isa = 0xc

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_LNS_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_OP(enum.IntEnum):
    addr = 0x3
    deref = 0x6
    const1u = 0x8
    const1s = 0x9
    const2u = 0xa
    const2s = 0xb
    const4u = 0xc
    const4s = 0xd
    const8u = 0xe
    const8s = 0xf
    constu = 0x10
    consts = 0x11
    dup = 0x12
    drop = 0x13
    over = 0x14
    pick = 0x15
    swap = 0x16
    rot = 0x17
    xderef = 0x18
    abs = 0x19
    and_ = 0x1a
    div = 0x1b
    minus = 0x1c
    mod = 0x1d
    mul = 0x1e
    neg = 0x1f
    not_ = 0x20
    or_ = 0x21
    plus = 0x22
    plus_uconst = 0x23
    shl = 0x24
    shr = 0x25
    shra = 0x26
    xor = 0x27
    bra = 0x28
    eq = 0x29
    ge = 0x2a
    gt = 0x2b
    le = 0x2c
    lt = 0x2d
    ne = 0x2e
    skip = 0x2f
    lit0 = 0x30
    lit1 = 0x31
    lit2 = 0x32
    lit3 = 0x33
    lit4 = 0x34
    lit5 = 0x35
    lit6 = 0x36
    lit7 = 0x37
    lit8 = 0x38
    lit9 = 0x39
    lit10 = 0x3a
    lit11 = 0x3b
    lit12 = 0x3c
    lit13 = 0x3d
    lit14 = 0x3e
    lit15 = 0x3f
    lit16 = 0x40
    lit17 = 0x41
    lit18 = 0x42
    lit19 = 0x43
    lit20 = 0x44
    lit21 = 0x45
    lit22 = 0x46
    lit23 = 0x47
    lit24 = 0x48
    lit25 = 0x49
    lit26 = 0x4a
    lit27 = 0x4b
    lit28 = 0x4c
    lit29 = 0x4d
    lit30 = 0x4e
    lit31 = 0x4f
    reg0 = 0x50
    reg1 = 0x51
    reg2 = 0x52
    reg3 = 0x53
    reg4 = 0x54
    reg5 = 0x55
    reg6 = 0x56
    reg7 = 0x57
    reg8 = 0x58
    reg9 = 0x59
    reg10 = 0x5a
    reg11 = 0x5b
    reg12 = 0x5c
    reg13 = 0x5d
    reg14 = 0x5e
    reg15 = 0x5f
    reg16 = 0x60
    reg17 = 0x61
    reg18 = 0x62
    reg19 = 0x63
    reg20 = 0x64
    reg21 = 0x65
    reg22 = 0x66
    reg23 = 0x67
    reg24 = 0x68
    reg25 = 0x69
    reg26 = 0x6a
    reg27 = 0x6b
    reg28 = 0x6c
    reg29 = 0x6d
    reg30 = 0x6e
    reg31 = 0x6f
    breg0 = 0x70
    breg1 = 0x71
    breg2 = 0x72
    breg3 = 0x73
    breg4 = 0x74
    breg5 = 0x75
    breg6 = 0x76
    breg7 = 0x77
    breg8 = 0x78
    breg9 = 0x79
    breg10 = 0x7a
    breg11 = 0x7b
    breg12 = 0x7c
    breg13 = 0x7d
    breg14 = 0x7e
    breg15 = 0x7f
    breg16 = 0x80
    breg17 = 0x81
    breg18 = 0x82
    breg19 = 0x83
    breg20 = 0x84
    breg21 = 0x85
    breg22 = 0x86
    breg23 = 0x87
    breg24 = 0x88
    breg25 = 0x89
    breg26 = 0x8a
    breg27 = 0x8b
    breg28 = 0x8c
    breg29 = 0x8d
    breg30 = 0x8e
    breg31 = 0x8f
    regx = 0x90
    fbreg = 0x91
    bregx = 0x92
    piece = 0x93
    deref_size = 0x94
    xderef_size = 0x95
    nop = 0x96
    push_object_address = 0x97
    call2 = 0x98
    call4 = 0x99
    call_ref = 0x9a
    form_tls_address = 0x9b
    call_frame_cfa = 0x9c
    bit_piece = 0x9d
    implicit_value = 0x9e
    stack_value = 0x9f
    implicit_pointer = 0xa0
    addrx = 0xa1
    constx = 0xa2
    entry_value = 0xa3
    const_type = 0xa4
    regval_type = 0xa5
    deref_type = 0xa6
    xderef_type = 0xa7
    convert = 0xa8
    reinterpret = 0xa9
    GNU_push_tls_address = 0xe0
    GNU_uninit = 0xf0
    GNU_encoded_addr = 0xf1
    GNU_implicit_pointer = 0xf2
    GNU_entry_value = 0xf3
    GNU_const_type = 0xf4
    GNU_regval_type = 0xf5
    GNU_deref_type = 0xf6
    GNU_convert = 0xf7
    GNU_reinterpret = 0xf9
    GNU_parameter_ref = 0xfa
    GNU_addr_index = 0xfb
    GNU_const_index = 0xfc
    GNU_variable_value = 0xfd
    lo_user = 0xe0
    hi_user = 0xff

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_OP_{cls(value).name}'
        except ValueError:
            return hex(value)


class DW_TAG(enum.IntEnum):
    array_type = 0x1
    class_type = 0x2
    entry_point = 0x3
    enumeration_type = 0x4
    formal_parameter = 0x5
    imported_declaration = 0x8
    label = 0xa
    lexical_block = 0xb
    member = 0xd
    pointer_type = 0xf
    reference_type = 0x10
    compile_unit = 0x11
    string_type = 0x12
    structure_type = 0x13
    subroutine_type = 0x15
    typedef = 0x16
    union_type = 0x17
    unspecified_parameters = 0x18
    variant = 0x19
    common_block = 0x1a
    common_inclusion = 0x1b
    inheritance = 0x1c
    inlined_subroutine = 0x1d
    module = 0x1e
    ptr_to_member_type = 0x1f
    set_type = 0x20
    subrange_type = 0x21
    with_stmt = 0x22
    access_declaration = 0x23
    base_type = 0x24
    catch_block = 0x25
    const_type = 0x26
    constant = 0x27
    enumerator = 0x28
    file_type = 0x29
    friend = 0x2a
    namelist = 0x2b
    namelist_item = 0x2c
    packed_type = 0x2d
    subprogram = 0x2e
    template_type_parameter = 0x2f
    template_value_parameter = 0x30
    thrown_type = 0x31
    try_block = 0x32
    variant_part = 0x33
    variable = 0x34
    volatile_type = 0x35
    dwarf_procedure = 0x36
    restrict_type = 0x37
    interface_type = 0x38
    namespace = 0x39
    imported_module = 0x3a
    unspecified_type = 0x3b
    partial_unit = 0x3c
    imported_unit = 0x3d
    condition = 0x3f
    shared_type = 0x40
    type_unit = 0x41
    rvalue_reference_type = 0x42
    template_alias = 0x43
    coarray_type = 0x44
    generic_subrange = 0x45
    dynamic_type = 0x46
    atomic_type = 0x47
    call_site = 0x48
    call_site_parameter = 0x49
    skeleton_unit = 0x4a
    immutable_type = 0x4b
    lo_user = 0x4080
    MIPS_loop = 0x4081
    format_label = 0x4101
    function_template = 0x4102
    class_template = 0x4103
    GNU_BINCL = 0x4104
    GNU_EINCL = 0x4105
    GNU_template_template_param = 0x4106
    GNU_template_parameter_pack = 0x4107
    GNU_formal_parameter_pack = 0x4108
    GNU_call_site = 0x4109
    GNU_call_site_parameter = 0x410a
    hi_user = 0xffff

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f'DW_TAG_{cls(value).name}'
        except ValueError:
            return hex(value)


TYPE_TAGS = {
    DW_TAG.array_type,
    DW_TAG.atomic_type,
    DW_TAG.base_type,
    DW_TAG.class_type,
    DW_TAG.const_type,
    DW_TAG.enumeration_type,
    DW_TAG.file_type,
    DW_TAG.interface_type,
    DW_TAG.packed_type,
    DW_TAG.pointer_type,
    DW_TAG.ptr_to_member_type,
    DW_TAG.reference_type,
    DW_TAG.restrict_type,
    DW_TAG.rvalue_reference_type,
    DW_TAG.set_type,
    DW_TAG.shared_type,
    DW_TAG.string_type,
    DW_TAG.structure_type,
    DW_TAG.subrange_type,
    DW_TAG.subroutine_type,
    DW_TAG.template_type_parameter,
    DW_TAG.thrown_type,
    DW_TAG.typedef,
    DW_TAG.union_type,
    DW_TAG.unspecified_type,
    DW_TAG.volatile_type,
}

QUALIFIED_TYPE_TAGS = {
    DW_TAG.atomic_type,
    DW_TAG.const_type,
    DW_TAG.packed_type,
    DW_TAG.restrict_type,
    DW_TAG.shared_type,
    DW_TAG.volatile_type,
}


class DwarfFormatError(Exception):
    pass


class DwarfAttribNotFoundError(Exception):
    pass


class _Reader:
    s8 = struct.Struct('b')
    u8 = struct.Struct('B')
    u16 = struct.Struct('H')
    u32 = struct.Struct('I')
    u64 = struct.Struct('Q')

    def __init__(self, view: bytes, offset: int = 0) -> None:
        self.view = view
        self.offset = offset

    def read_bytes(self, size: int) -> bytes:
        if self.offset + size > len(self.view):
            raise EOFError()
        ret = bytes(self.view[self.offset:self.offset + size])
        self.offset += size
        return ret

    def read_c_string(self) -> bytes:
        offset = self.offset
        while True:
            if offset >= len(self.view):
                raise EOFError()
            if self.view[offset] == 0:
                break
            offset += 1
        ret = bytes(self.view[self.offset:offset])
        self.offset = offset + 1
        return ret

    def read_struct(self, s: struct.Struct) -> Tuple:
        if self.offset + s.size > len(self.view):
            raise EOFError()
        ret = s.unpack_from(self.view, self.offset)
        self.offset += s.size
        return ret

    def read_s8(self) -> int:
        return self.read_struct(self.s8)[0]

    def read_u8(self) -> int:
        return self.read_struct(self.u8)[0]

    def read_u16(self) -> int:
        return self.read_struct(self.u16)[0]

    def read_u32(self) -> int:
        return self.read_struct(self.u32)[0]

    def read_u64(self) -> int:
        return self.read_struct(self.u64)[0]

    def read_uleb128(self) -> int:
        ret = 0
        shift = 0
        while True:
            byte = self.read_u8()
            ret |= (byte & 0x7f) << shift
            shift += 7
            if not (byte & 0x80):
                break
        return ret

    def read_sleb128(self) -> int:
        ret = 0
        shift = 0
        while True:
            byte = self.read_u8()
            ret |= (byte & 0x7f) << shift
            shift += 7
            if not (byte & 0x80):
                break
        if byte & 0x40:
            ret -= 1 << shift
        return ret


class DwarfFile:
    _SECTIONS = [
        '.debug_abbrev',
        '.debug_info',
        '.debug_line',
        '.debug_str',
    ]

    def __init__(self, path: str, elf_file: ElfFile) -> None:
        self.path = path
        self.elf_file = elf_file
        self.sections: Dict[str, bytes] = {}
        for section in DwarfFile._SECTIONS:
            try:
                shdr = self.elf_file.sections[section]
            except KeyError:
                continue
            self.elf_file.file.seek(shdr.sh_offset)
            self.sections[section] = self.elf_file.file.read(shdr.sh_size)

    def _get_section_reader(self, name: str) -> _Reader:
        try:
            data = self.sections[name]
        except KeyError:
            raise DwarfFormatError(f'no {name} section')
        return _Reader(data)

    def compilation_unit(self, offset: int) -> 'CompilationUnit':
        debug_info_reader = self._get_section_reader('.debug_info')
        debug_info_reader.offset = offset
        debug_abbrev_reader = self._get_section_reader('.debug_abbrev')
        return _parse_compilation_unit(debug_info_reader, debug_abbrev_reader,
                                       self)


class AttribSpec(NamedTuple):
    name: int
    form: int


class AbbrevDecl(NamedTuple):
    tag: int
    children: bool
    attribs: List[AttribSpec]


class CompilationUnit:
    def __init__(self, dwarf_file: DwarfFile, offset: int, unit_length: int,
                 version: int, debug_abbrev_offset: int, address_size: int,
                 is_64_bit: bool, abbrev_table: Dict[int, AbbrevDecl]) -> None:
        self.dwarf_file = dwarf_file
        # Offset from the beginning of .debug_info (or whatever section it was
        # parsed from).
        self.offset = offset
        self.unit_length = unit_length
        self.version = version
        self.debug_abbrev_offset = debug_abbrev_offset
        self.address_size = address_size
        self.is_64_bit = is_64_bit
        self.abbrev_table = abbrev_table

    def __repr__(self) -> str:
        return f'CompilationUnit({self.offset}, ...)'

    def name(self) -> str:
        return self.die().name()

    def end_offset(self) -> int:
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length

    def die_offset(self) -> int:
        return self.offset + (23 if self.is_64_bit else 11)

    @functools.lru_cache()
    def die(self, offset: Optional[int] = None) -> 'Die':
        reader = self.dwarf_file._get_section_reader('.debug_info')
        if offset is None:
            reader.offset = self.die_offset()
        else:
            reader.offset = self.offset + offset
        die = _parse_die(reader, self, False)
        assert die is not None
        return die

    def _die_siblings(self, offset: int) -> List['Die']:
        reader = self.dwarf_file._get_section_reader('.debug_info')
        reader.offset = offset
        return _parse_die_siblings(reader, self)

    @functools.lru_cache()
    def lnp(self) -> 'LineNumberProgram':
        reader = self.dwarf_file._get_section_reader('.debug_line')
        reader.offset = self.die().find_ptr(DW_AT.stmt_list)
        return _parse_line_number_program(reader, self.dwarf_file)


class LineNumberProgram:
    def __init__(self, dwarf_file: DwarfFile, offset: int, unit_length: int,
                 version: int, header_length: int,
                 minimum_instruction_length: int,
                 maximum_operations_per_instruction: int,
                 default_is_stmt: bool, line_base: int, line_range: int,
                 opcode_base: int, standard_opcode_lengths: Sequence[int],
                 include_directories: List[str],
                 file_names: List[Tuple[str, int, int, int]],
                 is_64_bit: bool) -> None:
        self.dwarf_file = dwarf_file
        self.offset = offset
        self.unit_length = unit_length
        self.version = version
        self.header_length = header_length
        self.minimum_instruction_length = minimum_instruction_length
        self.maximum_operations_per_instruction = maximum_operations_per_instruction
        self.default_is_stmt = default_is_stmt
        self.line_base = line_base
        self.line_range = line_range
        self.opcode_base = opcode_base
        self.standard_opcode_lengths = standard_opcode_lengths
        self.include_directories = include_directories
        self.file_names = file_names
        self.is_64_bit = is_64_bit

    def file_name(self, index: int) -> 'str':
        if index <= 0 or index > len(self.file_names):
            raise IndexError('file name index out of range')
        path, directory_index, _, _ = self.file_names[index - 1]
        if directory_index:
            directory = self.include_directories[directory_index - 1]
            path = os.path.join(directory, path)
        return os.path.normpath(path)


class DieAttrib(NamedTuple):
    name: int
    form: int
    value: Union[int, bytes]

    def __repr__(self) -> str:
        return f'DieAttrib({DW_AT.str(self.name)}, {DW_FORM.str(self.form)}, {self.value!r})'


class Die:
    _no_children: List['Die'] = []

    def __init__(self, cu: CompilationUnit, tag: int, attribs: List[DieAttrib],
                 children: Optional[Callable[[], List['Die']]] = None) -> None:
        self.cu = cu
        self.tag = tag
        self.attribs = attribs
        if children is None:
            self.children = lambda: Die._no_children
        else:
            self.children = children

    def __repr__(self) -> str:
        return f'Die({self.cu!r}, {DW_TAG.str(self.tag)}, {self.attribs!r}, ...)'

    def has_attrib(self, at: DW_AT) -> bool:
        for attrib in self.attribs:
            if attrib.name == at:
                return True
        return False

    def find(self, at: DW_AT) -> DieAttrib:
        for attrib in self.attribs:
            if attrib.name == at:
                return attrib
        raise DwarfAttribNotFoundError(f'no attribute with name {DW_AT.str(at)}')

    def find_constant(self, at: DW_AT) -> int:
        attrib = self.find(at)
        if (attrib.form == DW_FORM.data1 or
                attrib.form == DW_FORM.data2 or
                attrib.form == DW_FORM.data4 or
                attrib.form == DW_FORM.data8):
            assert isinstance(attrib.value, bytes)
            return int.from_bytes(attrib.value, sys.byteorder)
        elif (attrib.form == DW_FORM.udata or
              attrib.form == DW_FORM.sdata):
            assert isinstance(attrib.value, int)
            return attrib.value
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for constant')

    def find_string(self, at: DW_AT) -> str:
        attrib = self.find(at)
        if attrib.form == DW_FORM.strp:
            assert isinstance(attrib.value, int)
            reader = self.cu.dwarf_file._get_section_reader('.debug_str')
            reader.offset = attrib.value
            return reader.read_c_string().decode('utf-8')
        elif attrib.form == DW_FORM.string:
            assert isinstance(attrib.value, bytes)
            return attrib.value.decode('utf-8')
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for string')

    def find_flag(self, at: DW_AT) -> bool:
        try:
            attrib = self.find(at)
        except DwarfAttribNotFoundError:
            return False
        if attrib.form == DW_FORM.flag_present:
            return True
        elif attrib.form == DW_FORM.flag:
            return bool(attrib.value)
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for flag')

    def find_ptr(self, at: DW_AT) -> int:
        attrib = self.find(at)
        if attrib.form == DW_FORM.sec_offset:
            assert isinstance(attrib.value, int)
            return attrib.value
        elif (attrib.form == DW_FORM.data4 or
              attrib.form == DW_FORM.data8):
            assert isinstance(attrib.value, bytes)
            return int.from_bytes(attrib.value, sys.byteorder)
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for ptr')

    def find_die(self, at: DW_AT) -> 'Die':
        attrib = self.find(at)
        if (attrib.form == DW_FORM.ref1 or attrib.form == DW_FORM.ref2 or
                attrib.form == DW_FORM.ref4 or attrib.form == DW_FORM.ref8 or
                attrib.form == DW_FORM.ref_udata):
            assert isinstance(attrib.value, int)
            return self.cu.die(attrib.value)
        elif attrib.form == DW_FORM.ref_addr:
            raise NotImplementedError('DW_FORM_ref_addr is not implemented')
        elif attrib.form == DW_FORM.ref_sig8:
            raise NotImplementedError('DW_FORM_ref_sig8 is not implemented')
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for reference')

    def name(self) -> str:
        return self.find_string(DW_AT.name)

    def size(self) -> int:
        return self.find_constant(DW_AT.byte_size)

    def location(self) -> int:
        attrib = self.find(DW_AT.location)
        assert isinstance(attrib.value, bytes)
        if attrib.value[0] != DW_OP.addr:
            raise NotImplementedError('only DW_OP_addr is implemented')
        return int.from_bytes(attrib.value[1:], sys.byteorder)

    def specification(self) -> 'Die':
        return self.find_die(DW_AT.specification)

    def type(self) -> 'Die':
        return self.find_die(DW_AT.type)

    def decl_file(self) -> str:
        return self.cu.lnp().file_name(self.find_constant(DW_AT.decl_file))

    def decl(self) -> Tuple[str, Optional[int], Optional[int]]:
        file = self.decl_file()
        try:
            line = self.find_constant(DW_AT.decl_line)
        except DwarfAttribNotFoundError:
            line = 0
        try:
            column = self.find_constant(DW_AT.decl_column)
        except DwarfAttribNotFoundError:
            column = 0
        return (file, line if line else None, column if column else None)

    def is_type(self) -> bool:
        return self.tag in TYPE_TAGS

    def is_qualified_type(self) -> bool:
        return self.tag in QUALIFIED_TYPE_TAGS

    def unqualified(self) -> 'Die':
        if not self.is_type():
            raise ValueError('not a type DIE')
        die = self
        while die.is_qualified_type() or die.tag == DW_TAG.typedef:
            die = die.type()
        return die


def _parse_abbrev_decl(reader: _Reader) -> AbbrevDecl:
    tag = reader.read_uleb128()
    children = reader.read_u8() != DW_CHILDREN.no
    attribs = []
    while True:
        name = reader.read_uleb128()
        form = reader.read_uleb128()
        if name == 0 and form == 0:
            break
        attribs.append(AttribSpec(name, form))
    return AbbrevDecl(tag, children, attribs)


def _parse_abbrev_table(reader: _Reader) -> Dict[int, AbbrevDecl]:
    abbrev_table = {}
    while True:
        code = reader.read_uleb128()
        if code == 0:
            break
        decl = _parse_abbrev_decl(reader)
        abbrev_table[code] = decl
    return abbrev_table


def _parse_compilation_unit(debug_info_reader: _Reader,
                            debug_abbrev_reader: _Reader,
                            dwarf_file: DwarfFile) -> CompilationUnit:
    offset = debug_info_reader.offset
    unit_length = debug_info_reader.read_u32()
    if unit_length == 0xffffffff:
        is_64_bit = True
        unit_length = debug_info_reader.read_u64()
    else:
        is_64_bit = False

    version = debug_info_reader.read_u16()
    if not 2 <= version <= 4:
        raise DwarfFormatError(f'unknown CU version {version}')

    if is_64_bit:
        debug_abbrev_offset = debug_info_reader.read_u64()
    else:
        debug_abbrev_offset = debug_info_reader.read_u32()

    address_size = debug_info_reader.read_u8()

    debug_abbrev_reader.offset = debug_abbrev_offset
    abbrev_table = _parse_abbrev_table(debug_abbrev_reader)

    return CompilationUnit(dwarf_file=dwarf_file, offset=offset,
                           unit_length=unit_length, version=version,
                           debug_abbrev_offset=debug_abbrev_offset,
                           address_size=address_size, is_64_bit=is_64_bit,
                           abbrev_table=abbrev_table)


def _parse_die_attrib(reader: _Reader, form: int,
                      cu: CompilationUnit) -> Union[int, bytes]:
    if form == DW_FORM.addr:  # address
        if cu.address_size == 4:
            return reader.read_u32()
        elif cu.address_size == 8:
            return reader.read_u64()
        else:
            raise DwarfFormatError(f'unsupported address size {cu.address_size}')
    elif form == DW_FORM.block1:  # block
        return reader.read_bytes(reader.read_u8())
    elif form == DW_FORM.block2:
        return reader.read_bytes(reader.read_u16())
    elif form == DW_FORM.block4:
        return reader.read_bytes(reader.read_u32())
    elif form == DW_FORM.exprloc:  # exprloc
        return reader.read_bytes(reader.read_uleb128())
    elif form == DW_FORM.data1:  # constant
        return reader.read_bytes(1)
    elif form == DW_FORM.data2:
        return reader.read_bytes(2)
    elif form == DW_FORM.data4:
        return reader.read_bytes(4)
    elif form == DW_FORM.data8:
        return reader.read_bytes(8)
    elif form == DW_FORM.sdata:
        return reader.read_sleb128()
    elif (form == DW_FORM.udata or     # constant
          form == DW_FORM.ref_udata):  # reference
        return reader.read_uleb128()
    elif (form == DW_FORM.ref_addr or    # reference
          form == DW_FORM.sec_offset or  # lineptr, loclistptr, macptr, rangelistptr
          form == DW_FORM.strp):         # string
        if cu.is_64_bit:
            return reader.read_u64()
        else:
            return reader.read_u32()
    elif form == DW_FORM.string:  # string
        return reader.read_c_string()
    elif form == DW_FORM.flag_present:  # flag
        return 1
    elif (form == DW_FORM.flag or  # flag
          form == DW_FORM.ref1):   # reference
        return reader.read_u8()
    elif form == DW_FORM.ref2:  # reference
        return reader.read_u16()
    elif form == DW_FORM.ref4:
        return reader.read_u32()
    elif (form == DW_FORM.ref8 or form == DW_FORM.ref_sig8):
        return reader.read_u64()
    elif form == DW_FORM.indirect:
        raise DwarfFormatError('DW_FORM_indirect is not supported')
    else:
        raise DwarfFormatError(f'unknown form 0x{form:x}')


def _parse_die_siblings(reader: _Reader, cu: CompilationUnit) -> List[Die]:
    children = []
    while True:
        child = _parse_die(reader, cu, True)
        if child is None:
            break
        children.append(child)
    return children


def _parse_die(reader: _Reader, cu: CompilationUnit,
               jump_to_sibling: bool) -> Optional[Die]:
    code = reader.read_uleb128()
    if jump_to_sibling and code == 0:
        return None
    try:
        decl = cu.abbrev_table[code]
    except KeyError:
        raise DwarfFormatError(f'unknown abbreviation code {code}')

    attribs = []
    sibling = None
    for name, form in decl.attribs:
        value = _parse_die_attrib(reader, form, cu)
        attrib = DieAttrib(name, form, value)
        if name == DW_AT.sibling:
            sibling = attrib
        attribs.append(attrib)

    if not decl.children:
        children_callable = None
    elif jump_to_sibling and sibling is None:
        children = _parse_die_siblings(reader, cu)
        children_callable = lambda: children
    else:
        children_callable = thunk(cu._die_siblings, reader.offset)
        # sibling is not None is always True here if jump_to_sibling is True,
        # but mypy isn't smart enough to figure that out so we spell it out.
        if jump_to_sibling and sibling is not None:
            assert isinstance(sibling.value, int)
            if sibling.form == DW_FORM.ref_addr:
                reader.offset = sibling.value
            else:
                reader.offset = cu.offset + sibling.value

    return Die(cu, decl.tag, attribs, children_callable)


def _parse_line_number_program(reader: _Reader, dwarf_file: DwarfFile) -> LineNumberProgram:
    offset = reader.offset
    unit_length = reader.read_u32()
    if unit_length == 0xffffffff:
        is_64_bit = True
        unit_length = reader.read_u64()
    else:
        is_64_bit = False

    version = reader.read_u16()
    if not 2 <= version <= 4:
        raise DwarfFormatError(f'unknown line number program version {version}')

    if is_64_bit:
        header_length = reader.read_u64()
    else:
        header_length = reader.read_u32()

    minimum_instruction_length = reader.read_u8()
    if version >= 4:
        maximum_operations_per_instruction = reader.read_u8()
    else:
        maximum_operations_per_instruction = 1
    default_is_stmt = bool(reader.read_u8())
    line_base = reader.read_s8()
    line_range = reader.read_u8()
    opcode_base = reader.read_u8()
    standard_opcode_lengths = reader.read_bytes(opcode_base - 1)

    include_directories = []
    while True:
        path = reader.read_c_string()
        if not path:
            break
        include_directories.append(os.fsdecode(path))

    file_names = []
    while True:
        path = reader.read_c_string()
        if not path:
            break
        directory = reader.read_uleb128()
        if directory > len(include_directories):
            raise DwarfFormatError(f'file name directory index {directory} out of range')
        mtime = reader.read_uleb128()
        size = reader.read_uleb128()
        file_names.append((os.fsdecode(path), directory, mtime, size))

    return LineNumberProgram(dwarf_file, offset, unit_length, version,
                             header_length, minimum_instruction_length,
                             maximum_operations_per_instruction,
                             default_is_stmt, line_base, line_range,
                             opcode_base, standard_opcode_lengths,
                             include_directories, file_names, is_64_bit)
