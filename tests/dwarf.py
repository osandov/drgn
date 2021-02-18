# Automatically generated from dwarf.h

import enum
from typing import Text


class DW_AT(enum.IntEnum):
    sibling = 0x1
    location = 0x2
    name = 0x3  # type: ignore
    ordering = 0x9
    byte_size = 0xB
    bit_offset = 0xC
    bit_size = 0xD
    stmt_list = 0x10
    low_pc = 0x11
    high_pc = 0x12
    language = 0x13
    discr = 0x15
    discr_value = 0x16
    visibility = 0x17
    import_ = 0x18
    string_length = 0x19
    common_reference = 0x1A
    comp_dir = 0x1B
    const_value = 0x1C
    containing_type = 0x1D
    default_value = 0x1E
    inline = 0x20
    is_optional = 0x21
    lower_bound = 0x22
    producer = 0x25
    prototyped = 0x27
    return_addr = 0x2A
    start_scope = 0x2C
    bit_stride = 0x2E
    upper_bound = 0x2F
    abstract_origin = 0x31
    accessibility = 0x32
    address_class = 0x33
    artificial = 0x34
    base_types = 0x35
    calling_convention = 0x36
    count = 0x37
    data_member_location = 0x38
    decl_column = 0x39
    decl_file = 0x3A
    decl_line = 0x3B
    declaration = 0x3C
    discr_list = 0x3D
    encoding = 0x3E
    external = 0x3F
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
    use_location = 0x4A
    variable_parameter = 0x4B
    virtuality = 0x4C
    vtable_elem_location = 0x4D
    allocated = 0x4E
    associated = 0x4F
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
    description = 0x5A
    binary_scale = 0x5B
    decimal_scale = 0x5C
    small = 0x5D
    decimal_sign = 0x5E
    digit_count = 0x5F
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
    main_subprogram = 0x6A
    data_bit_offset = 0x6B
    const_expr = 0x6C
    enum_class = 0x6D
    linkage_name = 0x6E
    string_length_bit_size = 0x6F
    string_length_byte_size = 0x70
    rank = 0x71
    str_offsets_base = 0x72
    addr_base = 0x73
    rnglists_base = 0x74
    dwo_name = 0x76
    reference = 0x77
    rvalue_reference = 0x78
    macros = 0x79
    call_all_calls = 0x7A
    call_all_source_calls = 0x7B
    call_all_tail_calls = 0x7C
    call_return_pc = 0x7D
    call_value = 0x7E
    call_origin = 0x7F
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
    deleted = 0x8A
    defaulted = 0x8B
    loclists_base = 0x8C
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
    MIPS_clone_origin = 0x200A
    MIPS_has_inlines = 0x200B
    MIPS_stride_byte = 0x200C
    MIPS_stride_elem = 0x200D
    MIPS_ptr_dopetype = 0x200E
    MIPS_allocatable_dopetype = 0x200F
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
    GNU_guarded = 0x210A
    GNU_pt_guarded = 0x210B
    GNU_locks_excluded = 0x210C
    GNU_exclusive_locks_required = 0x210D
    GNU_shared_locks_required = 0x210E
    GNU_odr_signature = 0x210F
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
    GNU_deleted = 0x211A
    GNU_dwo_name = 0x2130
    GNU_dwo_id = 0x2131
    GNU_ranges_base = 0x2132
    GNU_addr_base = 0x2133
    GNU_pubnames = 0x2134
    GNU_pubtypes = 0x2135
    GNU_numerator = 0x2303
    GNU_denominator = 0x2304
    GNU_bias = 0x2305
    hi_user = 0x3FFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_AT_{cls(value).name}"
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
    packed_decimal = 0xA
    numeric_string = 0xB
    edited = 0xC
    signed_fixed = 0xD
    unsigned_fixed = 0xE
    decimal_float = 0xF
    UTF = 0x10
    UCS = 0x11
    ASCII = 0x12
    lo_user = 0x80
    hi_user = 0xFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_ATE_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_CHILDREN(enum.IntEnum):
    no = 0x0
    yes = 0x1

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_CHILDREN_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_END(enum.IntEnum):
    default = 0x0
    big = 0x1
    little = 0x2
    lo_user = 0x40
    hi_user = 0xFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_END_{cls(value).name}"
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
    block1 = 0xA
    data1 = 0xB
    flag = 0xC
    sdata = 0xD
    strp = 0xE
    udata = 0xF
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
    strx = 0x1A
    addrx = 0x1B
    ref_sup4 = 0x1C
    strp_sup = 0x1D
    data16 = 0x1E
    line_strp = 0x1F
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
    addrx2 = 0x2A
    addrx3 = 0x2B
    addrx4 = 0x2C
    GNU_addr_index = 0x1F01
    GNU_str_index = 0x1F02
    GNU_ref_alt = 0x1F20
    GNU_strp_alt = 0x1F21

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_FORM_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_LANG(enum.IntEnum):
    C89 = 0x1
    C = 0x2
    Ada83 = 0x3
    C_plus_plus = 0x4
    Cobol74 = 0x5
    Cobol85 = 0x6
    Fortran77 = 0x7
    Fortran90 = 0x8
    Pascal83 = 0x9
    Modula2 = 0xA
    Java = 0xB
    C99 = 0xC
    Ada95 = 0xD
    Fortran95 = 0xE
    PLI = 0xF
    ObjC = 0x10
    ObjC_plus_plus = 0x11
    UPC = 0x12
    D = 0x13
    Python = 0x14
    OpenCL = 0x15
    Go = 0x16
    Modula3 = 0x17
    Haskell = 0x18
    C_plus_plus_03 = 0x19
    C_plus_plus_11 = 0x1A
    OCaml = 0x1B
    Rust = 0x1C
    C11 = 0x1D
    Swift = 0x1E
    Julia = 0x1F
    Dylan = 0x20
    C_plus_plus_14 = 0x21
    Fortran03 = 0x22
    Fortran08 = 0x23
    RenderScript = 0x24
    BLISS = 0x25
    lo_user = 0x8000
    Mips_Assembler = 0x8001
    hi_user = 0xFFFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_LANG_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_LNE(enum.IntEnum):
    end_sequence = 0x1
    set_address = 0x2
    define_file = 0x3
    set_discriminator = 0x4
    lo_user = 0x80
    hi_user = 0xFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_LNE_{cls(value).name}"
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
    set_prologue_end = 0xA
    set_epilogue_begin = 0xB
    set_isa = 0xC

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_LNS_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_OP(enum.IntEnum):
    addr = 0x3
    deref = 0x6
    const1u = 0x8
    const1s = 0x9
    const2u = 0xA
    const2s = 0xB
    const4u = 0xC
    const4s = 0xD
    const8u = 0xE
    const8s = 0xF
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
    and_ = 0x1A
    div = 0x1B
    minus = 0x1C
    mod = 0x1D
    mul = 0x1E
    neg = 0x1F
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
    ge = 0x2A
    gt = 0x2B
    le = 0x2C
    lt = 0x2D
    ne = 0x2E
    skip = 0x2F
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
    lit10 = 0x3A
    lit11 = 0x3B
    lit12 = 0x3C
    lit13 = 0x3D
    lit14 = 0x3E
    lit15 = 0x3F
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
    lit26 = 0x4A
    lit27 = 0x4B
    lit28 = 0x4C
    lit29 = 0x4D
    lit30 = 0x4E
    lit31 = 0x4F
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
    reg10 = 0x5A
    reg11 = 0x5B
    reg12 = 0x5C
    reg13 = 0x5D
    reg14 = 0x5E
    reg15 = 0x5F
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
    reg26 = 0x6A
    reg27 = 0x6B
    reg28 = 0x6C
    reg29 = 0x6D
    reg30 = 0x6E
    reg31 = 0x6F
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
    breg10 = 0x7A
    breg11 = 0x7B
    breg12 = 0x7C
    breg13 = 0x7D
    breg14 = 0x7E
    breg15 = 0x7F
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
    breg26 = 0x8A
    breg27 = 0x8B
    breg28 = 0x8C
    breg29 = 0x8D
    breg30 = 0x8E
    breg31 = 0x8F
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
    call_ref = 0x9A
    form_tls_address = 0x9B
    call_frame_cfa = 0x9C
    bit_piece = 0x9D
    implicit_value = 0x9E
    stack_value = 0x9F
    implicit_pointer = 0xA0
    addrx = 0xA1
    constx = 0xA2
    entry_value = 0xA3
    const_type = 0xA4
    regval_type = 0xA5
    deref_type = 0xA6
    xderef_type = 0xA7
    convert = 0xA8
    reinterpret = 0xA9
    GNU_push_tls_address = 0xE0
    GNU_uninit = 0xF0
    GNU_encoded_addr = 0xF1
    GNU_implicit_pointer = 0xF2
    GNU_entry_value = 0xF3
    GNU_const_type = 0xF4
    GNU_regval_type = 0xF5
    GNU_deref_type = 0xF6
    GNU_convert = 0xF7
    GNU_reinterpret = 0xF9
    GNU_parameter_ref = 0xFA
    GNU_addr_index = 0xFB
    GNU_const_index = 0xFC
    GNU_variable_value = 0xFD
    lo_user = 0xE0
    hi_user = 0xFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_OP_{cls(value).name}"
        except ValueError:
            return hex(value)


class DW_TAG(enum.IntEnum):
    array_type = 0x1
    class_type = 0x2
    entry_point = 0x3
    enumeration_type = 0x4
    formal_parameter = 0x5
    imported_declaration = 0x8
    label = 0xA
    lexical_block = 0xB
    member = 0xD
    pointer_type = 0xF
    reference_type = 0x10
    compile_unit = 0x11
    string_type = 0x12
    structure_type = 0x13
    subroutine_type = 0x15
    typedef = 0x16
    union_type = 0x17
    unspecified_parameters = 0x18
    variant = 0x19
    common_block = 0x1A
    common_inclusion = 0x1B
    inheritance = 0x1C
    inlined_subroutine = 0x1D
    module = 0x1E
    ptr_to_member_type = 0x1F
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
    friend = 0x2A
    namelist = 0x2B
    namelist_item = 0x2C
    packed_type = 0x2D
    subprogram = 0x2E
    template_type_parameter = 0x2F
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
    imported_module = 0x3A
    unspecified_type = 0x3B
    partial_unit = 0x3C
    imported_unit = 0x3D
    condition = 0x3F
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
    skeleton_unit = 0x4A
    immutable_type = 0x4B
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
    GNU_call_site_parameter = 0x410A
    hi_user = 0xFFFF

    @classmethod
    def str(cls, value: int) -> Text:
        try:
            return f"DW_TAG_{cls(value).name}"
        except ValueError:
            return hex(value)
