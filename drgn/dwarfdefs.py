import enum

class DW_CHILDREN(enum.IntEnum):
    no = 0
    yes = 1


class DW_AT(enum.IntEnum):
    sibling = 0x01
    location = 0x02
    name = 0x03
    ordering = 0x09
    subscr_data = 0x0a
    byte_size = 0x0b
    bit_offset = 0x0c
    bit_size = 0x0d
    element_list = 0x0f
    stmt_list = 0x10
    low_pc = 0x11
    high_pc = 0x12
    language = 0x13
    member = 0x14
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

    # DWARF5
    noreturn = 0x87

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

    # GNU extensions
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
    GNU_macros = 0x2119
    GNU_deleted = 0x211a

    hi_user = 0x3fff


def at_name(at):
    try:
        return f'DW_AT_{DW_AT(at).name}'
    except ValueError:
        return hex(at)


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

    lo_user = 0x80
    hi_user = 0xff


def ate_name(ate):
    try:
        return f'DW_ATE_{DW_ATE(ate).name}'
    except ValueError:
        return hex(ate)


class DW_FORM(enum.IntEnum):
    addr = 0x01
    block2 = 0x03
    block4 = 0x04
    data2 = 0x05
    data4 = 0x06
    data8 = 0x07
    string = 0x08
    block = 0x09
    block1 = 0x0a
    data1 = 0x0b
    flag = 0x0c
    sdata = 0x0d
    strp = 0x0e
    udata = 0x0f
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
    ref_sig8 = 0x20


def form_name(form):
    try:
        return f'DW_FORM_{DW_FORM(form).name}'
    except ValueError:
        return hex(form)


class DW_LNS(enum.IntEnum):
    copy = 1
    advance_pc = 2
    advance_line = 3
    set_file = 4
    set_column = 5
    negate_stmt = 6
    set_basic_block = 7
    const_add_pc = 8
    fixed_advance_pc = 9
    set_prologue_end = 10
    set_epilogue_begin = 11
    set_isa = 12


def lns_name(lns):
    try:
        return f'DW_LNS_{DW_LNS(lns).name}'
    except ValueError:
        return hex(lns)


class DW_LNE(enum.IntEnum):
    end_sequence = 1
    set_address = 2
    define_file = 3
    set_discriminator = 4

    lo_user = 128
    hi_user = 255


def lne_name(lne):
    try:
        return f'DW_LNE_{DW_LNE(lne).name}'
    except ValueError:
        return hex(lne)


class DW_TAG(enum.IntEnum):
    array_type = 0x01
    class_type = 0x02
    entry_point = 0x03
    enumeration_type = 0x04
    formal_parameter = 0x05
    imported_declaration = 0x08
    label = 0x0a
    lexical_block = 0x0b
    member = 0x0d
    pointer_type = 0x0f
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
    # 0x3e reserved
    condition = 0x3f
    shared_type = 0x40
    type_unit = 0x41
    rvalue_reference_type = 0x42
    template_alias = 0x43

    # DWARF 5
    atomic_type = 0x47

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


def tag_name(tag):
    try:
        return f'DW_TAG_{DW_TAG(tag).name}'
    except ValueError:
        return hex(tag)


class DW_OP(enum.IntEnum):
    addr = 0x03         # Constant address.
    deref = 0x06
    const1u = 0x08      # Unsigned 1-byte constant.
    const1s = 0x09      # Signed 1-byte constant.
    const2u = 0x0a      # Unsigned 2-byte constant.
    const2s = 0x0b      # Signed 2-byte constant.
    const4u = 0x0c      # Unsigned 4-byte constant.
    const4s = 0x0d      # Signed 4-byte constant.
    const8u = 0x0e      # Unsigned 8-byte constant.
    const8s = 0x0f      # Signed 8-byte constant.
    constu = 0x10       # Unsigned LEB128 constant.
    consts = 0x11       # Signed LEB128 constant.
    dup = 0x12
    drop = 0x13
    over = 0x14
    pick = 0x15         # 1-byte stack index.
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
    plus_uconst = 0x23  # Unsigned LEB128 addend.
    shl = 0x24
    shr = 0x25
    shra = 0x26
    xor = 0x27
    bra = 0x28          # Signed 2-byte constant.
    eq = 0x29
    ge = 0x2a
    gt = 0x2b
    le = 0x2c
    lt = 0x2d
    ne = 0x2e
    skip = 0x2f         # Signed 2-byte constant.
    lit0 = 0x30         # Literal 0.
    lit1 = 0x31         # Literal 1.
    lit2 = 0x32         # Literal 2.
    lit3 = 0x33         # Literal 3.
    lit4 = 0x34         # Literal 4.
    lit5 = 0x35         # Literal 5.
    lit6 = 0x36         # Literal 6.
    lit7 = 0x37         # Literal 7.
    lit8 = 0x38         # Literal 8.
    lit9 = 0x39         # Literal 9.
    lit10 = 0x3a        # Literal 10.
    lit11 = 0x3b        # Literal 11.
    lit12 = 0x3c        # Literal 12.
    lit13 = 0x3d        # Literal 13.
    lit14 = 0x3e        # Literal 14.
    lit15 = 0x3f        # Literal 15.
    lit16 = 0x40        # Literal 16.
    lit17 = 0x41        # Literal 17.
    lit18 = 0x42        # Literal 18.
    lit19 = 0x43        # Literal 19.
    lit20 = 0x44        # Literal 20.
    lit21 = 0x45        # Literal 21.
    lit22 = 0x46        # Literal 22.
    lit23 = 0x47        # Literal 23.
    lit24 = 0x48        # Literal 24.
    lit25 = 0x49        # Literal 25.
    lit26 = 0x4a        # Literal 26.
    lit27 = 0x4b        # Literal 27.
    lit28 = 0x4c        # Literal 28.
    lit29 = 0x4d        # Literal 29.
    lit30 = 0x4e        # Literal 30.
    lit31 = 0x4f        # Literal 31.
    reg0 = 0x50         # Register 0.
    reg1 = 0x51         # Register 1.
    reg2 = 0x52         # Register 2.
    reg3 = 0x53         # Register 3.
    reg4 = 0x54         # Register 4.
    reg5 = 0x55         # Register 5.
    reg6 = 0x56         # Register 6.
    reg7 = 0x57         # Register 7.
    reg8 = 0x58         # Register 8.
    reg9 = 0x59         # Register 9.
    reg10 = 0x5a        # Register 10.
    reg11 = 0x5b        # Register 11.
    reg12 = 0x5c        # Register 12.
    reg13 = 0x5d        # Register 13.
    reg14 = 0x5e        # Register 14.
    reg15 = 0x5f        # Register 15.
    reg16 = 0x60        # Register 16.
    reg17 = 0x61        # Register 17.
    reg18 = 0x62        # Register 18.
    reg19 = 0x63        # Register 19.
    reg20 = 0x64        # Register 20.
    reg21 = 0x65        # Register 21.
    reg22 = 0x66        # Register 22.
    reg23 = 0x67        # Register 24.
    reg24 = 0x68        # Register 24.
    reg25 = 0x69        # Register 25.
    reg26 = 0x6a        # Register 26.
    reg27 = 0x6b        # Register 27.
    reg28 = 0x6c        # Register 28.
    reg29 = 0x6d        # Register 29.
    reg30 = 0x6e        # Register 30.
    reg31 = 0x6f        # Register 31.
    breg0 = 0x70        # Base register 0.
    breg1 = 0x71        # Base register 1.
    breg2 = 0x72        # Base register 2.
    breg3 = 0x73        # Base register 3.
    breg4 = 0x74        # Base register 4.
    breg5 = 0x75        # Base register 5.
    breg6 = 0x76        # Base register 6.
    breg7 = 0x77        # Base register 7.
    breg8 = 0x78        # Base register 8.
    breg9 = 0x79        # Base register 9.
    breg10 = 0x7a       # Base register 10.
    breg11 = 0x7b       # Base register 11.
    breg12 = 0x7c       # Base register 12.
    breg13 = 0x7d       # Base register 13.
    breg14 = 0x7e       # Base register 14.
    breg15 = 0x7f       # Base register 15.
    breg16 = 0x80       # Base register 16.
    breg17 = 0x81       # Base register 17.
    breg18 = 0x82       # Base register 18.
    breg19 = 0x83       # Base register 19.
    breg20 = 0x84       # Base register 20.
    breg21 = 0x85       # Base register 21.
    breg22 = 0x86       # Base register 22.
    breg23 = 0x87       # Base register 23.
    breg24 = 0x88       # Base register 24.
    breg25 = 0x89       # Base register 25.
    breg26 = 0x8a       # Base register 26.
    breg27 = 0x8b       # Base register 27.
    breg28 = 0x8c       # Base register 28.
    breg29 = 0x8d       # Base register 29.
    breg30 = 0x8e       # Base register 30.
    breg31 = 0x8f       # Base register 31.
    regx = 0x90         # Unsigned LEB128 register.
    fbreg = 0x91        # Signed LEB128 offset.
    bregx = 0x92        # ULEB128 register followed by SLEB128 off.
    piece = 0x93        # ULEB128 size of piece addressed.
    deref_size = 0x94   # 1-byte size of data retrieved.
    xderef_size = 0x95  # 1-byte size of data retrieved.
    nop = 0x96
    push_object_address = 0x97
    call2 = 0x98
    call4 = 0x99
    call_ref = 0x9a
    form_tls_address = 0x9b  # TLS offset to address in current thread
    call_frame_cfa = 0x9c    # CFA as determined by CFI.
    bit_piece = 0x9d         # ULEB128 size and ULEB128 offset in bits.
    implicit_value = 0x9e    # DW_FORM_block follows opcode.
    stack_value = 0x9f       # No operands, special like DW_OP_piece.

    # GNU extensions.
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

    lo_user = 0xe0  # Implementation-defined range start.
    hi_user = 0xff  # Implementation-defined range end.


def op_name(op):
    try:
        return f'DW_OP_{DW_OP(op).name}'
    except ValueError:
        return hex(op)


def at_class_constant(at):
    return (at == DW_FORM.data1 or at == DW_FORM.data2 or
            at == DW_FORM.data4 or at == DW_FORM.data8 or
            at == DW_FORM.udata or at == DW_FORM.sdata)


def at_class_constant_bytes(at):
    return (at == DW_FORM.data1 or at == DW_FORM.data2 or
            at == DW_FORM.data4 or at == DW_FORM.data8)


def at_class_constant_int(at):
    return at == DW_FORM.udata or at == DW_FORM.sdata


def at_class_reference(at):
    return (at == DW_FORM.ref1 or at == DW_FORM.ref2 or
            at == DW_FORM.ref4 or at == DW_FORM.ref8 or
            at == DW_FORM.ref_udata or at == DW_FORM.ref_sig8 or
            at == DW_FORM.ref_addr)


def at_class_internal_reference(at):
    return (at == DW_FORM.ref1 or at == DW_FORM.ref2 or
            at == DW_FORM.ref4 or at == DW_FORM.ref8 or
            at == DW_FORM.ref_udata)


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


UNQUALIFIED_TYPE_TAGS = {
    DW_TAG.array_type,
    # DW_TAG.atomic_type, DWARF 5, probably a qualifier?
    DW_TAG.base_type,
    DW_TAG.class_type,
    DW_TAG.file_type,
    DW_TAG.interface_type,
    DW_TAG.pointer_type,
    DW_TAG.ptr_to_member_type,
    DW_TAG.reference_type,
    DW_TAG.rvalue_reference_type,
    DW_TAG.set_type,
    DW_TAG.string_type,
    DW_TAG.structure_type,
    DW_TAG.subrange_type,
    DW_TAG.subroutine_type,
    DW_TAG.template_type_parameter,
    DW_TAG.typedef,
    DW_TAG.union_type,
    DW_TAG.unspecified_type,
}
