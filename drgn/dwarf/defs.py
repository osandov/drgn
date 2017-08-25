import enum

class DW_CHILDREN(enum.IntEnum):
    no = 0
    yes = 1


class DW_TAG(enum.IntEnum):
    array_type = 0x01,
    class_type = 0x02,
    entry_point = 0x03,
    enumeration_type = 0x04,
    formal_parameter = 0x05,
    imported_declaration = 0x08,
    label = 0x0a,
    lexical_block = 0x0b,
    member = 0x0d,
    pointer_type = 0x0f,
    reference_type = 0x10,
    compile_unit = 0x11,
    string_type = 0x12,
    structure_type = 0x13,
    subroutine_type = 0x15,
    typedef = 0x16,
    union_type = 0x17,
    unspecified_parameters = 0x18,
    variant = 0x19,
    common_block = 0x1a,
    common_inclusion = 0x1b,
    inheritance = 0x1c,
    inlined_subroutine = 0x1d,
    module = 0x1e,
    ptr_to_member_type = 0x1f,
    set_type = 0x20,
    subrange_type = 0x21,
    with_stmt = 0x22,
    access_declaration = 0x23,
    base_type = 0x24,
    catch_block = 0x25,
    const_type = 0x26,
    constant = 0x27,
    enumerator = 0x28,
    file_type = 0x29,
    friend = 0x2a,
    namelist = 0x2b,
    namelist_item = 0x2c,
    packed_type = 0x2d,
    subprogram = 0x2e,
    template_type_parameter = 0x2f,
    template_value_parameter = 0x30,
    thrown_type = 0x31,
    try_block = 0x32,
    variant_part = 0x33,
    variable = 0x34,
    volatile_type = 0x35,
    dwarf_procedure = 0x36,
    restrict_type = 0x37,
    interface_type = 0x38,
    namespace = 0x39,
    imported_module = 0x3a,
    unspecified_type = 0x3b,
    partial_unit = 0x3c,
    imported_unit = 0x3d,
    # 0x3e reserved
    condition = 0x3f,
    shared_type = 0x40,
    type_unit = 0x41,
    rvalue_reference_type = 0x42,
    template_alias = 0x43,

    # DWARF 5
    atomic_type = 0x47,

    lo_user = 0x4080,

    MIPS_loop = 0x4081,
    format_label = 0x4101,
    function_template = 0x4102,
    class_template = 0x4103,

    GNU_BINCL = 0x4104,
    GNU_EINCL = 0x4105,

    GNU_template_template_param = 0x4106,
    GNU_template_parameter_pack = 0x4107,
    GNU_formal_parameter_pack = 0x4108,
    GNU_call_site = 0x4109,
    GNU_call_site_parameter = 0x410a,

    hi_user = 0xffff


class DW_AT(enum.IntEnum):
    sibling = 0x01,
    location = 0x02,
    name = 0x03,
    ordering = 0x09,
    subscr_data = 0x0a,
    byte_size = 0x0b,
    bit_offset = 0x0c,
    bit_size = 0x0d,
    element_list = 0x0f,
    stmt_list = 0x10,
    low_pc = 0x11,
    high_pc = 0x12,
    language = 0x13,
    member = 0x14,
    discr = 0x15,
    discr_value = 0x16,
    visibility = 0x17,
    import_ = 0x18,
    string_length = 0x19,
    common_reference = 0x1a,
    comp_dir = 0x1b,
    const_value = 0x1c,
    containing_type = 0x1d,
    default_value = 0x1e,
    inline = 0x20,
    is_optional = 0x21,
    lower_bound = 0x22,
    producer = 0x25,
    prototyped = 0x27,
    return_addr = 0x2a,
    start_scope = 0x2c,
    bit_stride = 0x2e,
    upper_bound = 0x2f,
    abstract_origin = 0x31,
    accessibility = 0x32,
    address_class = 0x33,
    artificial = 0x34,
    base_types = 0x35,
    calling_convention = 0x36,
    count = 0x37,
    data_member_location = 0x38,
    decl_column = 0x39,
    decl_file = 0x3a,
    decl_line = 0x3b,
    declaration = 0x3c,
    discr_list = 0x3d,
    encoding = 0x3e,
    external = 0x3f,
    frame_base = 0x40,
    friend = 0x41,
    identifier_case = 0x42,
    macro_info = 0x43,
    namelist_item = 0x44,
    priority = 0x45,
    segment = 0x46,
    specification = 0x47,
    static_link = 0x48,
    type = 0x49,
    use_location = 0x4a,
    variable_parameter = 0x4b,
    virtuality = 0x4c,
    vtable_elem_location = 0x4d,
    allocated = 0x4e,
    associated = 0x4f,
    data_location = 0x50,
    byte_stride = 0x51,
    entry_pc = 0x52,
    use_UTF8 = 0x53,
    extension = 0x54,
    ranges = 0x55,
    trampoline = 0x56,
    call_column = 0x57,
    call_file = 0x58,
    call_line = 0x59,
    description = 0x5a,
    binary_scale = 0x5b,
    decimal_scale = 0x5c,
    small = 0x5d,
    decimal_sign = 0x5e,
    digit_count = 0x5f,
    picture_string = 0x60,
    mutable = 0x61,
    threads_scaled = 0x62,
    explicit = 0x63,
    object_pointer = 0x64,
    endianity = 0x65,
    elemental = 0x66,
    pure = 0x67,
    recursive = 0x68,
    signature = 0x69,
    main_subprogram = 0x6a,
    data_bit_offset = 0x6b,
    const_expr = 0x6c,
    enum_class = 0x6d,
    linkage_name = 0x6e,

    # DWARF5
    noreturn = 0x87,

    lo_user = 0x2000,

    MIPS_fde = 0x2001,
    MIPS_loop_begin = 0x2002,
    MIPS_tail_loop_begin = 0x2003,
    MIPS_epilog_begin = 0x2004,
    MIPS_loop_unroll_factor = 0x2005,
    MIPS_software_pipeline_depth = 0x2006,
    MIPS_linkage_name = 0x2007,
    MIPS_stride = 0x2008,
    MIPS_abstract_name = 0x2009,
    MIPS_clone_origin = 0x200a,
    MIPS_has_inlines = 0x200b,
    MIPS_stride_byte = 0x200c,
    MIPS_stride_elem = 0x200d,
    MIPS_ptr_dopetype = 0x200e,
    MIPS_allocatable_dopetype = 0x200f,
    MIPS_assumed_shape_dopetype = 0x2010,
    MIPS_assumed_size = 0x2011,

    # GNU extensions
    sf_names = 0x2101,
    src_info = 0x2102,
    mac_info = 0x2103,
    src_coords = 0x2104,
    body_begin = 0x2105,
    body_end = 0x2106,
    GNU_vector = 0x2107,
    GNU_guarded_by = 0x2108,
    GNU_pt_guarded_by = 0x2109,
    GNU_guarded = 0x210a,
    GNU_pt_guarded = 0x210b,
    GNU_locks_excluded = 0x210c,
    GNU_exclusive_locks_required = 0x210d,
    GNU_shared_locks_required = 0x210e,
    GNU_odr_signature = 0x210f,
    GNU_template_name = 0x2110,
    GNU_call_site_value = 0x2111,
    GNU_call_site_data_value = 0x2112,
    GNU_call_site_target = 0x2113,
    GNU_call_site_target_clobbered = 0x2114,
    GNU_tail_call = 0x2115,
    GNU_all_tail_call_sites = 0x2116,
    GNU_all_call_sites = 0x2117,
    GNU_all_source_call_sites = 0x2118,
    GNU_macros = 0x2119,
    GNU_deleted = 0x211a,

    hi_user = 0x3fff


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


class DW_LNE(enum.IntEnum):
    end_sequence = 1
    set_address = 2
    define_file = 3
    set_discriminator = 4

    lo_user = 128
    hi_user = 255


def at_name(at):
    try:
        return f'DW_AT_{DW_AT(at).name}'
    except ValueError:
        return str(at)


def at_class_constant(at):
    return (at == DW_FORM.data1 or at == DW_FORM.data2 or
            at == DW_FORM.data4 or at == DW_FORM.data8 or
            at == DW_FORM.udata or at == DW_FORM.sdata)


def at_class_constant_bytes(at):
    return (at == DW_FORM.data1 or at == DW_FORM.data2 or
            at == DW_FORM.data4 or at == DW_FORM.data8)


def at_class_constant_int(at):
    return at == DW_FORM.udata or at == DW_FORM.sdata


def form_name(form):
    try:
        return f'DW_FORM_{DW_FORM(form).name}'
    except ValueError:
        return str(form)


def tag_name(tag):
    try:
        return f'DW_TAG_{DW_TAG(tag).name}'
    except ValueError:
        return str(tag)


def lns_name(lns):
    try:
        return f'DW_LNS_{DW_LNS(lns).name}'
    except ValueError:
        return str(lns)


def lne_name(lne):
    try:
        return f'DW_LNE_{DW_LNE(lne).name}'
    except ValueError:
        return str(lne)
