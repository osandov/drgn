from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, Py_buffer, PyBUF_SIMPLE
from cpython.mem cimport PyMem_Realloc, PyMem_Free
from libc.stdint cimport UINT32_MAX, UINT64_MAX
from libc.string cimport strcmp

from drgn.read cimport *
from drgn.elf import ElfFile
import enum
import mmap


cdef extern from "Python.h":
    void *PyMem_RawMalloc(size_t n)
    void *PyMem_RawCalloc(size_t nelem, size_t elsize)
    void PyMem_RawFree(void *p)

    void *PyMem_Calloc(size_t nelem, size_t elsize)


cdef enum:
    DW_AT_sibling = 0x1
    DW_AT_location = 0x2
    DW_AT_name = 0x3
    DW_AT_ordering = 0x9
    DW_AT_subscr_data = 0xa
    DW_AT_byte_size = 0xb
    DW_AT_bit_offset = 0xc
    DW_AT_bit_size = 0xd
    DW_AT_element_list = 0xf
    DW_AT_stmt_list = 0x10
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    DW_AT_member = 0x14
    DW_AT_discr = 0x15
    DW_AT_discr_value = 0x16
    DW_AT_visibility = 0x17
    DW_AT_import = 0x18
    DW_AT_string_length = 0x19
    DW_AT_common_reference = 0x1a
    DW_AT_comp_dir = 0x1b
    DW_AT_const_value = 0x1c
    DW_AT_containing_type = 0x1d
    DW_AT_default_value = 0x1e
    DW_AT_inline = 0x20
    DW_AT_is_optional = 0x21
    DW_AT_lower_bound = 0x22
    DW_AT_producer = 0x25
    DW_AT_prototyped = 0x27
    DW_AT_return_addr = 0x2a
    DW_AT_start_scope = 0x2c
    DW_AT_bit_stride = 0x2e
    DW_AT_upper_bound = 0x2f
    DW_AT_abstract_origin = 0x31
    DW_AT_accessibility = 0x32
    DW_AT_address_class = 0x33
    DW_AT_artificial = 0x34
    DW_AT_base_types = 0x35
    DW_AT_calling_convention = 0x36
    DW_AT_count = 0x37
    DW_AT_data_member_location = 0x38
    DW_AT_decl_column = 0x39
    DW_AT_decl_file = 0x3a
    DW_AT_decl_line = 0x3b
    DW_AT_declaration = 0x3c
    DW_AT_discr_list = 0x3d
    DW_AT_encoding = 0x3e
    DW_AT_external = 0x3f
    DW_AT_frame_base = 0x40
    DW_AT_friend = 0x41
    DW_AT_identifier_case = 0x42
    DW_AT_macro_info = 0x43
    DW_AT_namelist_item = 0x44
    DW_AT_priority = 0x45
    DW_AT_segment = 0x46
    DW_AT_specification = 0x47
    DW_AT_static_link = 0x48
    DW_AT_type = 0x49
    DW_AT_use_location = 0x4a
    DW_AT_variable_parameter = 0x4b
    DW_AT_virtuality = 0x4c
    DW_AT_vtable_elem_location = 0x4d
    DW_AT_allocated = 0x4e
    DW_AT_associated = 0x4f
    DW_AT_data_location = 0x50
    DW_AT_byte_stride = 0x51
    DW_AT_entry_pc = 0x52
    DW_AT_use_UTF8 = 0x53
    DW_AT_extension = 0x54
    DW_AT_ranges = 0x55
    DW_AT_trampoline = 0x56
    DW_AT_call_column = 0x57
    DW_AT_call_file = 0x58
    DW_AT_call_line = 0x59
    DW_AT_description = 0x5a
    DW_AT_binary_scale = 0x5b
    DW_AT_decimal_scale = 0x5c
    DW_AT_small = 0x5d
    DW_AT_decimal_sign = 0x5e
    DW_AT_digit_count = 0x5f
    DW_AT_picture_string = 0x60
    DW_AT_mutable = 0x61
    DW_AT_threads_scaled = 0x62
    DW_AT_explicit = 0x63
    DW_AT_object_pointer = 0x64
    DW_AT_endianity = 0x65
    DW_AT_elemental = 0x66
    DW_AT_pure = 0x67
    DW_AT_recursive = 0x68
    DW_AT_signature = 0x69
    DW_AT_main_subprogram = 0x6a
    DW_AT_data_bit_offset = 0x6b
    DW_AT_const_expr = 0x6c
    DW_AT_enum_class = 0x6d
    DW_AT_linkage_name = 0x6e
    DW_AT_noreturn = 0x87
    DW_AT_lo_user = 0x2000
    DW_AT_MIPS_fde = 0x2001
    DW_AT_MIPS_loop_begin = 0x2002
    DW_AT_MIPS_tail_loop_begin = 0x2003
    DW_AT_MIPS_epilog_begin = 0x2004
    DW_AT_MIPS_loop_unroll_factor = 0x2005
    DW_AT_MIPS_software_pipeline_depth = 0x2006
    DW_AT_MIPS_linkage_name = 0x2007
    DW_AT_MIPS_stride = 0x2008
    DW_AT_MIPS_abstract_name = 0x2009
    DW_AT_MIPS_clone_origin = 0x200a
    DW_AT_MIPS_has_inlines = 0x200b
    DW_AT_MIPS_stride_byte = 0x200c
    DW_AT_MIPS_stride_elem = 0x200d
    DW_AT_MIPS_ptr_dopetype = 0x200e
    DW_AT_MIPS_allocatable_dopetype = 0x200f
    DW_AT_MIPS_assumed_shape_dopetype = 0x2010
    DW_AT_MIPS_assumed_size = 0x2011
    DW_AT_sf_names = 0x2101
    DW_AT_src_info = 0x2102
    DW_AT_mac_info = 0x2103
    DW_AT_src_coords = 0x2104
    DW_AT_body_begin = 0x2105
    DW_AT_body_end = 0x2106
    DW_AT_GNU_vector = 0x2107
    DW_AT_GNU_guarded_by = 0x2108
    DW_AT_GNU_pt_guarded_by = 0x2109
    DW_AT_GNU_guarded = 0x210a
    DW_AT_GNU_pt_guarded = 0x210b
    DW_AT_GNU_locks_excluded = 0x210c
    DW_AT_GNU_exclusive_locks_required = 0x210d
    DW_AT_GNU_shared_locks_required = 0x210e
    DW_AT_GNU_odr_signature = 0x210f
    DW_AT_GNU_template_name = 0x2110
    DW_AT_GNU_call_site_value = 0x2111
    DW_AT_GNU_call_site_data_value = 0x2112
    DW_AT_GNU_call_site_target = 0x2113
    DW_AT_GNU_call_site_target_clobbered = 0x2114
    DW_AT_GNU_tail_call = 0x2115
    DW_AT_GNU_all_tail_call_sites = 0x2116
    DW_AT_GNU_all_call_sites = 0x2117
    DW_AT_GNU_all_source_call_sites = 0x2118
    DW_AT_GNU_macros = 0x2119
    DW_AT_GNU_deleted = 0x211a
    DW_AT_hi_user = 0x3fff


class DW_AT(enum.IntEnum):
    sibling = DW_AT_sibling
    location = DW_AT_location
    name = DW_AT_name
    ordering = DW_AT_ordering
    subscr_data = DW_AT_subscr_data
    byte_size = DW_AT_byte_size
    bit_offset = DW_AT_bit_offset
    bit_size = DW_AT_bit_size
    element_list = DW_AT_element_list
    stmt_list = DW_AT_stmt_list
    low_pc = DW_AT_low_pc
    high_pc = DW_AT_high_pc
    language = DW_AT_language
    member = DW_AT_member
    discr = DW_AT_discr
    discr_value = DW_AT_discr_value
    visibility = DW_AT_visibility
    import_ = DW_AT_import
    string_length = DW_AT_string_length
    common_reference = DW_AT_common_reference
    comp_dir = DW_AT_comp_dir
    const_value = DW_AT_const_value
    containing_type = DW_AT_containing_type
    default_value = DW_AT_default_value
    inline = DW_AT_inline
    is_optional = DW_AT_is_optional
    lower_bound = DW_AT_lower_bound
    producer = DW_AT_producer
    prototyped = DW_AT_prototyped
    return_addr = DW_AT_return_addr
    start_scope = DW_AT_start_scope
    bit_stride = DW_AT_bit_stride
    upper_bound = DW_AT_upper_bound
    abstract_origin = DW_AT_abstract_origin
    accessibility = DW_AT_accessibility
    address_class = DW_AT_address_class
    artificial = DW_AT_artificial
    base_types = DW_AT_base_types
    calling_convention = DW_AT_calling_convention
    count = DW_AT_count
    data_member_location = DW_AT_data_member_location
    decl_column = DW_AT_decl_column
    decl_file = DW_AT_decl_file
    decl_line = DW_AT_decl_line
    declaration = DW_AT_declaration
    discr_list = DW_AT_discr_list
    encoding = DW_AT_encoding
    external = DW_AT_external
    frame_base = DW_AT_frame_base
    friend = DW_AT_friend
    identifier_case = DW_AT_identifier_case
    macro_info = DW_AT_macro_info
    namelist_item = DW_AT_namelist_item
    priority = DW_AT_priority
    segment = DW_AT_segment
    specification = DW_AT_specification
    static_link = DW_AT_static_link
    type = DW_AT_type
    use_location = DW_AT_use_location
    variable_parameter = DW_AT_variable_parameter
    virtuality = DW_AT_virtuality
    vtable_elem_location = DW_AT_vtable_elem_location
    allocated = DW_AT_allocated
    associated = DW_AT_associated
    data_location = DW_AT_data_location
    byte_stride = DW_AT_byte_stride
    entry_pc = DW_AT_entry_pc
    use_UTF8 = DW_AT_use_UTF8
    extension = DW_AT_extension
    ranges = DW_AT_ranges
    trampoline = DW_AT_trampoline
    call_column = DW_AT_call_column
    call_file = DW_AT_call_file
    call_line = DW_AT_call_line
    description = DW_AT_description
    binary_scale = DW_AT_binary_scale
    decimal_scale = DW_AT_decimal_scale
    small = DW_AT_small
    decimal_sign = DW_AT_decimal_sign
    digit_count = DW_AT_digit_count
    picture_string = DW_AT_picture_string
    mutable = DW_AT_mutable
    threads_scaled = DW_AT_threads_scaled
    explicit = DW_AT_explicit
    object_pointer = DW_AT_object_pointer
    endianity = DW_AT_endianity
    elemental = DW_AT_elemental
    pure = DW_AT_pure
    recursive = DW_AT_recursive
    signature = DW_AT_signature
    main_subprogram = DW_AT_main_subprogram
    data_bit_offset = DW_AT_data_bit_offset
    const_expr = DW_AT_const_expr
    enum_class = DW_AT_enum_class
    linkage_name = DW_AT_linkage_name
    noreturn = DW_AT_noreturn
    lo_user = DW_AT_lo_user
    MIPS_fde = DW_AT_MIPS_fde
    MIPS_loop_begin = DW_AT_MIPS_loop_begin
    MIPS_tail_loop_begin = DW_AT_MIPS_tail_loop_begin
    MIPS_epilog_begin = DW_AT_MIPS_epilog_begin
    MIPS_loop_unroll_factor = DW_AT_MIPS_loop_unroll_factor
    MIPS_software_pipeline_depth = DW_AT_MIPS_software_pipeline_depth
    MIPS_linkage_name = DW_AT_MIPS_linkage_name
    MIPS_stride = DW_AT_MIPS_stride
    MIPS_abstract_name = DW_AT_MIPS_abstract_name
    MIPS_clone_origin = DW_AT_MIPS_clone_origin
    MIPS_has_inlines = DW_AT_MIPS_has_inlines
    MIPS_stride_byte = DW_AT_MIPS_stride_byte
    MIPS_stride_elem = DW_AT_MIPS_stride_elem
    MIPS_ptr_dopetype = DW_AT_MIPS_ptr_dopetype
    MIPS_allocatable_dopetype = DW_AT_MIPS_allocatable_dopetype
    MIPS_assumed_shape_dopetype = DW_AT_MIPS_assumed_shape_dopetype
    MIPS_assumed_size = DW_AT_MIPS_assumed_size
    sf_names = DW_AT_sf_names
    src_info = DW_AT_src_info
    mac_info = DW_AT_mac_info
    src_coords = DW_AT_src_coords
    body_begin = DW_AT_body_begin
    body_end = DW_AT_body_end
    GNU_vector = DW_AT_GNU_vector
    GNU_guarded_by = DW_AT_GNU_guarded_by
    GNU_pt_guarded_by = DW_AT_GNU_pt_guarded_by
    GNU_guarded = DW_AT_GNU_guarded
    GNU_pt_guarded = DW_AT_GNU_pt_guarded
    GNU_locks_excluded = DW_AT_GNU_locks_excluded
    GNU_exclusive_locks_required = DW_AT_GNU_exclusive_locks_required
    GNU_shared_locks_required = DW_AT_GNU_shared_locks_required
    GNU_odr_signature = DW_AT_GNU_odr_signature
    GNU_template_name = DW_AT_GNU_template_name
    GNU_call_site_value = DW_AT_GNU_call_site_value
    GNU_call_site_data_value = DW_AT_GNU_call_site_data_value
    GNU_call_site_target = DW_AT_GNU_call_site_target
    GNU_call_site_target_clobbered = DW_AT_GNU_call_site_target_clobbered
    GNU_tail_call = DW_AT_GNU_tail_call
    GNU_all_tail_call_sites = DW_AT_GNU_all_tail_call_sites
    GNU_all_call_sites = DW_AT_GNU_all_call_sites
    GNU_all_source_call_sites = DW_AT_GNU_all_source_call_sites
    GNU_macros = DW_AT_GNU_macros
    GNU_deleted = DW_AT_GNU_deleted
    hi_user = DW_AT_hi_user

    @classmethod
    def str(cls, value):
        try:
            return f'DW_AT_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_ATE_void = 0x0
    DW_ATE_address = 0x1
    DW_ATE_boolean = 0x2
    DW_ATE_complex_float = 0x3
    DW_ATE_float = 0x4
    DW_ATE_signed = 0x5
    DW_ATE_signed_char = 0x6
    DW_ATE_unsigned = 0x7
    DW_ATE_unsigned_char = 0x8
    DW_ATE_imaginary_float = 0x9
    DW_ATE_packed_decimal = 0xa
    DW_ATE_numeric_string = 0xb
    DW_ATE_edited = 0xc
    DW_ATE_signed_fixed = 0xd
    DW_ATE_unsigned_fixed = 0xe
    DW_ATE_decimal_float = 0xf
    DW_ATE_UTF = 0x10
    DW_ATE_lo_user = 0x80
    DW_ATE_hi_user = 0xff


class DW_ATE(enum.IntEnum):
    void = DW_ATE_void
    address = DW_ATE_address
    boolean = DW_ATE_boolean
    complex_float = DW_ATE_complex_float
    float = DW_ATE_float
    signed = DW_ATE_signed
    signed_char = DW_ATE_signed_char
    unsigned = DW_ATE_unsigned
    unsigned_char = DW_ATE_unsigned_char
    imaginary_float = DW_ATE_imaginary_float
    packed_decimal = DW_ATE_packed_decimal
    numeric_string = DW_ATE_numeric_string
    edited = DW_ATE_edited
    signed_fixed = DW_ATE_signed_fixed
    unsigned_fixed = DW_ATE_unsigned_fixed
    decimal_float = DW_ATE_decimal_float
    UTF = DW_ATE_UTF
    lo_user = DW_ATE_lo_user
    hi_user = DW_ATE_hi_user

    @classmethod
    def str(cls, value):
        try:
            return f'DW_ATE_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_CHILDREN_no = 0x0
    DW_CHILDREN_yes = 0x1


class DW_CHILDREN(enum.IntEnum):
    no = DW_CHILDREN_no
    yes = DW_CHILDREN_yes

    @classmethod
    def str(cls, value):
        try:
            return f'DW_CHILDREN_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_FORM_addr = 0x1
    DW_FORM_block2 = 0x3
    DW_FORM_block4 = 0x4
    DW_FORM_data2 = 0x5
    DW_FORM_data4 = 0x6
    DW_FORM_data8 = 0x7
    DW_FORM_string = 0x8
    DW_FORM_block = 0x9
    DW_FORM_block1 = 0xa
    DW_FORM_data1 = 0xb
    DW_FORM_flag = 0xc
    DW_FORM_sdata = 0xd
    DW_FORM_strp = 0xe
    DW_FORM_udata = 0xf
    DW_FORM_ref_addr = 0x10
    DW_FORM_ref1 = 0x11
    DW_FORM_ref2 = 0x12
    DW_FORM_ref4 = 0x13
    DW_FORM_ref8 = 0x14
    DW_FORM_ref_udata = 0x15
    DW_FORM_indirect = 0x16
    DW_FORM_sec_offset = 0x17
    DW_FORM_exprloc = 0x18
    DW_FORM_flag_present = 0x19
    DW_FORM_ref_sig8 = 0x20


class DW_FORM(enum.IntEnum):
    addr = DW_FORM_addr
    block2 = DW_FORM_block2
    block4 = DW_FORM_block4
    data2 = DW_FORM_data2
    data4 = DW_FORM_data4
    data8 = DW_FORM_data8
    string = DW_FORM_string
    block = DW_FORM_block
    block1 = DW_FORM_block1
    data1 = DW_FORM_data1
    flag = DW_FORM_flag
    sdata = DW_FORM_sdata
    strp = DW_FORM_strp
    udata = DW_FORM_udata
    ref_addr = DW_FORM_ref_addr
    ref1 = DW_FORM_ref1
    ref2 = DW_FORM_ref2
    ref4 = DW_FORM_ref4
    ref8 = DW_FORM_ref8
    ref_udata = DW_FORM_ref_udata
    indirect = DW_FORM_indirect
    sec_offset = DW_FORM_sec_offset
    exprloc = DW_FORM_exprloc
    flag_present = DW_FORM_flag_present
    ref_sig8 = DW_FORM_ref_sig8

    @classmethod
    def str(cls, value):
        try:
            return f'DW_FORM_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_LNE_end_sequence = 0x1
    DW_LNE_set_address = 0x2
    DW_LNE_define_file = 0x3
    DW_LNE_set_discriminator = 0x4
    DW_LNE_lo_user = 0x80
    DW_LNE_hi_user = 0xff


class DW_LNE(enum.IntEnum):
    end_sequence = DW_LNE_end_sequence
    set_address = DW_LNE_set_address
    define_file = DW_LNE_define_file
    set_discriminator = DW_LNE_set_discriminator
    lo_user = DW_LNE_lo_user
    hi_user = DW_LNE_hi_user

    @classmethod
    def str(cls, value):
        try:
            return f'DW_LNE_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_LNS_copy = 0x1
    DW_LNS_advance_pc = 0x2
    DW_LNS_advance_line = 0x3
    DW_LNS_set_file = 0x4
    DW_LNS_set_column = 0x5
    DW_LNS_negate_stmt = 0x6
    DW_LNS_set_basic_block = 0x7
    DW_LNS_const_add_pc = 0x8
    DW_LNS_fixed_advance_pc = 0x9
    DW_LNS_set_prologue_end = 0xa
    DW_LNS_set_epilogue_begin = 0xb
    DW_LNS_set_isa = 0xc


class DW_LNS(enum.IntEnum):
    copy = DW_LNS_copy
    advance_pc = DW_LNS_advance_pc
    advance_line = DW_LNS_advance_line
    set_file = DW_LNS_set_file
    set_column = DW_LNS_set_column
    negate_stmt = DW_LNS_negate_stmt
    set_basic_block = DW_LNS_set_basic_block
    const_add_pc = DW_LNS_const_add_pc
    fixed_advance_pc = DW_LNS_fixed_advance_pc
    set_prologue_end = DW_LNS_set_prologue_end
    set_epilogue_begin = DW_LNS_set_epilogue_begin
    set_isa = DW_LNS_set_isa

    @classmethod
    def str(cls, value):
        try:
            return f'DW_LNS_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_OP_addr = 0x3
    DW_OP_deref = 0x6
    DW_OP_const1u = 0x8
    DW_OP_const1s = 0x9
    DW_OP_const2u = 0xa
    DW_OP_const2s = 0xb
    DW_OP_const4u = 0xc
    DW_OP_const4s = 0xd
    DW_OP_const8u = 0xe
    DW_OP_const8s = 0xf
    DW_OP_constu = 0x10
    DW_OP_consts = 0x11
    DW_OP_dup = 0x12
    DW_OP_drop = 0x13
    DW_OP_over = 0x14
    DW_OP_pick = 0x15
    DW_OP_swap = 0x16
    DW_OP_rot = 0x17
    DW_OP_xderef = 0x18
    DW_OP_abs = 0x19
    DW_OP_and = 0x1a
    DW_OP_div = 0x1b
    DW_OP_minus = 0x1c
    DW_OP_mod = 0x1d
    DW_OP_mul = 0x1e
    DW_OP_neg = 0x1f
    DW_OP_not = 0x20
    DW_OP_or = 0x21
    DW_OP_plus = 0x22
    DW_OP_plus_uconst = 0x23
    DW_OP_shl = 0x24
    DW_OP_shr = 0x25
    DW_OP_shra = 0x26
    DW_OP_xor = 0x27
    DW_OP_bra = 0x28
    DW_OP_eq = 0x29
    DW_OP_ge = 0x2a
    DW_OP_gt = 0x2b
    DW_OP_le = 0x2c
    DW_OP_lt = 0x2d
    DW_OP_ne = 0x2e
    DW_OP_skip = 0x2f
    DW_OP_lit0 = 0x30
    DW_OP_lit1 = 0x31
    DW_OP_lit2 = 0x32
    DW_OP_lit3 = 0x33
    DW_OP_lit4 = 0x34
    DW_OP_lit5 = 0x35
    DW_OP_lit6 = 0x36
    DW_OP_lit7 = 0x37
    DW_OP_lit8 = 0x38
    DW_OP_lit9 = 0x39
    DW_OP_lit10 = 0x3a
    DW_OP_lit11 = 0x3b
    DW_OP_lit12 = 0x3c
    DW_OP_lit13 = 0x3d
    DW_OP_lit14 = 0x3e
    DW_OP_lit15 = 0x3f
    DW_OP_lit16 = 0x40
    DW_OP_lit17 = 0x41
    DW_OP_lit18 = 0x42
    DW_OP_lit19 = 0x43
    DW_OP_lit20 = 0x44
    DW_OP_lit21 = 0x45
    DW_OP_lit22 = 0x46
    DW_OP_lit23 = 0x47
    DW_OP_lit24 = 0x48
    DW_OP_lit25 = 0x49
    DW_OP_lit26 = 0x4a
    DW_OP_lit27 = 0x4b
    DW_OP_lit28 = 0x4c
    DW_OP_lit29 = 0x4d
    DW_OP_lit30 = 0x4e
    DW_OP_lit31 = 0x4f
    DW_OP_reg0 = 0x50
    DW_OP_reg1 = 0x51
    DW_OP_reg2 = 0x52
    DW_OP_reg3 = 0x53
    DW_OP_reg4 = 0x54
    DW_OP_reg5 = 0x55
    DW_OP_reg6 = 0x56
    DW_OP_reg7 = 0x57
    DW_OP_reg8 = 0x58
    DW_OP_reg9 = 0x59
    DW_OP_reg10 = 0x5a
    DW_OP_reg11 = 0x5b
    DW_OP_reg12 = 0x5c
    DW_OP_reg13 = 0x5d
    DW_OP_reg14 = 0x5e
    DW_OP_reg15 = 0x5f
    DW_OP_reg16 = 0x60
    DW_OP_reg17 = 0x61
    DW_OP_reg18 = 0x62
    DW_OP_reg19 = 0x63
    DW_OP_reg20 = 0x64
    DW_OP_reg21 = 0x65
    DW_OP_reg22 = 0x66
    DW_OP_reg23 = 0x67
    DW_OP_reg24 = 0x68
    DW_OP_reg25 = 0x69
    DW_OP_reg26 = 0x6a
    DW_OP_reg27 = 0x6b
    DW_OP_reg28 = 0x6c
    DW_OP_reg29 = 0x6d
    DW_OP_reg30 = 0x6e
    DW_OP_reg31 = 0x6f
    DW_OP_breg0 = 0x70
    DW_OP_breg1 = 0x71
    DW_OP_breg2 = 0x72
    DW_OP_breg3 = 0x73
    DW_OP_breg4 = 0x74
    DW_OP_breg5 = 0x75
    DW_OP_breg6 = 0x76
    DW_OP_breg7 = 0x77
    DW_OP_breg8 = 0x78
    DW_OP_breg9 = 0x79
    DW_OP_breg10 = 0x7a
    DW_OP_breg11 = 0x7b
    DW_OP_breg12 = 0x7c
    DW_OP_breg13 = 0x7d
    DW_OP_breg14 = 0x7e
    DW_OP_breg15 = 0x7f
    DW_OP_breg16 = 0x80
    DW_OP_breg17 = 0x81
    DW_OP_breg18 = 0x82
    DW_OP_breg19 = 0x83
    DW_OP_breg20 = 0x84
    DW_OP_breg21 = 0x85
    DW_OP_breg22 = 0x86
    DW_OP_breg23 = 0x87
    DW_OP_breg24 = 0x88
    DW_OP_breg25 = 0x89
    DW_OP_breg26 = 0x8a
    DW_OP_breg27 = 0x8b
    DW_OP_breg28 = 0x8c
    DW_OP_breg29 = 0x8d
    DW_OP_breg30 = 0x8e
    DW_OP_breg31 = 0x8f
    DW_OP_regx = 0x90
    DW_OP_fbreg = 0x91
    DW_OP_bregx = 0x92
    DW_OP_piece = 0x93
    DW_OP_deref_size = 0x94
    DW_OP_xderef_size = 0x95
    DW_OP_nop = 0x96
    DW_OP_push_object_address = 0x97
    DW_OP_call2 = 0x98
    DW_OP_call4 = 0x99
    DW_OP_call_ref = 0x9a
    DW_OP_form_tls_address = 0x9b
    DW_OP_call_frame_cfa = 0x9c
    DW_OP_bit_piece = 0x9d
    DW_OP_implicit_value = 0x9e
    DW_OP_stack_value = 0x9f
    DW_OP_GNU_push_tls_address = 0xe0
    DW_OP_GNU_uninit = 0xf0
    DW_OP_GNU_encoded_addr = 0xf1
    DW_OP_GNU_implicit_pointer = 0xf2
    DW_OP_GNU_entry_value = 0xf3
    DW_OP_GNU_const_type = 0xf4
    DW_OP_GNU_regval_type = 0xf5
    DW_OP_GNU_deref_type = 0xf6
    DW_OP_GNU_convert = 0xf7
    DW_OP_GNU_reinterpret = 0xf9
    DW_OP_GNU_parameter_ref = 0xfa
    DW_OP_lo_user = 0xe0
    DW_OP_hi_user = 0xff


class DW_OP(enum.IntEnum):
    addr = DW_OP_addr
    deref = DW_OP_deref
    const1u = DW_OP_const1u
    const1s = DW_OP_const1s
    const2u = DW_OP_const2u
    const2s = DW_OP_const2s
    const4u = DW_OP_const4u
    const4s = DW_OP_const4s
    const8u = DW_OP_const8u
    const8s = DW_OP_const8s
    constu = DW_OP_constu
    consts = DW_OP_consts
    dup = DW_OP_dup
    drop = DW_OP_drop
    over = DW_OP_over
    pick = DW_OP_pick
    swap = DW_OP_swap
    rot = DW_OP_rot
    xderef = DW_OP_xderef
    abs = DW_OP_abs
    and_ = DW_OP_and
    div = DW_OP_div
    minus = DW_OP_minus
    mod = DW_OP_mod
    mul = DW_OP_mul
    neg = DW_OP_neg
    not_ = DW_OP_not
    or_ = DW_OP_or
    plus = DW_OP_plus
    plus_uconst = DW_OP_plus_uconst
    shl = DW_OP_shl
    shr = DW_OP_shr
    shra = DW_OP_shra
    xor = DW_OP_xor
    bra = DW_OP_bra
    eq = DW_OP_eq
    ge = DW_OP_ge
    gt = DW_OP_gt
    le = DW_OP_le
    lt = DW_OP_lt
    ne = DW_OP_ne
    skip = DW_OP_skip
    lit0 = DW_OP_lit0
    lit1 = DW_OP_lit1
    lit2 = DW_OP_lit2
    lit3 = DW_OP_lit3
    lit4 = DW_OP_lit4
    lit5 = DW_OP_lit5
    lit6 = DW_OP_lit6
    lit7 = DW_OP_lit7
    lit8 = DW_OP_lit8
    lit9 = DW_OP_lit9
    lit10 = DW_OP_lit10
    lit11 = DW_OP_lit11
    lit12 = DW_OP_lit12
    lit13 = DW_OP_lit13
    lit14 = DW_OP_lit14
    lit15 = DW_OP_lit15
    lit16 = DW_OP_lit16
    lit17 = DW_OP_lit17
    lit18 = DW_OP_lit18
    lit19 = DW_OP_lit19
    lit20 = DW_OP_lit20
    lit21 = DW_OP_lit21
    lit22 = DW_OP_lit22
    lit23 = DW_OP_lit23
    lit24 = DW_OP_lit24
    lit25 = DW_OP_lit25
    lit26 = DW_OP_lit26
    lit27 = DW_OP_lit27
    lit28 = DW_OP_lit28
    lit29 = DW_OP_lit29
    lit30 = DW_OP_lit30
    lit31 = DW_OP_lit31
    reg0 = DW_OP_reg0
    reg1 = DW_OP_reg1
    reg2 = DW_OP_reg2
    reg3 = DW_OP_reg3
    reg4 = DW_OP_reg4
    reg5 = DW_OP_reg5
    reg6 = DW_OP_reg6
    reg7 = DW_OP_reg7
    reg8 = DW_OP_reg8
    reg9 = DW_OP_reg9
    reg10 = DW_OP_reg10
    reg11 = DW_OP_reg11
    reg12 = DW_OP_reg12
    reg13 = DW_OP_reg13
    reg14 = DW_OP_reg14
    reg15 = DW_OP_reg15
    reg16 = DW_OP_reg16
    reg17 = DW_OP_reg17
    reg18 = DW_OP_reg18
    reg19 = DW_OP_reg19
    reg20 = DW_OP_reg20
    reg21 = DW_OP_reg21
    reg22 = DW_OP_reg22
    reg23 = DW_OP_reg23
    reg24 = DW_OP_reg24
    reg25 = DW_OP_reg25
    reg26 = DW_OP_reg26
    reg27 = DW_OP_reg27
    reg28 = DW_OP_reg28
    reg29 = DW_OP_reg29
    reg30 = DW_OP_reg30
    reg31 = DW_OP_reg31
    breg0 = DW_OP_breg0
    breg1 = DW_OP_breg1
    breg2 = DW_OP_breg2
    breg3 = DW_OP_breg3
    breg4 = DW_OP_breg4
    breg5 = DW_OP_breg5
    breg6 = DW_OP_breg6
    breg7 = DW_OP_breg7
    breg8 = DW_OP_breg8
    breg9 = DW_OP_breg9
    breg10 = DW_OP_breg10
    breg11 = DW_OP_breg11
    breg12 = DW_OP_breg12
    breg13 = DW_OP_breg13
    breg14 = DW_OP_breg14
    breg15 = DW_OP_breg15
    breg16 = DW_OP_breg16
    breg17 = DW_OP_breg17
    breg18 = DW_OP_breg18
    breg19 = DW_OP_breg19
    breg20 = DW_OP_breg20
    breg21 = DW_OP_breg21
    breg22 = DW_OP_breg22
    breg23 = DW_OP_breg23
    breg24 = DW_OP_breg24
    breg25 = DW_OP_breg25
    breg26 = DW_OP_breg26
    breg27 = DW_OP_breg27
    breg28 = DW_OP_breg28
    breg29 = DW_OP_breg29
    breg30 = DW_OP_breg30
    breg31 = DW_OP_breg31
    regx = DW_OP_regx
    fbreg = DW_OP_fbreg
    bregx = DW_OP_bregx
    piece = DW_OP_piece
    deref_size = DW_OP_deref_size
    xderef_size = DW_OP_xderef_size
    nop = DW_OP_nop
    push_object_address = DW_OP_push_object_address
    call2 = DW_OP_call2
    call4 = DW_OP_call4
    call_ref = DW_OP_call_ref
    form_tls_address = DW_OP_form_tls_address
    call_frame_cfa = DW_OP_call_frame_cfa
    bit_piece = DW_OP_bit_piece
    implicit_value = DW_OP_implicit_value
    stack_value = DW_OP_stack_value
    GNU_push_tls_address = DW_OP_GNU_push_tls_address
    GNU_uninit = DW_OP_GNU_uninit
    GNU_encoded_addr = DW_OP_GNU_encoded_addr
    GNU_implicit_pointer = DW_OP_GNU_implicit_pointer
    GNU_entry_value = DW_OP_GNU_entry_value
    GNU_const_type = DW_OP_GNU_const_type
    GNU_regval_type = DW_OP_GNU_regval_type
    GNU_deref_type = DW_OP_GNU_deref_type
    GNU_convert = DW_OP_GNU_convert
    GNU_reinterpret = DW_OP_GNU_reinterpret
    GNU_parameter_ref = DW_OP_GNU_parameter_ref
    lo_user = DW_OP_lo_user
    hi_user = DW_OP_hi_user

    @classmethod
    def str(cls, value):
        try:
            return f'DW_OP_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef enum:
    DW_TAG_array_type = 0x1
    DW_TAG_class_type = 0x2
    DW_TAG_entry_point = 0x3
    DW_TAG_enumeration_type = 0x4
    DW_TAG_formal_parameter = 0x5
    DW_TAG_imported_declaration = 0x8
    DW_TAG_label = 0xa
    DW_TAG_lexical_block = 0xb
    DW_TAG_member = 0xd
    DW_TAG_pointer_type = 0xf
    DW_TAG_reference_type = 0x10
    DW_TAG_compile_unit = 0x11
    DW_TAG_string_type = 0x12
    DW_TAG_structure_type = 0x13
    DW_TAG_subroutine_type = 0x15
    DW_TAG_typedef = 0x16
    DW_TAG_union_type = 0x17
    DW_TAG_unspecified_parameters = 0x18
    DW_TAG_variant = 0x19
    DW_TAG_common_block = 0x1a
    DW_TAG_common_inclusion = 0x1b
    DW_TAG_inheritance = 0x1c
    DW_TAG_inlined_subroutine = 0x1d
    DW_TAG_module = 0x1e
    DW_TAG_ptr_to_member_type = 0x1f
    DW_TAG_set_type = 0x20
    DW_TAG_subrange_type = 0x21
    DW_TAG_with_stmt = 0x22
    DW_TAG_access_declaration = 0x23
    DW_TAG_base_type = 0x24
    DW_TAG_catch_block = 0x25
    DW_TAG_const_type = 0x26
    DW_TAG_constant = 0x27
    DW_TAG_enumerator = 0x28
    DW_TAG_file_type = 0x29
    DW_TAG_friend = 0x2a
    DW_TAG_namelist = 0x2b
    DW_TAG_namelist_item = 0x2c
    DW_TAG_packed_type = 0x2d
    DW_TAG_subprogram = 0x2e
    DW_TAG_template_type_parameter = 0x2f
    DW_TAG_template_value_parameter = 0x30
    DW_TAG_thrown_type = 0x31
    DW_TAG_try_block = 0x32
    DW_TAG_variant_part = 0x33
    DW_TAG_variable = 0x34
    DW_TAG_volatile_type = 0x35
    DW_TAG_dwarf_procedure = 0x36
    DW_TAG_restrict_type = 0x37
    DW_TAG_interface_type = 0x38
    DW_TAG_namespace = 0x39
    DW_TAG_imported_module = 0x3a
    DW_TAG_unspecified_type = 0x3b
    DW_TAG_partial_unit = 0x3c
    DW_TAG_imported_unit = 0x3d
    DW_TAG_condition = 0x3f
    DW_TAG_shared_type = 0x40
    DW_TAG_type_unit = 0x41
    DW_TAG_rvalue_reference_type = 0x42
    DW_TAG_template_alias = 0x43
    DW_TAG_atomic_type = 0x47
    DW_TAG_lo_user = 0x4080
    DW_TAG_MIPS_loop = 0x4081
    DW_TAG_format_label = 0x4101
    DW_TAG_function_template = 0x4102
    DW_TAG_class_template = 0x4103
    DW_TAG_GNU_BINCL = 0x4104
    DW_TAG_GNU_EINCL = 0x4105
    DW_TAG_GNU_template_template_param = 0x4106
    DW_TAG_GNU_template_parameter_pack = 0x4107
    DW_TAG_GNU_formal_parameter_pack = 0x4108
    DW_TAG_GNU_call_site = 0x4109
    DW_TAG_GNU_call_site_parameter = 0x410a
    DW_TAG_hi_user = 0xffff


class DW_TAG(enum.IntEnum):
    array_type = DW_TAG_array_type
    class_type = DW_TAG_class_type
    entry_point = DW_TAG_entry_point
    enumeration_type = DW_TAG_enumeration_type
    formal_parameter = DW_TAG_formal_parameter
    imported_declaration = DW_TAG_imported_declaration
    label = DW_TAG_label
    lexical_block = DW_TAG_lexical_block
    member = DW_TAG_member
    pointer_type = DW_TAG_pointer_type
    reference_type = DW_TAG_reference_type
    compile_unit = DW_TAG_compile_unit
    string_type = DW_TAG_string_type
    structure_type = DW_TAG_structure_type
    subroutine_type = DW_TAG_subroutine_type
    typedef = DW_TAG_typedef
    union_type = DW_TAG_union_type
    unspecified_parameters = DW_TAG_unspecified_parameters
    variant = DW_TAG_variant
    common_block = DW_TAG_common_block
    common_inclusion = DW_TAG_common_inclusion
    inheritance = DW_TAG_inheritance
    inlined_subroutine = DW_TAG_inlined_subroutine
    module = DW_TAG_module
    ptr_to_member_type = DW_TAG_ptr_to_member_type
    set_type = DW_TAG_set_type
    subrange_type = DW_TAG_subrange_type
    with_stmt = DW_TAG_with_stmt
    access_declaration = DW_TAG_access_declaration
    base_type = DW_TAG_base_type
    catch_block = DW_TAG_catch_block
    const_type = DW_TAG_const_type
    constant = DW_TAG_constant
    enumerator = DW_TAG_enumerator
    file_type = DW_TAG_file_type
    friend = DW_TAG_friend
    namelist = DW_TAG_namelist
    namelist_item = DW_TAG_namelist_item
    packed_type = DW_TAG_packed_type
    subprogram = DW_TAG_subprogram
    template_type_parameter = DW_TAG_template_type_parameter
    template_value_parameter = DW_TAG_template_value_parameter
    thrown_type = DW_TAG_thrown_type
    try_block = DW_TAG_try_block
    variant_part = DW_TAG_variant_part
    variable = DW_TAG_variable
    volatile_type = DW_TAG_volatile_type
    dwarf_procedure = DW_TAG_dwarf_procedure
    restrict_type = DW_TAG_restrict_type
    interface_type = DW_TAG_interface_type
    namespace = DW_TAG_namespace
    imported_module = DW_TAG_imported_module
    unspecified_type = DW_TAG_unspecified_type
    partial_unit = DW_TAG_partial_unit
    imported_unit = DW_TAG_imported_unit
    condition = DW_TAG_condition
    shared_type = DW_TAG_shared_type
    type_unit = DW_TAG_type_unit
    rvalue_reference_type = DW_TAG_rvalue_reference_type
    template_alias = DW_TAG_template_alias
    atomic_type = DW_TAG_atomic_type
    lo_user = DW_TAG_lo_user
    MIPS_loop = DW_TAG_MIPS_loop
    format_label = DW_TAG_format_label
    function_template = DW_TAG_function_template
    class_template = DW_TAG_class_template
    GNU_BINCL = DW_TAG_GNU_BINCL
    GNU_EINCL = DW_TAG_GNU_EINCL
    GNU_template_template_param = DW_TAG_GNU_template_template_param
    GNU_template_parameter_pack = DW_TAG_GNU_template_parameter_pack
    GNU_formal_parameter_pack = DW_TAG_GNU_formal_parameter_pack
    GNU_call_site = DW_TAG_GNU_call_site
    GNU_call_site_parameter = DW_TAG_GNU_call_site_parameter
    hi_user = DW_TAG_hi_user

    @classmethod
    def str(cls, value):
        try:
            return f'DW_TAG_{cls(value).name}'
        except ValueError:
            return hex(value)


cdef bint tag_is_type(uint64_t tag):
    return (
        tag == DW_TAG_array_type or
        tag == DW_TAG_atomic_type or
        tag == DW_TAG_base_type or
        tag == DW_TAG_class_type or
        tag == DW_TAG_const_type or
        tag == DW_TAG_enumeration_type or
        tag == DW_TAG_file_type or
        tag == DW_TAG_interface_type or
        tag == DW_TAG_packed_type or
        tag == DW_TAG_pointer_type or
        tag == DW_TAG_ptr_to_member_type or
        tag == DW_TAG_reference_type or
        tag == DW_TAG_restrict_type or
        tag == DW_TAG_rvalue_reference_type or
        tag == DW_TAG_set_type or
        tag == DW_TAG_shared_type or
        tag == DW_TAG_string_type or
        tag == DW_TAG_structure_type or
        tag == DW_TAG_subrange_type or
        tag == DW_TAG_subroutine_type or
        tag == DW_TAG_template_type_parameter or
        tag == DW_TAG_thrown_type or
        tag == DW_TAG_typedef or
        tag == DW_TAG_union_type or
        tag == DW_TAG_unspecified_type or
        tag == DW_TAG_volatile_type
    )


cdef class DwarfFormatError(Exception):
    pass


cdef class DwarfAttribNotFoundError(Exception):
    pass


cdef class DwarfLocationNotFoundError(Exception):
    pass


SECTIONS = [
    '.debug_abbrev',
    '.debug_aranges',
    '.debug_info',
    '.debug_line',
    '.debug_loc',
    '.debug_ranges',
    '.debug_str',
]


cdef class DwarfFile:
    cdef dict sections

    def __init__(self, sections):
        self.sections = sections

    @staticmethod
    def from_elf_file(elf_file):
        sections = {}
        for section in SECTIONS:
            try:
                shdr = elf_file.shdr(section)
            except KeyError:
                continue
            sections[section] = elf_file.read_section(shdr)
        return DwarfFile(sections)

    @staticmethod
    def from_file(file):
        return DwarfFile.from_elf_file(ElfFile(file))

    cdef int get_section_buffer(self, str name, Py_buffer *buffer) except -1:
        try:
            data = self.sections[name]
        except KeyError:
            raise DwarfFormatError(f'no {name} section')
        PyObject_GetBuffer(data, buffer, PyBUF_SIMPLE)
        return 0

    cdef CompilationUnitHeader cu_header(self, Py_buffer *debug_info_buffer,
                                         Py_buffer *debug_abbrev_buffer,
                                         Py_ssize_t offset):
        cdef CompilationUnitHeader cu
        cu = parse_compilation_unit_header(debug_info_buffer, &offset, self)
        offset = cu.debug_abbrev_offset
        parse_abbrev_table(debug_abbrev_buffer, &offset, &cu._abbrev_table)
        return cu

    def cu_headers(self):
        cdef CompilationUnitHeader cu
        cdef Py_buffer debug_info_buffer
        cdef Py_buffer debug_abbrev_buffer
        cdef Py_ssize_t offset = 0

        self.get_section_buffer('.debug_info', &debug_info_buffer)
        try:
            self.get_section_buffer('.debug_abbrev', &debug_abbrev_buffer)
            try:
                while offset < debug_info_buffer.len:
                    cu = self.cu_header(&debug_info_buffer,
                                        &debug_abbrev_buffer, offset)
                    yield cu
                    offset = cu.end_offset()
            finally:
                PyBuffer_Release(&debug_abbrev_buffer)
        finally:
            PyBuffer_Release(&debug_info_buffer)

    def arange_tables(self):
        cdef Py_buffer buffer
        cdef Py_ssize_t offset = 0

        self.get_section_buffer('.debug_aranges', &buffer)
        try:
            while offset < buffer.len:
                art = parse_arange_table(&buffer, &offset)
                yield art
                offset = art.end_offset()
        finally:
            PyBuffer_Release(&buffer)


cdef class AddressRange:
    cdef public uint64_t segment
    cdef public uint64_t address
    cdef public uint64_t length

    def __cinit__(self, uint64_t segment, uint64_t address, uint64_t length):
        self.segment = segment
        self.address = address
        self.length = length


cdef class ArangeTable:
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset
    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t debug_info_offset
    cdef public uint8_t address_size
    cdef public uint8_t segment_size
    cdef public bint is_64_bit
    cdef public list table

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length


cdef struct AttribSpec:
    uint64_t name
    uint64_t form


cdef struct AbbrevDecl:
    uint64_t tag
    bint children
    uint64_t num_attribs
    AttribSpec *attribs


# Technically, abbreviation codes don't have to be sequential. In practice, GCC
# seems to always generate sequential codes, so we can get away with a flat
# array.
cdef struct AbbrevTable:
    uint64_t num_decls
    AbbrevDecl *decls


cdef class CompilationUnitHeader:
    cdef public DwarfFile dwarf_file
    # Offset from the beginning of .debug_info (or whatever section it was
    # parsed from).
    cdef public Py_ssize_t offset

    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t debug_abbrev_offset
    cdef public uint8_t address_size
    cdef public bint is_64_bit

    cdef str _name

    cdef AbbrevTable _abbrev_table

    def __dealloc__(self):
        for i in range(self._abbrev_table.num_decls):
            PyMem_Free(self._abbrev_table.decls[i].attribs)
        PyMem_Free(self._abbrev_table.decls)

    cpdef str name(self):
        if self._name is not None:
            return self._name

        self._name = self.die().name()
        return self._name

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length

    cpdef Py_ssize_t die_offset(self):
        return self.offset + (23 if self.is_64_bit else 11)

    cdef AbbrevDecl *abbrev_decl(self, uint64_t code):
        if code < 1 or code > self._abbrev_table.num_decls:
            return NULL
        return &self._abbrev_table.decls[code - 1]

    cpdef Die die(self, Py_ssize_t offset=0):
        cdef Py_buffer buffer

        if offset == 0:
            offset = self.die_offset()
        else:
            offset += self.offset

        self.dwarf_file.get_section_buffer('.debug_info', &buffer)
        try:
            return parse_die(&buffer, &offset, self, False)
        finally:
            PyBuffer_Release(&buffer)

    cpdef LineNumberProgram line_number_program(self):
        cdef Py_buffer buffer
        cdef Py_ssize_t offset

        offset = self.die().find_sec_offset(DW_AT_stmt_list)

        self.dwarf_file.get_section_buffer('.debug_line', &buffer)
        try:
            return parse_line_number_program(&buffer, &offset, self)
        finally:
            PyBuffer_Release(&buffer)


cdef struct DieAttribValuePtr:
    # Offset from the beginning of the section.
    Py_ssize_t offset
    Py_ssize_t length


cdef union DieAttribValue:
    # DW_FORM_addr, DW_FORM_udata, DW_FORM_flag{,_present},
    # DW_FORM_sec_offset, DW_FORM_ref{1,2,4,8,_sig8,_udata,_addr},
    # and DW_FORM_strp. For DW_FORM_flag_present, always 1.
    uint64_t u

    # DW_FORM_sdata.
    int64_t s

    # DW_FORM_data{1,2,4,8}
    char data[8]

    # DW_FORM_block{,1,2,4}, DW_FORM_exprloc, and DW_FORM_string.
    DieAttribValuePtr ptr


cdef struct DieAttrib:
    uint64_t name
    uint64_t form
    DieAttribValue value


cdef class Die:
    cdef public CompilationUnitHeader cu
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset
    cdef public Py_ssize_t length
    cdef public uint64_t tag
    cdef list _children
    # XXX: Cython doesn't support variable-size objects.
    cdef DieAttrib *attribs
    cdef Py_ssize_t num_attribs

    def __dealloc__(self):
        PyMem_Free(self.attribs)

    def __len__(self):
        return self.num_attribs

    def __getitem__(self, i):
        if i < 0 or i >= self.num_attribs:
            raise IndexError('attribute index out of range')
        cdef const DieAttrib *attrib = &self.attribs[i]
        return (attrib.name, attrib.form, self.attrib_value(attrib))

    def __eq__(self, other):
        if not isinstance(other, Die):
            return False
        cdef Die other_die = other
        return (self.cu == other_die.cu and
                self.offset == other_die.offset and
                self.length == other_die.length and
                self.tag == other_die.tag and
                list(self) == list(other_die))

    def __contains__(self, item):
        for i in range(self.num_attribs):
            if self.attribs[i].name == item:
                return True
        return False

    cdef const DieAttrib *find_attrib(self, uint64_t name) except NULL:
        for i in range(self.num_attribs):
            if self.attribs[i].name == name:
                return &self.attribs[i]
        else:
            raise DwarfAttribNotFoundError(f'no attribute with name {DW_AT.str(name)}')

    @staticmethod
    cdef uint64_t attrib_sec_offset(const DieAttrib *attrib):
        if attrib.form == DW_FORM_data4:
            # DWARF 2 and 3
            return (<const uint32_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_sec_offset:
            return attrib.value.u
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for section offset')

    cdef object attrib_value(self, const DieAttrib *attrib):
        cdef Py_buffer buffer
        cdef Py_ssize_t offset

        if (attrib.form == DW_FORM_addr or
                attrib.form == DW_FORM_udata or
                attrib.form == DW_FORM_ref_udata or
                attrib.form == DW_FORM_ref1 or
                attrib.form == DW_FORM_ref2 or
                attrib.form == DW_FORM_ref4 or
                attrib.form == DW_FORM_ref8 or
                attrib.form == DW_FORM_ref_sig8 or
                attrib.form == DW_FORM_sec_offset or
                attrib.form == DW_FORM_strp):
            return attrib.value.u
        elif (attrib.form == DW_FORM_block1 or
              attrib.form == DW_FORM_block2 or
              attrib.form == DW_FORM_block4 or
              attrib.form == DW_FORM_block or
              attrib.form == DW_FORM_exprloc or
              attrib.form == DW_FORM_string):
            offset = attrib.value.ptr.offset
            self.cu.dwarf_file.get_section_buffer('.debug_info', &buffer)
            try:
                return read_bytes(&buffer, &offset, attrib.value.ptr.length)
            finally:
                PyBuffer_Release(&buffer)
        elif attrib.form == DW_FORM_data1:
            return PyBytes_FromStringAndSize(attrib.value.data, 1)
        elif attrib.form == DW_FORM_data2:
            return PyBytes_FromStringAndSize(attrib.value.data, 2)
        elif attrib.form == DW_FORM_data4:
            return PyBytes_FromStringAndSize(attrib.value.data, 4)
        elif attrib.form == DW_FORM_data8:
            return PyBytes_FromStringAndSize(attrib.value.data, 8)
        elif attrib.form == DW_FORM_sdata:
            return attrib.value.s
        elif attrib.form == DW_FORM_flag:
            return bool(attrib.value.u)
        elif attrib.form == DW_FORM_flag_present:
            return True
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)}')

    def find(self, at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        return attrib.form, self.attrib_value(attrib)

    def find_constant(self, at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        if attrib.form == DW_FORM_data1:
            return (<const uint8_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data2:
            return (<const uint16_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data4:
            return (<const uint32_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data8:
            return (<const uint64_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_udata:
            return attrib.value.u
        elif attrib.form == DW_FORM_sdata:
            return attrib.value.s
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for constant')

    cpdef find_string(self, uint64_t at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        cdef Py_buffer buffer
        cdef Py_ssize_t offset

        if attrib.form == DW_FORM_strp:
            offset = attrib.value.u
            self.cu.dwarf_file.get_section_buffer('.debug_str', &buffer)
            try:
                return read_str(&buffer, &offset)
            finally:
                PyBuffer_Release(&buffer)
        elif attrib.form == DW_FORM_string:
            self.cu.dwarf_file.get_section_buffer('.debug_info', &buffer)
            try:
                return PyUnicode_FromStringAndSize(<const char *>buffer.buf + attrib.value.ptr.offset,
                                                   attrib.value.ptr.length)
            finally:
                PyBuffer_Release(&buffer)
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for string')

    cpdef find_sec_offset(self, uint64_t at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        return Die.attrib_sec_offset(attrib)

    def find_flag(self, at):
        cdef const DieAttrib *attrib
        try:
            attrib = self.find_attrib(at)
        except DwarfAttribNotFoundError:
            return False
        if attrib.form == DW_FORM_flag_present:
            return True
        elif attrib.form == DW_FORM_flag:
            return bool(attrib.value.u)
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for flag')

    cpdef str name(self):
        return self.find_string(DW_AT_name)

    def size(self):
        return self.find_constant(DW_AT_byte_size)

    cpdef uint64_t address(self):
        cdef const DieAttrib *low_pc = self.find_attrib(DW_AT_low_pc)
        if low_pc.form != DW_FORM_addr:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(low_pc.form)} for DW_AT_low_pc')
        return low_pc.value.u

    cpdef uint64_t high_address(self):
        cdef const DieAttrib *high_pc = self.find_attrib(DW_AT_high_pc)
        cdef uint64_t length
        if high_pc.form == DW_FORM_addr:
            return high_pc.value.u
        else:
            if high_pc.form == DW_FORM_data1:
                length = (<const uint8_t *>&high_pc.value.data[0])[0]
            elif high_pc.form == DW_FORM_data2:
                length = (<const uint16_t *>&high_pc.value.data[0])[0]
            elif high_pc.form == DW_FORM_data4:
                length = (<const uint32_t *>&high_pc.value.data[0])[0]
            elif high_pc.form == DW_FORM_data8:
                length = (<const uint64_t *>&high_pc.value.data[0])[0]
            elif high_pc.form == DW_FORM_udata:
                length = high_pc.value.u
            else:
                raise DwarfFormatError(f'unknown form {DW_FORM.str(high_pc.form)} for DW_AT_high_pc')
            return self.address() + length

    def type(self):
        cdef const DieAttrib *attrib = self.find_attrib(DW_AT_type)

        if (attrib.form == DW_FORM_ref1 or attrib.form == DW_FORM_ref2 or
                attrib.form == DW_FORM_ref4 or attrib.form == DW_FORM_ref8 or
                attrib.form == DW_FORM_ref_udata):
            return self.cu.die(attrib.value.u)
        elif attrib.form == DW_FORM_ref_addr:
            raise NotImplementedError('DW_FORM_ref_addr is not implemented')
        elif attrib.form == DW_FORM_ref_sig8:
            raise NotImplementedError('DW_FORM_ref_sig8 is not implemented')
        else:
            raise DwarfFormatError(f'unknown form {DW_FORM.str(attrib.form)} for DW_AT_type')

    cpdef list children(self):
        # Note that _children isn't a cache; it's used for DIEs with no
        # children or DIEs which we had to parse the children for anyways when
        # we were parsing a list of siblings.
        if self._children is not None:
            return self._children

        cdef Py_buffer buffer
        cdef Py_ssize_t offset

        offset = self.offset + self.length

        self.cu.dwarf_file.get_section_buffer('.debug_info', &buffer)
        try:
            return parse_die_siblings(&buffer, &offset, self.cu)
        finally:
            PyBuffer_Release(&buffer)

    def location(self, uint64_t addr):
        cdef const DieAttrib *attrib = self.find_attrib(DW_AT_location)
        cdef Py_buffer buffer
        cdef Py_ssize_t offset

        if attrib.form == DW_FORM_exprloc:
            return self.attrib_value(attrib)
        else:
            return self.location_list_entry(Die.attrib_sec_offset(attrib),
                                            addr)

    cdef bytes location_list_entry(self, Py_ssize_t offset, uint64_t addr):
        cdef Py_buffer buffer
        cdef uint64_t base_addr
        cdef uint64_t start
        cdef uint64_t end
        cdef uint16_t lle_length

        try:
            base_addr = self.cu.die().address()
        except DwarfAttribNotFoundError:
            base_addr = 0

        self.cu.dwarf_file.get_section_buffer('.debug_loc', &buffer)
        try:
            while True:
                if self.cu.address_size == 4:
                    read_u32_into_u64(&buffer, &offset, &start)
                    read_u32_into_u64(&buffer, &offset, &end)
                    if start == UINT32_MAX:
                        base_addr = end
                        continue
                elif self.cu.address_size == 8:
                    read_u64(&buffer, &offset, &start)
                    read_u64(&buffer, &offset, &end)
                    if start == UINT64_MAX:
                        base_addr = end
                        continue
                else:
                    raise DwarfFormatError(f'unsupported address size {self.cu.address_size}')

                if start == 0 and end == 0:
                    break

                read_u16(&buffer, &offset, &lle_length)

                if base_addr + start <= addr < base_addr + end:
                    return read_bytes(&buffer, &offset, lle_length)
        finally:
            PyBuffer_Release(&buffer)

        raise DwarfLocationNotFoundError(f'could not find location list entry for address 0x{addr:x}')

    def is_type(self):
        return tag_is_type(self.tag)

    def is_qualified_type(self):
        return (
            self.tag == DW_TAG_atomic_type or
            self.tag == DW_TAG_const_type or
            self.tag == DW_TAG_packed_type or
            self.tag == DW_TAG_restrict_type or
            self.tag == DW_TAG_shared_type or
            self.tag == DW_TAG_volatile_type
        )

    def unqualified(self):
        if not self.is_type():
            raise ValueError('not a type DIE')
        die = self
        while die.is_qualified_type() or die.tag == DW_TAG_typedef:
            die = die.type()
        return die

    cpdef bint contains_address(self, uint64_t addr):
        cdef uint64_t ranges
        try:
            ranges = self.find_sec_offset(DW_AT_ranges)
        except DwarfAttribNotFoundError:
            pass
        else:
            return self.ranges_contains_address(ranges, addr)

        cdef uint64_t low_pc
        cdef uint64_t high_pc
        try:
            low_pc = self.address()
            high_pc = self.high_address()
        except DwarfAttribNotFoundError:
            raise DwarfAttribNotFoundError('DIE does not have address range information')

        return low_pc <= addr < high_pc

    cdef bint ranges_contains_address(self, Py_ssize_t offset, uint64_t addr):
        cdef Py_buffer buffer
        cdef uint64_t base_addr
        cdef uint64_t start
        cdef uint64_t end

        try:
            base_addr = self.cu.die().address()
        except DwarfAttribNotFoundError:
            base_addr = 0

        self.cu.dwarf_file.get_section_buffer('.debug_ranges', &buffer)
        try:
            while True:
                if self.cu.address_size == 4:
                    read_u32_into_u64(&buffer, &offset, &start)
                    read_u32_into_u64(&buffer, &offset, &end)
                    if start == UINT32_MAX:
                        base_addr = end
                        continue
                elif self.cu.address_size == 8:
                    read_u64(&buffer, &offset, &start)
                    read_u64(&buffer, &offset, &end)
                    if start == UINT64_MAX:
                        base_addr = end
                        continue
                else:
                    raise DwarfFormatError(f'unsupported address size {self.cu.address_size}')

                if start == 0 and end == 0:
                    break

                if base_addr + start <= addr < base_addr + end:
                    return True
        finally:
            PyBuffer_Release(&buffer)

        return False


cdef class LineNumberProgram:
    cdef public CompilationUnitHeader cu
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset

    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t header_length
    cdef public uint8_t minimum_instruction_length
    cdef public uint8_t maximum_operations_per_instruction
    cdef public bint default_is_stmt
    cdef public int8_t line_base
    cdef public uint8_t line_range
    cdef public uint8_t opcode_base
    cdef public list standard_opcode_lengths
    cdef public list include_directories
    cdef public list file_names
    cdef public bint is_64_bit

    cpdef Py_ssize_t program_offset(self):
        return self.offset + (22 if self.is_64_bit else 10) + self.header_length

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length

    cdef init_state(self, LineNumberRow state):
        state.address = 0
        state.op_index = 0
        state.file = 1
        state.line = 1
        state.column = 0
        state.is_stmt = self.default_is_stmt
        state.basic_block = False
        state.end_sequence = False
        state.prologue_end = False
        state.epilogue_begin = False
        state.isa = 0
        state.discriminator = 0

    @staticmethod
    cdef reset_state(LineNumberRow state):
        state.basic_block = False
        state.prologue_end = False
        state.epilogue_begin = False
        state.discriminator = 0

    cpdef list execute(self):
        cdef Py_buffer buffer
        cdef Py_ssize_t offset = self.program_offset()
        cdef Py_ssize_t end = self.end_offset()

        cdef LineNumberRow state = LineNumberRow.__new__(LineNumberRow, self)
        self.init_state(state)

        cdef list matrix = []
        cdef uint8_t opcode
        self.cu.dwarf_file.get_section_buffer('.debug_line', &buffer)
        try:
            while offset < end:
                read_u8(&buffer, &offset, &opcode)
                self.execute_opcode(&buffer, &offset, state, matrix, opcode)
        finally:
            PyBuffer_Release(&buffer)
        return matrix

    cdef execute_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                        LineNumberRow state, list matrix, uint8_t opcode):
        if opcode == 0:
            self.execute_extended_opcode(buffer, offset, state, matrix)
        elif opcode < self.opcode_base:
            self.execute_standard_opcode(buffer, offset, state, matrix, opcode)
        else:
            self.execute_special_opcode(state, matrix, opcode)

    cdef execute_extended_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                                 LineNumberRow state, list matrix):
        cdef uint64_t op_length
        read_uleb128(buffer, offset, &op_length)
        read_check_bounds(buffer, offset[0], op_length)
        cdef Py_ssize_t end = offset[0] + op_length

        cdef uint8_t opcode
        read_u8(buffer, offset, &opcode)
        if opcode == DW_LNE_end_sequence:
            state.end_sequence = True
            matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
            self.init_state(state)
        elif opcode == DW_LNE_set_address:
            if op_length == 9:
                read_u64(buffer, offset, &state.address)
            elif op_length == 5:
                read_u32_into_u64(buffer, offset, &state.address)
            else:
                raise DwarfFormatError(f'unsupported address size {op_length}')
            state.op_index = 0
        elif opcode == DW_LNE_define_file:
            raise NotImplementedError('DW_LNE_define_file is not implemented')
        elif opcode == DW_LNE_set_discriminator:
            read_uleb128(buffer, offset, &state.discriminator)
        else:
            raise DwarfFormatError(f'unknown extended opcode {DW_LNE.str(opcode)}')

    cdef advance_pc(self, LineNumberRow state, uint64_t operation_advance):
        state.address += (self.minimum_instruction_length *
                          ((state.op_index + operation_advance) /
                            self.maximum_operations_per_instruction))
        state.op_index = ((state.op_index + operation_advance) %
                           self.maximum_operations_per_instruction)

    cdef execute_standard_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                                 LineNumberRow state, list matrix, uint8_t opcode):
        cdef uint64_t arg
        cdef int64_t sarg

        if opcode == DW_LNS_copy:
            matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
            LineNumberProgram.reset_state(state)
        elif opcode == DW_LNS_advance_pc:
            read_uleb128(buffer, offset, &arg)
            self.advance_pc(state, arg)
        elif opcode == DW_LNS_advance_line:
            read_sleb128(buffer, offset, &sarg)
            state.line += sarg
        elif opcode == DW_LNS_set_file:
            read_uleb128(buffer, offset, &state.file)
        elif opcode == DW_LNS_set_column:
            read_uleb128(buffer, offset, &state.column)
        elif opcode == DW_LNS_negate_stmt:
            state.is_stmt = not state.is_stmt
        elif opcode == DW_LNS_set_basic_block:
            state.basic_block = True
        elif opcode == DW_LNS_const_add_pc:
            self.advance_pc(state, (255 - self.opcode_base) / self.line_range)
        elif opcode == DW_LNS_fixed_advance_pc:
            self.advance_pc(state, (255 - self.opcode_base) / self.line_range)
            read_u16_into_u64(buffer, offset, &arg)
            state.address += arg
            state.op_index = 0
        elif opcode == DW_LNS_set_prologue_end:
            state.prologue_end = True
        elif opcode == DW_LNS_set_epilogue_begin:
            state.epilogue_begin = True
        elif opcode == DW_LNS_set_isa:
            read_uleb128(buffer, offset, &state.isa)
        else:
            raise DwarfFormatError(f'unknown standard opcode {DW_LNS.str(opcode)}')

    cdef execute_special_opcode(self, LineNumberRow state, list matrix, uint8_t opcode):
        cdef uint8_t adjusted_opcode = opcode - self.opcode_base
        cdef uint8_t operation_advance = adjusted_opcode / self.line_range

        self.advance_pc(state, operation_advance)
        state.line += self.line_base + (adjusted_opcode % self.line_range)
        matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
        LineNumberProgram.reset_state(state)


cdef class LineNumberRow:
    cdef public LineNumberProgram lnp

    cdef public uint64_t address
    cdef public uint64_t file
    cdef public uint64_t line
    cdef public uint64_t column
    cdef public uint64_t isa
    cdef public uint64_t discriminator
    cdef public uint8_t op_index
    cdef public bint is_stmt
    cdef public bint basic_block
    cdef public bint end_sequence
    cdef public bint prologue_end
    cdef public bint epilogue_begin

    def __cinit__(self, LineNumberProgram lnp, LineNumberRow row=None):
        self.lnp = lnp
        if row is not None:
            self.address = row.address
            self.file = row.file
            self.line = row.line
            self.column = row.column
            self.isa = row.isa
            self.discriminator = row.discriminator
            self.op_index = row.op_index
            self.is_stmt = row.is_stmt
            self.basic_block = row.basic_block
            self.end_sequence = row.end_sequence
            self.prologue_end = row.prologue_end
            self.epilogue_begin = row.epilogue_begin

    def path(self):
        assert self.lnp is not None
        if self.file == 0:
            assert self.lnp.cu is not None
            return self.lnp.cu.name()
        else:
            filename = self.lnp.file_names[self.file - 1]
            if filename.directory_index > 0:
                directory = self.lnp.include_directories[filename.directory_index - 1]
                return directory + '/' + filename.name
            else:
                return filename.name


cdef class LineNumberFilename:
    cdef public str name
    cdef public uint64_t directory_index
    cdef public uint64_t mtime
    cdef public uint64_t file_size


cdef read_uleb128(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    cdef int shift = 0
    cdef uint8_t byte

    ret[0] = 0
    while True:
        read_u8(buffer, offset, &byte)
        if shift == 63 and byte > 1:
            raise OverflowError('ULEB128 overflowed unsigned 64-bit integer')
        ret[0] |= <uint64_t>(byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break


cdef read_sleb128(Py_buffer *buffer, Py_ssize_t *offset, int64_t *ret):
    cdef int shift = 0
    cdef uint8_t byte

    ret[0] = 0
    while True:
        read_u8(buffer, offset, &byte)
        if shift == 63 and byte != 0 and byte != 0x7f:
            raise OverflowError('ULEB128 overflowed unsigned 64-bit integer')
        ret[0] |= <int64_t>(byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if shift < 64 and (byte & 0x40):
        ret[0] |= -(<int64_t>1 << shift)


def parse_uleb128(s, Py_ssize_t offset):
    cdef uint64_t ret
    cdef Py_buffer buffer
    PyObject_GetBuffer(s, &buffer, PyBUF_SIMPLE)
    try:
        read_uleb128(&buffer, &offset, &ret)
        return ret, offset
    finally:
        PyBuffer_Release(&buffer)


def parse_sleb128(s, Py_ssize_t offset):
    cdef int64_t ret
    cdef Py_buffer buffer
    PyObject_GetBuffer(s, &buffer, PyBUF_SIMPLE)
    try:
        read_sleb128(&buffer, &offset, &ret)
        return ret, offset
    finally:
        PyBuffer_Release(&buffer)


cdef int realloc_abbrev_decls(AbbrevDecl **abbrev_decls, Py_ssize_t n) except -1:
    if n > PY_SSIZE_T_MAX / <Py_ssize_t>sizeof(AbbrevDecl):
        raise MemoryError()

    cdef AbbrevDecl *tmp = <AbbrevDecl *>PyMem_Realloc(abbrev_decls[0],
                                                       n * sizeof(AbbrevDecl))
    if tmp == NULL:
        raise MemoryError()

    abbrev_decls[0] = tmp
    return 0


cdef int realloc_attrib_specs(AttribSpec **attrib_specs, Py_ssize_t n) except -1:
    if n > PY_SSIZE_T_MAX / <Py_ssize_t>sizeof(AttribSpec):
        raise MemoryError()

    cdef AttribSpec *tmp = <AttribSpec *>PyMem_Realloc(attrib_specs[0],
                                                       n * sizeof(AttribSpec))
    if tmp == NULL:
        raise MemoryError()

    attrib_specs[0] = tmp
    return 0


cdef int parse_abbrev_decl(Py_buffer *buffer, Py_ssize_t *offset,
                           AbbrevTable *abbrev_table,
                           uint64_t *decls_capacity) except -1:
    cdef uint64_t code

    try:
        read_uleb128(buffer, offset, &code)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration code is truncated')
    if code == 0:
        return 0
    if code != abbrev_table.num_decls + 1:
        raise NotImplementedError('abbreviation table is not sequential')

    if abbrev_table.num_decls >= decls_capacity[0]:
        decls_capacity[0] *= 2
        realloc_abbrev_decls(&abbrev_table.decls, decls_capacity[0])

    cdef AbbrevDecl *decl = &abbrev_table.decls[abbrev_table.num_decls]
    decl.attribs = NULL
    decl.num_attribs = 0
    abbrev_table.num_decls += 1

    try:
        read_uleb128(buffer, offset, &decl.tag)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration tag is truncated')
    cdef uint8_t children
    try:
        read_u8(buffer, offset, &children)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration children flag is truncated')
    decl.children = children != DW_CHILDREN_no

    cdef uint64_t attribs_capacity = 1  # XXX: is this a good first guess?
    realloc_attrib_specs(&decl.attribs, attribs_capacity)

    cdef uint64_t name, form
    while True:
        try:
            read_uleb128(buffer, offset, &name)
        except EOFError:
            raise DwarfFormatError('abbreviation specification name is truncated')
        try:
            read_uleb128(buffer, offset, &form)
        except EOFError:
            raise DwarfFormatError('abbreviation specification form is truncated')
        if name == 0 and form == 0:
            break

        if decl.num_attribs >= attribs_capacity:
            attribs_capacity *= 2
            realloc_attrib_specs(&decl.attribs, attribs_capacity)

        decl.attribs[decl.num_attribs].name = name
        decl.attribs[decl.num_attribs].form = form
        decl.num_attribs += 1

    realloc_attrib_specs(&decl.attribs, decl.num_attribs)
    return 1


cdef int parse_abbrev_table(Py_buffer *buffer, Py_ssize_t *offset,
                            AbbrevTable *abbrev_table) except -1:
    cdef uint64_t decls_capacity = 1  # XXX: is this a good first guess?

    abbrev_table.decls = NULL
    abbrev_table.num_decls = 0
    realloc_abbrev_decls(&abbrev_table.decls, decls_capacity)

    while parse_abbrev_decl(buffer, offset, abbrev_table, &decls_capacity):
        pass
    realloc_abbrev_decls(&abbrev_table.decls, abbrev_table.num_decls)
    return 0


cdef ArangeTable parse_arange_table(Py_buffer *buffer, Py_ssize_t *offset):
    cdef ArangeTable art = ArangeTable.__new__(ArangeTable)
    art.offset = offset[0]

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    art.is_64_bit = tmp == 0xffffffffUL
    if art.is_64_bit:
        read_u64(buffer, offset, &art.unit_length)
    else:
        art.unit_length = tmp

    read_u16(buffer, offset, &art.version)
    if art.version != 2:
        raise DwarfFormatError(f'unknown arange table version {art.version}')

    if art.is_64_bit:
        read_u64(buffer, offset, &art.debug_info_offset)
    else:
        read_u32_into_u64(buffer, offset, &art.debug_info_offset)

    read_u8(buffer, offset, &art.address_size)
    read_u8(buffer, offset, &art.segment_size)

    if art.segment_size != 4 and art.segment_size != 8 and art.segment_size != 0:
        raise DwarfFormatError(f'unsupported segment size {art.segment_size}')
    if art.address_size != 4 and art.address_size != 8:
        raise DwarfFormatError(f'unsupported address size {art.address_size}')

    cdef Py_ssize_t align = art.segment_size + 2 * art.address_size
    if offset[0] % align:
        offset[0] += align - (offset[0] % align)

    cdef uint64_t segment, address, length_
    art.table = []
    while True:
        if art.segment_size == 4:
            read_u32_into_u64(buffer, offset, &segment)
        elif art.segment_size == 8:
            read_u64(buffer, offset, &segment)
        else:  # art.segment_size == 0
            segment = 0

        if art.address_size == 4:
            read_u32_into_u64(buffer, offset, &address)
            read_u32_into_u64(buffer, offset, &length_)
        else:  # art.address_size == 8
            read_u64(buffer, offset, &address)
            read_u64(buffer, offset, &length_)

        if segment == 0 and address == 0 and length_ == 0:
            break

        art.table.append(AddressRange.__new__(AddressRange, segment, address, length_))

    return art


cdef CompilationUnitHeader parse_compilation_unit_header(Py_buffer *buffer,
                                                         Py_ssize_t *offset,
                                                         DwarfFile dwarf_file):
    cdef CompilationUnitHeader cu = CompilationUnitHeader.__new__(CompilationUnitHeader)
    cu.dwarf_file = dwarf_file
    cu.offset = offset[0]

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    cu.is_64_bit = tmp == 0xffffffffUL
    if cu.is_64_bit:
        read_u64(buffer, offset, &cu.unit_length)
    else:
        cu.unit_length = tmp

    read_u16(buffer, offset, &cu.version)
    if cu.version != 2 and cu.version != 3 and cu.version != 4:
        raise DwarfFormatError(f'unknown CU version {cu.version}')

    if cu.is_64_bit:
        read_u64(buffer, offset, &cu.debug_abbrev_offset)
    else:
        read_u32_into_u64(buffer, offset, &cu.debug_abbrev_offset)

    read_u8(buffer, offset, &cu.address_size)

    return cu


cdef parse_die_attrib(Py_buffer *buffer, Py_ssize_t *offset, DieAttrib *attrib,
                      uint8_t address_size, bint is_64_bit):
    cdef uint64_t tmp

    # address
    if attrib.form == DW_FORM_addr:
        if address_size == 4:
            read_u32_into_u64(buffer, offset, &attrib.value.u)
        elif address_size == 8:
            read_u64(buffer, offset, &attrib.value.u)
        else:
            raise DwarfFormatError(f'unsupported address size {address_size}')
    elif (attrib.form == DW_FORM_block1 or  # block
          attrib.form == DW_FORM_block2 or
          attrib.form == DW_FORM_block4 or
          attrib.form == DW_FORM_exprloc):  # exprloc
        if attrib.form == DW_FORM_block1:
            read_u8_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_block2:
            read_u16_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_block4:
            read_u32_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_exprloc:
            read_uleb128(buffer, offset, &tmp)
            if tmp > <uint64_t>PY_SSIZE_T_MAX:
                raise DwarfFormatError('attribute length too big')
            attrib.value.ptr.length = tmp
        read_check_bounds(buffer, offset[0], attrib.value.ptr.length)
        attrib.value.ptr.offset = offset[0]
        offset[0] += attrib.value.ptr.length
    # constant
    elif attrib.form == DW_FORM_data1:
        read_buffer(buffer, offset, &attrib.value.data, 1)
    elif attrib.form == DW_FORM_data2:
        read_buffer(buffer, offset, &attrib.value.data, 2)
    elif attrib.form == DW_FORM_data4:
        read_buffer(buffer, offset, &attrib.value.data, 4)
    elif attrib.form == DW_FORM_data8:
        read_buffer(buffer, offset, &attrib.value.data, 8)
    elif attrib.form == DW_FORM_sdata:
        read_sleb128(buffer, offset, &attrib.value.s)
    elif (attrib.form == DW_FORM_udata or     # constant
          attrib.form == DW_FORM_ref_udata):  # reference
        read_uleb128(buffer, offset, &attrib.value.u)
    elif (attrib.form == DW_FORM_ref_addr or    # reference
          attrib.form == DW_FORM_sec_offset or  # lineptr, loclistptr, macptr, rangelistptr
          attrib.form == DW_FORM_strp):         # string
        if is_64_bit:
            read_u64(buffer, offset, &attrib.value.u)
        else:
            read_u32_into_u64(buffer, offset, &attrib.value.u)
    # string
    elif attrib.form == DW_FORM_string:
        attrib.value.ptr.offset = offset[0]
        attrib.value.ptr.length = read_strlen(buffer, offset)
    # flag
    elif attrib.form == DW_FORM_flag_present:
        attrib.value.u = 1
    elif (attrib.form == DW_FORM_flag or  # flag
          attrib.form == DW_FORM_ref1):   # reference
        read_u8_into_u64(buffer, offset, &attrib.value.u)
    # reference
    elif attrib.form == DW_FORM_ref2:
        read_u16_into_u64(buffer, offset, &attrib.value.u)
    elif attrib.form == DW_FORM_ref4:
        read_u32_into_u64(buffer, offset, &attrib.value.u)
    elif (attrib.form == DW_FORM_ref8 or attrib.form == DW_FORM_ref_sig8):
        read_u64(buffer, offset, &attrib.value.u)
    elif DW_FORM_indirect:
        raise DwarfFormatError('DW_FORM_indirect is not supported')
    else:
        raise DwarfFormatError(f'unknown form 0x{attrib.form:x}')


cdef list no_children = []


cdef list parse_die_siblings(Py_buffer *buffer, Py_ssize_t *offset,
                             CompilationUnitHeader cu):
    cdef list children = []
    cdef Die child

    while True:
        child = parse_die(buffer, offset, cu, True)
        if child is None:
            break
        children.append(child)

    return children


cdef Die parse_die(Py_buffer *buffer, Py_ssize_t *offset,
                   CompilationUnitHeader cu, bint jump_to_sibling):
    cdef Die die = Die.__new__(Die)
    die.cu = cu
    die.offset = offset[0]

    cdef uint64_t code
    read_uleb128(buffer, offset, &code)
    if code == 0:
        return None

    cdef AbbrevDecl *decl = cu.abbrev_decl(code)
    if decl == NULL:
        raise DwarfFormatError(f'unknown abbreviation code {code}')

    die.tag = decl.tag
    die.attribs = <DieAttrib *>PyMem_Calloc(decl.num_attribs, sizeof(DieAttrib))
    if die.attribs == NULL:
        raise MemoryError()
    die.num_attribs = decl.num_attribs

    cdef uint64_t sibling_form = 0
    cdef Py_ssize_t sibling = 0
    for i in range(die.num_attribs):
        die.attribs[i].name = decl.attribs[i].name
        die.attribs[i].form = decl.attribs[i].form
        parse_die_attrib(buffer, offset, &die.attribs[i], cu.address_size,
                         cu.is_64_bit)
        if die.attribs[i].name == DW_AT_sibling:
            sibling_form = die.attribs[i].form
            sibling = die.attribs[i].value.u

    die.length = offset[0] - die.offset

    if not decl.children:
        die._children = no_children
    elif jump_to_sibling and sibling == 0:
        die._children = parse_die_siblings(buffer, offset, cu)
    elif jump_to_sibling:
        if sibling_form == DW_FORM_ref_addr:
            offset[0] = sibling
        else:
            offset[0] = cu.offset + sibling

    return die


cdef LineNumberProgram parse_line_number_program(Py_buffer *buffer,
                                                 Py_ssize_t *offset,
                                                 CompilationUnitHeader cu):
    cdef LineNumberProgram lnp = LineNumberProgram.__new__(LineNumberProgram)
    lnp.cu = cu
    lnp.offset = offset[0]

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    lnp.is_64_bit = tmp == 0xffffffffUL
    if lnp.is_64_bit:
        read_u64(buffer, offset, &lnp.unit_length)
    else:
        lnp.unit_length = tmp

    read_u16(buffer, offset, &lnp.version)
    if lnp.version != 2 and lnp.version != 3 and lnp.version != 4:
        raise DwarfFormatError(f'unknown line number program version {lnp.version}')

    if lnp.is_64_bit:
        read_u64(buffer, offset, &lnp.header_length)
    else:
        read_u32_into_u64(buffer, offset, &lnp.header_length)

    read_u8(buffer, offset, &lnp.minimum_instruction_length)
    if lnp.version >= 4:
        read_u8(buffer, offset, &lnp.maximum_operations_per_instruction)
    else:
        lnp.maximum_operations_per_instruction = 1
    cdef uint8_t default_is_stmt
    read_u8(buffer, offset, &default_is_stmt)
    lnp.default_is_stmt = default_is_stmt
    read_s8(buffer, offset, &lnp.line_base)
    read_u8(buffer, offset, &lnp.line_range)
    read_u8(buffer, offset, &lnp.opcode_base)

    if lnp.opcode_base == 0:
        raise DwarfFormatError('opcode_base is 0')
    lnp.standard_opcode_lengths = []
    cdef uint8_t opcode_length
    for i in range(lnp.opcode_base - 1):
        read_u8(buffer, offset, &opcode_length)
        lnp.standard_opcode_lengths.append(opcode_length)

    lnp.include_directories = []
    cdef str directory
    while True:
        directory = read_str(buffer, offset)
        if not directory:
            break
        lnp.include_directories.append(directory)

    lnp.file_names = []
    cdef str name
    cdef LineNumberFilename file
    while True:
        name = read_str(buffer, offset)
        if not name:
            break
        file = LineNumberFilename.__new__(LineNumberFilename)
        file.name = name
        read_uleb128(buffer, offset, &file.directory_index)
        read_uleb128(buffer, offset, &file.mtime)
        read_uleb128(buffer, offset, &file.file_size)
        lnp.file_names.append(file)

    return lnp


cdef struct DieHashEntry:
    DieHashEntry *next
    char *name
    void *cu
    uint64_t tag
    uint64_t offset


# DJBX33A hash function
cdef unsigned long name_hash(char *name):
    cdef unsigned long hash = 5381
    cdef Py_ssize_t i = 0

    while name[i]:
        hash = ((hash << 5) + hash) + <unsigned char>name[i]
        i += 1
    return hash


cdef class DwarfIndex:
    cdef DieHashEntry **die_hash
    cdef unsigned long mask
    cdef set cus
    cdef public object address_size

    def __cinit__(self, shift=17):
        self.cus = set()
        if shift >= 31:
            raise ValueError('shift is too large')
        self.die_hash = <DieHashEntry **>PyMem_RawCalloc(1 << shift, sizeof(DieHashEntry *))
        if self.die_hash == NULL:
            raise MemoryError()
        self.mask = (1 << shift) - 1
        self.address_size = None

    def __dealloc__(self):
        cdef DieHashEntry *entry
        cdef DieHashEntry *next

        for i in range(self.mask + 1):
            entry = self.die_hash[i]
            while entry:
                next = entry.next
                PyMem_RawFree(entry)
                entry = next
        PyMem_RawFree(self.die_hash)

    cdef add_die_hash_entry(self, Py_buffer *buffer, uint64_t die_offset,
                            uint64_t tag, char *name,
                            CompilationUnitHeader cu):
        cdef unsigned long hash
        cdef DieHashEntry **bucket
        cdef DieHashEntry *entry

        hash = name_hash(name)
        bucket = &self.die_hash[hash & self.mask]
        entry = bucket[0]
        while entry:
            if entry.tag == tag and strcmp(entry.name, name) == 0:
                return
            entry = entry.next

        entry = <DieHashEntry *>PyMem_RawMalloc(sizeof(DieHashEntry))
        if entry == NULL:
            raise MemoryError()
        entry.next = bucket[0]
        entry.name = name
        entry.cu = <void *>cu
        entry.tag = tag
        entry.offset = die_offset
        bucket[0] = entry

    cdef int index_die(self, Py_buffer *buffer, Py_buffer *debug_str_buffer,
                       Py_ssize_t *offset, CompilationUnitHeader cu,
                       int depth) except -1:
        cdef Py_ssize_t die_offset = offset[0] - cu.offset

        cdef uint64_t code
        read_uleb128(buffer, offset, &code)
        if code == 0:
            return 0

        cdef AbbrevDecl *decl = cu.abbrev_decl(code)
        if decl == NULL:
            raise DwarfFormatError(f'unknown abbreviation code {code}')

        cdef DieAttrib attrib
        cdef char *name = NULL
        cdef uint64_t sibling_form = 0
        cdef Py_ssize_t sibling = 0
        cdef bint declaration = 0
        for i in range(decl.num_attribs):
            attrib.name = decl.attribs[i].name
            attrib.form = decl.attribs[i].form
            parse_die_attrib(buffer, offset, &attrib, cu.address_size,
                             cu.is_64_bit)
            if attrib.name == DW_AT_sibling:
                sibling_form = attrib.form
                sibling = attrib.value.u
            elif attrib.name == DW_AT_name:
                if attrib.form == DW_FORM_strp:
                    name = <char *>debug_str_buffer.buf + attrib.value.u
                elif attrib.form == DW_FORM_string:
                    name = <char *>buffer.buf + attrib.value.ptr.offset
            elif attrib.name == DW_AT_declaration:
                if attrib.form == DW_FORM_flag or attrib.form == DW_FORM.flag_present:
                    declaration = attrib.value.u
        if (depth == 1 and name != NULL and
            (decl.tag == DW_TAG_variable or
             (tag_is_type(decl.tag) and not declaration))):
            self.add_die_hash_entry(buffer, die_offset, decl.tag, name, cu)

        if decl.children:
            if depth == 0 or sibling == 0:
                while self.index_die(buffer, debug_str_buffer, offset, cu,
                                     depth + 1):
                    pass
            else:
                if sibling_form == DW_FORM_ref_addr:
                    offset[0] = sibling
                else:
                    offset[0] = cu.offset + sibling

        return 1

    def index_cu(self, CompilationUnitHeader cu):
        if self.address_size is None:
            self.address_size = cu.address_size
        else:
            assert cu.address_size == self.address_size
        self.cus.add(cu)

        cdef Py_buffer buffer
        cdef Py_buffer debug_str_buffer
        cdef Py_ssize_t offset = cu.die_offset()

        cu.dwarf_file.get_section_buffer('.debug_info', &buffer)
        try:
            cu.dwarf_file.get_section_buffer('.debug_str', &debug_str_buffer)
            try:
                self.index_die(&buffer, &debug_str_buffer, &offset, cu, 0)
            finally:
                PyBuffer_Release(&debug_str_buffer)
        finally:
            PyBuffer_Release(&buffer)

    def find(self, str name_obj, uint64_t tag):
        cdef bytes name_bytes = name_obj.encode('utf-8')
        cdef char *name = name_bytes
        cdef unsigned long hash = name_hash(name)
        cdef DieHashEntry *entry

        entry = self.die_hash[hash & self.mask]
        while entry:
            if entry.tag == tag and strcmp(entry.name, name) == 0:
                return (<CompilationUnitHeader>entry.cu).die(entry.offset)
            entry = entry.next
        raise KeyError()

    def find_variable(self, str name_obj):
        return self.find(name_obj, DW_TAG_variable)
