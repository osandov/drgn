# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

import tempfile

from _drgn_util.elf import ET, PT, SHF, SHT, STB, STT
from drgn import (
    Object,
    ObjectNotFoundError,
    PlatformFlags,
    Program,
    Qualifiers,
    TypeEnumerator,
    TypeMember,
    TypeParameter,
    host_platform,
)
from tests import MOCK_BIG_ENDIAN_PLATFORM, TestCase, skip_unless_have_libbpf
from tests.btf import (
    BtfEnum,
    btf_array,
    btf_compile,
    btf_const,
    btf_datasec,
    btf_enum,
    btf_enum64,
    btf_float,
    btf_func,
    btf_func_proto,
    btf_fwd,
    btf_int,
    btf_member,
    btf_param,
    btf_ptr,
    btf_restrict,
    btf_struct,
    btf_typedef,
    btf_union,
    btf_var,
    btf_var_secinfo,
    btf_volatile,
)
from tests.elfwriter import ElfSection, ElfSymbol, create_elf_file


def btf_program(types, *, little_endian=True, platform=host_platform):
    # libbpf infers the pointer size by searching for the "unsigned long" type
    # size (among others). Include a definition so we get valid pointer sizes
    # matching the target platform.
    if not any(t.name == "unsigned long" for t in types):
        ptr_size = 64 if platform.flags & PlatformFlags.IS_64_BIT else 32
        types.append(btf_int("unsigned long", bits=ptr_size))
    data = btf_compile(types, little_endian=little_endian).data
    prog = Program(platform=platform)
    module = prog.main_module("btf", create=True)
    module.load_btf(data=data)
    return prog


def btf_test_type(*types, **kwargs):
    prog = btf_program([*types, btf_typedef("TEST", len(types))], **kwargs)
    return prog, prog.type("TEST").type


@skip_unless_have_libbpf
class TestBtfTypeFinder(TestCase):
    def test_big_endian(self):
        # A basic correctness check: can big-endian platform read a big-endian
        # encoded BTF data and load a basic int type?
        # Note that BTF has no mechanism to encode an integer type with some
        # other endianness, so this is not about creating a big-endian in on
        # a little-endian platform.
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True),
            little_endian=False,
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertIdentical(type_, prog.int_type("int", 4, True, "big"))

    def test_int(self):
        prog, type_ = btf_test_type(btf_int("u8", bits=8))
        self.assertIdentical(type_, prog.int_type("u8", 1, False))

    def test_signed_int(self):
        prog, type_ = btf_test_type(btf_int("s16", bits=16, signed=True))
        self.assertIdentical(type_, prog.int_type("s16", 2, True))

    def test_bool(self):
        prog, type_ = btf_test_type(btf_int("_Bool", bits=8, bool=True))
        self.assertIdentical(type_, prog.bool_type("_Bool", 1, None))

    def test_char(self):
        # The char flag actually does nothing. See below.
        prog, type_ = btf_test_type(btf_int("char", bits=8, char=True))
        self.assertIdentical(type_, prog.int_type("char", 1, False))

    def test_signed_char(self):
        # According to the BTF documentation, "At most one encoding can be
        # specified for the int type", which would indicate that it is not legal
        # to represent a signed char with both flags enabled. In practice, when
        # representing a signed char, GCC only uses the "signed" flag. The char
        # flag doesn't actually do anything except enable pretty-printing for
        # some BTF consumers.
        prog, type_ = btf_test_type(btf_int("char", bits=8, signed=True))
        self.assertIdentical(type_, prog.int_type("char", 1, True))

    def test_int_offset_bits(self):
        # The offset and bits encoding of an integer type are ignored, since
        # they only apply to a compound type member. The size field of btf_type
        # is the official byte size of the integer, regardless of the bit size.
        #
        # In practice, an integer with non-standard bits & offset would only be
        # referenced by a member anyway, not a typedef.
        prog, type_ = btf_test_type(btf_int("oddball", bits=17, offset=2, size=4))
        self.assertIdentical(type_, prog.int_type("oddball", 4, False))

    def test_qualifiers(self):
        for combination in range(8):
            with self.subTest(combination):
                types = [btf_int("int", bits=32, signed=True)]
                quals = Qualifiers.NONE
                if combination & 1:
                    types.append(btf_const(len(types)))
                    quals |= Qualifiers.CONST
                if combination & 2:
                    types.append(btf_restrict(len(types)))
                    quals |= Qualifiers.RESTRICT
                if combination & 4:
                    types.append(btf_volatile(len(types)))
                    quals |= Qualifiers.VOLATILE
                prog, type_ = btf_test_type(*types)
                self.assertIdentical(
                    type_, prog.int_type("int", 4, True, qualifiers=quals)
                )

    def test_void_pointer(self):
        prog, type_ = btf_test_type(btf_ptr(0))
        self.assertIdentical(type_, prog.pointer_type(prog.void_type()))

    def test_qualified_void(self):
        prog, type_ = btf_test_type(btf_const(0))
        self.assertIdentical(type_, prog.void_type(qualifiers=Qualifiers.CONST))

    def test_pointer(self):
        prog, type_ = btf_test_type(btf_int("int", bits=32, signed=True), btf_ptr(1))
        self.assertIdentical(type_, prog.pointer_type(prog.int_type("int", 4, True)))

    def test_float(self):
        prog, type_ = btf_test_type(btf_float("float", 4))
        self.assertIdentical(type_, prog.float_type("float", 4))

    def test_array(self):
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True), btf_array(1, 1, 3)
        )
        self.assertIdentical(type_, prog.array_type(prog.int_type("int", 4, True), 3))

    def test_multidimensional_array(self):
        # BTF is fully capable of representing multi-dimensional arrays.
        # However, according to the BTF documentation: "Currently for the
        # kernel, both pahole and llvm collapse multidimensional array into
        # one-dimensional array, e.g., for a[5][6], the btf_array.nelems is
        # equal to 30."
        # HOWEVER, GCC does not perform this flattening. So it's important to
        # verify that we correctly handle multidimensional arrays. Hopefully
        # correctly encoding arrays will become the norm for LLVM & pahole too.
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True),
            btf_array(1, 1, 6),
            btf_array(2, 1, 5),
        )
        self.assertIdentical(
            type_,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 6), 5),
        )

    def test_zero_length_array_not_incomplete(self):
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True), btf_array(1, 1, 0)
        )
        # BTF does not provide a mechanism to distinguish between a zero-length
        # array and an incomplete array type. Zero-length arrays are a bit more
        # flexible (they support sizeof) so drgn always encodes as zero-length,
        # not incomplete.
        self.assertIdentical(type_, prog.array_type(prog.int_type("int", 4, True), 0))

    def test_simple_struct_members(self):
        prog = btf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_struct(
                    "point",
                    8,
                    [
                        btf_member("x", 1, 0),
                        btf_member("y", 1, 32),
                    ],
                ),
            ]
        )
        int_type = prog.int_type("int", 4, True)
        self.assertIdentical(
            prog.type("struct point"),
            prog.struct_type(
                "point",
                8,
                [
                    TypeMember(int_type, "x", 0),
                    TypeMember(int_type, "y", 32),
                ],
            ),
        )

    def test_struct_bitfield_legacy(self):
        # With the legacy approach, compilers are "supposed" to encode the
        # byte-aligned offset in the structure and then bit offsets can be
        # placed into the int encoding. It's important that we must traverse the
        # type graph and skip typedefs & qualifiers in order to arrive at the
        # base type.
        prog = btf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_int("unsigned int", size=4, bits=1, offset=0),
                btf_int("unsigned int", size=4, bits=1, offset=1),
                btf_typedef("foo_flag_t", 3),
                btf_const(4),
                btf_struct(
                    "structure",
                    8,
                    [
                        btf_member("number", 1, 0),
                        btf_member("flag1", 2, 32),
                        btf_member("flag2", 5, 32),
                    ],
                ),
            ]
        )
        int_type = prog.int_type("int", 4, True)
        uint_type = prog.int_type("unsigned int", 4, False)
        foo_t = prog.typedef_type("foo_flag_t", uint_type, qualifiers=Qualifiers.CONST)
        self.assertIdentical(
            prog.type("struct structure"),
            prog.struct_type(
                "structure",
                8,
                [
                    TypeMember(int_type, "number", 0),
                    TypeMember(Object(prog, uint_type, bit_field_size=1), "flag1", 32),
                    TypeMember(Object(prog, foo_t, bit_field_size=1), "flag2", 33),
                ],
            ),
        )

    def test_struct_bitfield_kflag(self):
        # With the flag approach, all bitfield size and offset information is
        # part of the member itself, not in the int encoding. This is the only
        # way it is possible to specify bitfields with enums.
        prog = btf_program(
            [
                btf_int("int", bits=32, signed=True),
                # bits and offset here are red herrings! They should go unused.
                btf_int("unsigned int", size=4, bits=5, offset=9),
                btf_enum("myflags", size=4, values=[BtfEnum("FLAG_A", 1)]),
                btf_struct(
                    "structure",
                    8,
                    [
                        btf_member("number", 1, 0),
                        btf_member("flag1", 2, 32, bitfield_size=1),
                        btf_member("flag2", 2, 33, bitfield_size=1),
                        btf_member("flag3", 3, 34, bitfield_size=1),
                    ],
                ),
            ]
        )
        int_type = prog.int_type("int", 4, True)
        uint_type = prog.int_type("unsigned int", 4, False)
        enum_type = prog.enum_type(
            "myflags",
            prog.int_type("u32", 4, False),
            [TypeEnumerator("FLAG_A", 1)],
        )
        self.assertIdentical(
            prog.type("struct structure"),
            prog.struct_type(
                "structure",
                8,
                [
                    TypeMember(int_type, "number", 0),
                    TypeMember(Object(prog, uint_type, bit_field_size=1), "flag1", 32),
                    TypeMember(Object(prog, uint_type, bit_field_size=1), "flag2", 33),
                    TypeMember(Object(prog, enum_type, bit_field_size=1), "flag3", 34),
                ],
            ),
        )

    def test_empty_struct_and_union(self):
        prog = btf_program([btf_struct("empty", 0), btf_union("u", 0)])
        self.assertIdentical(
            prog.type("struct empty"), prog.struct_type("empty", 0, ())
        )
        self.assertIdentical(prog.type("union u"), prog.union_type("u", 0, ()))

    def test_anonymous_struct_union(self):
        # struct x {
        #     int kind;
        #     union {
        #         struct {
        #             int value_a;
        #             int value_b;
        #         };
        #         void *ptr;
        #     };
        # };
        prog = btf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_ptr(0),
                btf_struct(
                    None,
                    8,
                    [
                        btf_member("value_a", 1, 0),
                        btf_member("value_b", 1, 32),
                    ],
                ),
                btf_union(
                    None,
                    8,
                    [
                        btf_member(None, 3, 0),
                        btf_member("ptr", 2, 0),
                    ],
                ),
                btf_struct(
                    "x",
                    16,
                    [
                        btf_member("kind", 1, 0),
                        btf_member(None, 4, 64),
                    ],
                ),
            ]
        )
        int_type = prog.int_type("int", 4, True)
        self.assertIdentical(
            prog.type("struct x"),
            prog.struct_type(
                "x",
                16,
                [
                    TypeMember(int_type, "kind", 0),
                    TypeMember(
                        prog.union_type(
                            None,
                            8,
                            [
                                TypeMember(
                                    prog.struct_type(
                                        None,
                                        8,
                                        [
                                            TypeMember(int_type, "value_a", 0),
                                            TypeMember(int_type, "value_b", 32),
                                        ],
                                    ),
                                    None,
                                    0,
                                ),
                                TypeMember(
                                    prog.pointer_type(prog.void_type()),
                                    "ptr",
                                    0,
                                ),
                            ],
                        ),
                        None,
                        64,
                    ),
                ],
            ),
        )

    def test_forward_declarations(self):
        prog, type_ = btf_test_type(btf_fwd("s"))
        self.assertIdentical(type_, prog.struct_type("s"))
        prog, type_ = btf_test_type(btf_fwd("u", is_union=True))
        self.assertIdentical(type_, prog.union_type("u"))

    def test_enum(self):
        prog = btf_program(
            [
                btf_enum(
                    "color",
                    4,
                    [
                        BtfEnum("RED", 0),
                        BtfEnum("ALL", -1),
                    ],
                )
            ]
        )
        type_ = prog.enum_type(
            "color",
            prog.int_type("u32", 4, False),
            (TypeEnumerator("RED", 0), TypeEnumerator("ALL", 2**32 - 1)),
        )
        self.assertIdentical(prog.type("enum color"), type_)
        self.assertIdentical(prog.constant("ALL"), Object(prog, type_, value=2**32 - 1))

    def test_signed_enum64(self):
        prog = btf_program(
            [
                btf_enum64(
                    "number",
                    8,
                    [BtfEnum("NEGATIVE", -1)],
                    signed=True,
                )
            ]
        )
        self.assertIdentical(
            prog.type("enum number"),
            prog.enum_type(
                "number",
                prog.int_type("s64", 8, True),
                (TypeEnumerator("NEGATIVE", -1),),
            ),
        )

    def test_incomplete_enum(self):
        prog = btf_program([btf_enum("incomplete", 4)])
        self.assertIdentical(prog.type("enum incomplete"), prog.enum_type("incomplete"))

    def test_function_type(self):
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True),
            btf_ptr(1),
            btf_func_proto(1, [btf_param("argc", 1), btf_param("argv", 2)]),
        )
        self.assertIdentical(
            type_,
            prog.function_type(
                prog.int_type("int", 4, True),
                (
                    TypeParameter(prog.int_type("int", 4, True), "argc"),
                    TypeParameter(
                        prog.pointer_type(prog.int_type("int", 4, True)), "argv"
                    ),
                ),
                False,
            ),
        )

    def test_variadic_function_type(self):
        prog, type_ = btf_test_type(
            btf_int("int", bits=32, signed=True),
            btf_func_proto(1, [btf_param("arg", 1), btf_param(None, 0)]),
        )
        self.assertIdentical(
            type_,
            prog.function_type(
                prog.int_type("int", 4, True),
                (TypeParameter(prog.int_type("int", 4, True), "arg"),),
                True,
            ),
        )


@skip_unless_have_libbpf
class TestSplitBtf(TestCase):

    def test_main_module_base(self):
        # Verifies that split BTF can be loaded using the main module as base.
        # Also verifies that this is NOT the default for userspace programs.
        for main_mod_base, is_split in ((True, True), (False, False), (None, False)):
            with self.subTest(main_mod_base=main_mod_base, is_split=is_split):
                prog = Program(platform=host_platform)
                main = prog.main_module("btf", create=True)
                main_btf = btf_compile(
                    [
                        btf_int("int", bits=32, signed=True),
                    ]
                )
                main.load_btf(data=main_btf.data)
                child = prog.extra_module("child", create=True)
                child_btf = btf_compile(
                    [
                        btf_int("short", bits=16, signed=True),
                        # If child_btf is loaded as split, this will point at
                        # the int. If child_btf is loaded indpendently, it will
                        # point at the short.
                        btf_typedef("TEST", 1),
                    ],
                    base=main_btf if main_mod_base else None,
                )
                child.load_btf(data=child_btf.data, main_module_base=main_mod_base)

                if is_split:
                    self.assertIdentical(
                        prog.type("TEST").type,
                        prog.int_type("int", 4, True),
                    )
                else:
                    self.assertIdentical(
                        prog.type("TEST").type,
                        prog.int_type("short", 2, True),
                    )

    def test_datasec_variable_type_id_collision(self):
        prog = Program(platform=host_platform)
        main = prog.main_module("btf", create=True)
        main_btf = btf_compile([btf_int("int", bits=32, signed=True)])
        main.load_btf(data=main_btf.data)

        # Split BTF type IDs are only unique within each module. Give both
        # modules the same-named variable at the same type ID to verify that
        # loading the second module does not update the first module's index
        # entry.
        variable_type_id = main_btf.nr_types + 1
        module_btf = btf_compile(
            [
                btf_var("counter", 1),
                btf_datasec(
                    ".data",
                    4,
                    [btf_var_secinfo(variable_type_id, 0, 4)],
                ),
            ],
            base=main_btf,
        )

        first = prog.relocatable_module("first", 0x1000, create=True)
        first.section_addresses[".data"] = 0x1000
        first.load_btf(data=module_btf.data, main_module_base=True)
        self.assertIdentical(
            prog.variable("counter"),
            Object(prog, prog.int_type("int", 4, True), address=0x1000),
        )

        second = prog.relocatable_module("second", 0x2000, create=True)
        second.section_addresses[".data"] = 0x2000
        second.load_btf(data=module_btf.data, main_module_base=True)
        self.assertIdentical(
            prog.variable("counter"),
            Object(prog, prog.int_type("int", 4, True), address=0x1000),
        )


def btf_elf_program(types, symbols):
    start = min(symbol.value for symbol in symbols) & ~7
    end = max(symbol.value + max(symbol.size, 1) for symbol in symbols)
    end = (end + 7) & ~7
    compiled_btf = btf_compile(types).data
    data = create_elf_file(
        ET.EXEC,
        [
            ElfSection(
                name=".data",
                sh_type=SHT.PROGBITS,
                sh_flags=SHF.ALLOC,
                p_type=PT.LOAD,
                vaddr=start,
                memsz=end - start,
                data=bytes(end - start),
            ),
            ElfSection(
                name=".BTF",
                sh_type=SHT.PROGBITS,
                sh_flags=0,
                memsz=len(compiled_btf),
                data=compiled_btf,
            ),
        ],
        symbols,
    )
    prog = Program(platform=host_platform)
    with tempfile.NamedTemporaryFile() as f:
        f.write(data)
        f.flush()
        module = prog.extra_module(f.name, 1, create=True)
        module.address_range = (start, end)
        module.try_file(f.name, force=True)
        module.load_btf()
    return prog


@skip_unless_have_libbpf
class TestBtfObjectFinder(TestCase):
    def test_function(self):
        # Function lookup always works based on symbol finder. There is no
        # DATASEC equivalent for functions. It should work the same for either
        # object finder.
        prog = btf_elf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_func_proto(1),
                btf_func("main", 2),
            ],
            [ElfSymbol("main", 0x1000, 0, STT.FUNC, STB.GLOBAL, 1)],
        )
        prog.set_enabled_object_finders(["btf"])
        self.assertIdentical(
            prog.function("main"),
            Object(
                prog,
                prog.function_type(prog.int_type("int", 4, True), (), False),
                address=0x1000,
            ),
        )
        prog.set_enabled_object_finders(["btf_symbol"])
        self.assertIdentical(
            prog.function("main"),
            Object(
                prog,
                prog.function_type(prog.int_type("int", 4, True), (), False),
                address=0x1000,
            ),
        )

    def test_variable_without_datasec(self):
        prog = btf_elf_program(
            [btf_int("int", bits=32, signed=True), btf_var("counter", 1)],
            [ElfSymbol("counter", 0x2000, 4, STT.OBJECT, STB.GLOBAL, 1)],
        )
        # The "btf" finder will not be able to find this, because there is no
        # DATASEC containing the VAR, so there is no way to determine the
        # address without a symbol.
        prog.set_enabled_object_finders(["btf"])
        msgre = "A BTF VAR is present.*no DATASEC containing.*"
        with self.assertRaisesRegex(ObjectNotFoundError, msgre):
            prog.variable("counter")
        # The "btf_symbol" finder will be able to find this, because there is a
        # VAR entry with the type, and a symbol of the same name providing the
        # address.
        prog.set_enabled_object_finders(["btf_symbol"])
        self.assertIdentical(
            prog.variable("counter"),
            Object(prog, prog.int_type("int", 4, True), address=0x2000),
        )

    def test_variable_with_datasec(self):
        prog = btf_elf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_var("counter", 1),
                btf_var("counter2", 1),
                btf_datasec(
                    ".data",
                    8,
                    (
                        btf_var_secinfo(2, 0, 4),
                        btf_var_secinfo(3, 4, 4),
                    ),
                ),
            ],
            [ElfSymbol("dummy", 0x2000, 8, STT.OBJECT, STB.GLOBAL, 1)],
        )
        # The "btf" finder will will be able to use the ".data" section address
        # to determine the base address, and the offset from the var_secinfo to
        # augment it.
        prog.set_enabled_object_finders(["btf"])
        self.assertIdentical(
            prog.variable("counter"),
            Object(prog, prog.int_type("int", 4, True), address=0x2000),
        )
        self.assertIdentical(
            prog.variable("counter2"),
            Object(prog, prog.int_type("int", 4, True), address=0x2004),
        )
        # Since there is no matching symbol, the "btf_symbol" finder cannot find
        # the variable.
        prog.set_enabled_object_finders(["btf_symbol"])
        self.assertRaises(ObjectNotFoundError, prog.variable, "counter")
        self.assertRaises(ObjectNotFoundError, prog.variable, "counter2")

    def test_variable_with_datasec_unknown_section_address(self):
        prog = btf_elf_program(
            [
                btf_int("int", bits=32, signed=True),
                btf_var("counter", 1),
                btf_datasec(".foobar", 4, (btf_var_secinfo(2, 0, 4),)),
            ],
            [ElfSymbol("dummy", 0x2000, 4, STT.OBJECT, STB.GLOBAL, 1)],
        )
        # Although a DATASEC is available, we cannot find the base address for
        # the section. As a result, the btf finder will be unable to find the
        # "counter" variable.
        prog.set_enabled_object_finders(["btf"])
        msgre = "A BTF VAR is present.*DATASEC base address was not found.*"
        with self.assertRaisesRegex(ObjectNotFoundError, msgre):
            prog.variable("counter")
        # Since there is no matching symbol, the "btf_symbol" finder cannot find
        # the variable.
        prog.set_enabled_object_finders(["btf_symbol"])
        self.assertRaises(ObjectNotFoundError, prog.variable, "counter")

    def test_constant(self):
        prog = btf_elf_program(
            [
                btf_enum(
                    "color",
                    4,
                    [
                        BtfEnum("RED", 0),
                        BtfEnum("ALL", -1),
                    ],
                ),
                btf_var("my_color", 1),
            ],
            [ElfSymbol("my_color", 0x2000, 4, STT.OBJECT, STB.GLOBAL, 1)],
        )
        type_ = prog.enum_type(
            "color",
            prog.int_type("u32", 4, False),
            (TypeEnumerator("RED", 0), TypeEnumerator("ALL", 2**32 - 1)),
        )
        prog.set_enabled_object_finders(["btf"])
        self.assertIdentical(
            prog.constant("RED"),
            Object(prog, type_, value=0),
        )
        prog.set_enabled_object_finders(["btf_symbol"])
        self.assertIdentical(
            prog.constant("RED"),
            Object(prog, type_, value=0),
        )
