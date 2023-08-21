# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import functools
import logging
import operator
import os.path
import re
import tempfile

import drgn
from drgn import (
    FaultError,
    FindObjectFlags,
    Language,
    Object,
    Program,
    ProgramFlags,
    Qualifiers,
    TypeEnumerator,
    TypeMember,
    TypeParameter,
    TypeTemplateParameter,
)
from tests import (
    DEFAULT_LANGUAGE,
    MockMemorySegment,
    TestCase,
    add_mock_memory_segments,
    identical,
)
import tests.assembler as assembler
from tests.dwarf import DW_AT, DW_ATE, DW_END, DW_FORM, DW_LANG, DW_OP, DW_TAG, DW_UT
from tests.dwarfwriter import (
    DwarfAttrib,
    DwarfDie,
    DwarfLabel,
    DwarfUnit,
    compile_dwarf,
)

bool_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.boolean),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "_Bool"),
    ),
)
char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed_char),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "char"),
    ),
)
signed_char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed_char),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "signed char"),
    ),
)
unsigned_char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.unsigned_char),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "unsigned char"),
    ),
)
utf8_char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.UTF),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "char8_t"),
    ),
)
utf16_char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 2),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.UTF),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "char16_t"),
    ),
)
utf32_char_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.UTF),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "char32_t"),
    ),
)
short_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 2),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "short"),
    ),
)
unsigned_short_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 2),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.unsigned),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "unsigned short"),
    ),
)
int_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "int"),
    ),
)
unsigned_int_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.unsigned),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "unsigned int"),
    ),
)
long_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "long"),
    ),
)
unsigned_long_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.unsigned),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "unsigned long"),
    ),
)
long_long_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "long long"),
    ),
)
float_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.float),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "float"),
    ),
)
double_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.float),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "double"),
    ),
)
long_double_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 16),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.float),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "long double"),
    ),
)
unsigned_long_long_die = DwarfDie(
    DW_TAG.base_type,
    (
        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.unsigned),
        DwarfAttrib(DW_AT.name, DW_FORM.string, "unsigned long long"),
    ),
)


labeled_char_die = (DwarfLabel("char_die"), char_die)
labeled_int_die = (DwarfLabel("int_die"), int_die)
labeled_unsigned_int_die = (DwarfLabel("unsigned_int_die"), unsigned_int_die)
labeled_float_die = (DwarfLabel("float_die"), float_die)


def dwarf_program(*args, segments=None, **kwds):
    prog = Program()
    with tempfile.NamedTemporaryFile() as f:
        f.write(compile_dwarf(*args, **kwds))
        f.flush()
        prog.load_debug_info([f.name])

    if segments is not None:
        add_mock_memory_segments(prog, segments)
    return prog


def wrap_test_type_dies(*dies):
    return (
        DwarfDie(
            DW_TAG.typedef,
            (
                DwarfAttrib(DW_AT.name, DW_FORM.string, "TEST"),
                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "test_type_die"),
            ),
        ),
        DwarfLabel("test_type_die"),
    ) + dies


elfutils_version = tuple(int(x) for x in drgn._elfutils_version.split(".")[:2])


def with_and_without_dw_form_indirect(f):
    @functools.wraps(f)
    def wrapper(self):
        with self.subTest():
            f(self, False)
        # elfutils does not support DW_FORM_indirect properly before commit
        # d63b26b8d21f ("libdw: handle DW_FORM_indirect when reading
        # attributes").
        if elfutils_version >= (0, 184):
            with self.subTest(msg="with DW_FORM_indirect"):
                f(self, True)

    return wrapper


class TestTypes(TestCase):
    def test_unknown_tag(self):
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(0x9999, ())))
        self.assertRaisesRegex(
            Exception, "unknown DWARF type tag 0x9999", prog.type, "TEST"
        )

    def test_base_type_missing_byte_size(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "bad egg"),
                    ),
                )
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_byte_size",
            prog.type,
            "TEST",
        )

    def test_base_type_missing_encoding(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "bad egg"),
                    ),
                )
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_encoding",
            prog.type,
            "TEST",
        )

    def test_base_type_missing_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                    ),
                )
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_name",
            prog.type,
            "TEST",
        )

    def test_unknown_base_type_encoding(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, 99),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "magic int"),
                    ),
                )
            )
        )
        self.assertRaisesRegex(Exception, "unknown DWARF encoding", prog.type, "TEST")

    def test_int_type_byteorder(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "int"),
                        DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                    ),
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.int_type("int", 4, True, "big")
        )

    def test_bool_type_byteorder(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.boolean),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "_Bool"),
                        DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                    ),
                )
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.bool_type("_Bool", 1, "big"))

    def test_float_type_byteorder(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.float),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "float"),
                        DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                    ),
                )
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.float_type("float", 4, "big"))

    def test_byteorder_by_name(self):
        # The only producer that uses DW_AT_endianity that I could find is GCC
        # for the scalar_storage_order type attribute (see
        # https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html). It
        # always places the standard DIE before the DIE with DW_AT_endianity,
        # which luckily guarantees that we'll use the standard one when doing a
        # name lookup.
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "int"),
                    ),
                ),
                DwarfDie(
                    DW_TAG.base_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "int"),
                        DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                    ),
                ),
            )
        )
        self.assertIdentical(prog.type("int"), prog.int_type("int", 4, True, "little"))

    @with_and_without_dw_form_indirect
    def test_qualifier(self, use_dw_form_indirect):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.const_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            ),
            use_dw_form_indirect=use_dw_form_indirect,
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST),
        )

    def test_multiple_qualifiers(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.const_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "restrict_die"),),
                ),
                DwarfLabel("restrict_die"),
                DwarfDie(
                    DW_TAG.restrict_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "volatile_die"),),
                ),
                DwarfLabel("volatile_die"),
                DwarfDie(
                    DW_TAG.volatile_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "atomic_die"),),
                ),
                DwarfLabel("atomic_die"),
                DwarfDie(
                    DW_TAG.atomic_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.int_type(
                "int",
                4,
                True,
                qualifiers=Qualifiers.CONST
                | Qualifiers.RESTRICT
                | Qualifiers.VOLATILE
                | Qualifiers.ATOMIC,
            ),
        )

    def test_qualifier_void(self):
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(DW_TAG.const_type, ())))
        self.assertIdentical(
            prog.type("TEST").type, prog.void_type(qualifiers=Qualifiers.CONST)
        )

    def test_multiple_qualifiers_void(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.const_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "restrict_die"),),
                ),
                DwarfLabel("restrict_die"),
                DwarfDie(
                    DW_TAG.restrict_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "volatile_die"),),
                ),
                DwarfLabel("volatile_die"),
                DwarfDie(
                    DW_TAG.volatile_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "atomic_die"),),
                ),
                DwarfLabel("atomic_die"),
                DwarfDie(DW_TAG.atomic_type, ()),
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.void_type(
                qualifiers=Qualifiers.CONST
                | Qualifiers.RESTRICT
                | Qualifiers.VOLATILE
                | Qualifiers.ATOMIC,
            ),
        )

    def test_struct(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
        )

    def test_struct_anonymous(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
        )

    def test_struct_no_members(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),),
                )
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.struct_type(None, 0, ()))

    def test_struct_incomplete(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                )
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.struct_type("point"))

    def test_struct_unnamed_member(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), None),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
        )

    def test_struct_member_missing_type(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                            ),
                        ),
                    ),
                )
            )
        )
        with self.assertRaisesRegex(Exception, "DW_TAG_member is missing DW_AT_type"):
            prog.type("TEST").type.members[0].type

    def test_struct_member_invalid_type(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.string, "foo"),
                            ),
                        ),
                    ),
                )
            )
        )
        with self.assertRaisesRegex(Exception, "DW_TAG_member has invalid DW_AT_type"):
            prog.type("TEST").type.members[0].type

    def test_struct_member_invalid_location(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(
                                    DW_AT.data_member_location,
                                    DW_FORM.string,
                                    "foo",
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_data_member_location",
            prog.type,
            "TEST",
        )

    def test_struct_missing_size(self):
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(DW_TAG.structure_type, ())))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_structure_type has missing or invalid DW_AT_byte_size",
            prog.type,
            "TEST",
        )

    def test_incomplete_to_complete(self):
        for version in (4, 5):
            with self.subTest(version=version):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        DwarfDie(
                            DW_TAG.pointer_type,
                            (
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                DwarfAttrib(
                                    DW_AT.type, DW_FORM.ref4, "incomplete_struct_die"
                                ),
                            ),
                        ),
                        DwarfLabel("incomplete_struct_die"),
                        DwarfDie(
                            DW_TAG.structure_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                                DwarfAttrib(
                                    DW_AT.declaration, DW_FORM.flag_present, True
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.structure_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "foo.c"),
                            ),
                            (
                                DwarfDie(
                                    DW_TAG.member,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                        DwarfAttrib(
                                            DW_AT.data_member_location, DW_FORM.data1, 0
                                        ),
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                    ),
                                ),
                                DwarfDie(
                                    DW_TAG.member,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                        DwarfAttrib(
                                            DW_AT.data_member_location, DW_FORM.data1, 4
                                        ),
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        *labeled_int_die,
                    ),
                    version=version,
                )
                self.assertIdentical(
                    prog.type("TEST").type,
                    prog.pointer_type(
                        prog.struct_type(
                            "point",
                            8,
                            (
                                TypeMember(prog.int_type("int", 4, True), "x"),
                                TypeMember(prog.int_type("int", 4, True), "y", 32),
                            ),
                        )
                    ),
                )

    def test_incomplete_to_complete_namespace(self):
        for version in (4, 5):
            with self.subTest(version=version):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        DwarfDie(
                            DW_TAG.pointer_type,
                            (
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                DwarfAttrib(
                                    DW_AT.type, DW_FORM.ref4, "incomplete_struct_die"
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.namespace,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "Math"),),
                            (
                                DwarfLabel("incomplete_struct_die"),
                                DwarfDie(
                                    DW_TAG.structure_type,
                                    (
                                        DwarfAttrib(
                                            DW_AT.name, DW_FORM.string, "point"
                                        ),
                                        DwarfAttrib(
                                            DW_AT.declaration,
                                            DW_FORM.flag_present,
                                            True,
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.namespace,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "Math"),),
                            (
                                DwarfDie(
                                    DW_TAG.structure_type,
                                    (
                                        DwarfAttrib(
                                            DW_AT.name, DW_FORM.string, "point"
                                        ),
                                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                        DwarfAttrib(
                                            DW_AT.decl_file, DW_FORM.udata, "foo.c"
                                        ),
                                    ),
                                    (
                                        DwarfDie(
                                            DW_TAG.member,
                                            (
                                                DwarfAttrib(
                                                    DW_AT.name, DW_FORM.string, "x"
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.data_member_location,
                                                    DW_FORM.data1,
                                                    0,
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.type, DW_FORM.ref4, "int_die"
                                                ),
                                            ),
                                        ),
                                        DwarfDie(
                                            DW_TAG.member,
                                            (
                                                DwarfAttrib(
                                                    DW_AT.name, DW_FORM.string, "y"
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.data_member_location,
                                                    DW_FORM.data1,
                                                    4,
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.type, DW_FORM.ref4, "int_die"
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        *labeled_int_die,
                        # Incorrect structure we should not access
                        DwarfDie(
                            DW_TAG.structure_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "wrong.c"),
                            ),
                        ),
                    ),
                    lang=DW_LANG.C_plus_plus,
                    version=version,
                )
                self.assertIdentical(
                    prog.type("TEST").type,
                    prog.pointer_type(
                        prog.struct_type(
                            "point",
                            8,
                            (
                                TypeMember(
                                    prog.int_type(
                                        "int", 4, True, language=Language.CPP
                                    ),
                                    "x",
                                ),
                                TypeMember(
                                    prog.int_type(
                                        "int", 4, True, language=Language.CPP
                                    ),
                                    "y",
                                    32,
                                ),
                            ),
                            language=Language.CPP,
                        ),
                        language=Language.CPP,
                    ),
                )

    def test_incomplete_to_complete_specification(self):
        for version in (4, 5):
            with self.subTest(version=version):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        DwarfDie(
                            DW_TAG.pointer_type,
                            (
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                                DwarfAttrib(
                                    DW_AT.type, DW_FORM.ref4, "incomplete_struct_die"
                                ),
                            ),
                        ),
                        DwarfLabel("incomplete_struct_die"),
                        DwarfDie(
                            DW_TAG.structure_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                                DwarfAttrib(
                                    DW_AT.declaration, DW_FORM.flag_present, True
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.structure_type,
                            (
                                DwarfAttrib(
                                    DW_AT.specification,
                                    DW_FORM.ref4,
                                    "incomplete_struct_die",
                                ),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            ),
                            (
                                DwarfDie(
                                    DW_TAG.member,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                        DwarfAttrib(
                                            DW_AT.data_member_location, DW_FORM.data1, 0
                                        ),
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                    ),
                                ),
                                DwarfDie(
                                    DW_TAG.member,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                        DwarfAttrib(
                                            DW_AT.data_member_location, DW_FORM.data1, 4
                                        ),
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        *labeled_int_die,
                    ),
                    version=version,
                )
                self.assertIdentical(
                    prog.type("TEST").type,
                    prog.pointer_type(
                        prog.struct_type(
                            "point",
                            8,
                            (
                                TypeMember(prog.int_type("int", 4, True), "x"),
                                TypeMember(prog.int_type("int", 4, True), "y", 32),
                            ),
                        )
                    ),
                )

    def test_incomplete_to_complete_nested(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "incomplete_class_die"),
                    ),
                ),
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Foo"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                    ),
                    (
                        DwarfLabel("incomplete_class_die"),
                        DwarfDie(
                            DW_TAG.class_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                                DwarfAttrib(
                                    DW_AT.declaration, DW_FORM.flag_present, True
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.class_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                            ),
                        ),
                    ),
                ),
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
                    ),
                ),
                DwarfDie(
                    DW_TAG.subprogram,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),),
                ),
            ),
            lang=DW_LANG.C_plus_plus,
        )
        self.assertIdentical(
            prog.type("TEST").type.type,
            prog.class_type("Bar", 0, ()),
        )

    def test_incomplete_to_complete_nested_specification(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "incomplete_class_die"),
                    ),
                ),
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Foo"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                    ),
                    (
                        DwarfLabel("incomplete_class_die"),
                        DwarfDie(
                            DW_TAG.class_type,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                                DwarfAttrib(
                                    DW_AT.declaration, DW_FORM.flag_present, True
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.class_type,
                            (
                                DwarfAttrib(
                                    DW_AT.specification,
                                    DW_FORM.ref4,
                                    "incomplete_class_die",
                                ),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                            ),
                        ),
                    ),
                ),
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
                    ),
                ),
                DwarfDie(
                    DW_TAG.subprogram,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),),
                ),
            ),
            lang=DW_LANG.C_plus_plus,
        )
        self.assertIdentical(
            prog.type("TEST").type.type,
            prog.class_type("Bar", 0, ()),
        )

    def test_filename(self):
        dies = (
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "foo.c"),
                ],
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                ),
            ),
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "bar/baz.c"),
                ],
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "b"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                ),
            ),
            *labeled_int_die,
        )

        def point_type(prog):
            return prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x"),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            )

        def other_point_type(prog):
            return prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "a"),
                    TypeMember(prog.int_type("int", 4, True), "b", 32),
                ),
            )

        prog = dwarf_program(dies)
        for dir in ["", "src", "usr/src", "/usr/src"]:
            with self.subTest(dir=dir):
                self.assertIdentical(
                    prog.type("struct point", os.path.join(dir, "foo.c")),
                    point_type(prog),
                )
        for dir in ["", "bar", "src/bar", "usr/src/bar", "/usr/src/bar"]:
            with self.subTest(dir=dir):
                self.assertIdentical(
                    prog.type("struct point", os.path.join(dir, "baz.c")),
                    other_point_type(prog),
                )

        dies[0].attribs[-1] = DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "xy/foo.h")
        dies[1].attribs[-1] = DwarfAttrib(
            DW_AT.decl_file, DW_FORM.udata, "/usr/include/ab/foo.h"
        )
        prog = dwarf_program(dies)
        for dir in ["xy", "src/xy", "usr/src/xy", "/usr/src/xy"]:
            with self.subTest(dir=dir):
                self.assertIdentical(
                    prog.type("struct point", os.path.join(dir, "foo.h")),
                    point_type(prog),
                )
        for dir in ["ab", "include/ab", "usr/include/ab", "/usr/include/ab"]:
            with self.subTest(dir=dir):
                self.assertIdentical(
                    prog.type("struct point", os.path.join(dir, "foo.h")),
                    other_point_type(prog),
                )
        for filename in [None, "foo.h"]:
            with self.subTest(filename=filename):
                t = prog.type("struct point", filename)
                self.assertTrue(
                    identical(t, point_type(prog))
                    or identical(t, other_point_type(prog))
                )

    def test_bit_field_data_bit_offset(self):
        dies = (
            DwarfDie(
                DW_TAG.structure_type,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                ),
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 32),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 44),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                ),
            ),
            *labeled_int_die,
        )

        for little_endian in [True, False]:
            prog = dwarf_program(
                wrap_test_type_dies(*dies), little_endian=little_endian
            )
            self.assertIdentical(
                prog.type("TEST").type,
                prog.struct_type(
                    "point",
                    8,
                    [
                        TypeMember(prog.int_type("int", 4, True), "x", 0),
                        TypeMember(
                            Object(
                                prog, prog.int_type("int", 4, True), bit_field_size=12
                            ),
                            "y",
                            32,
                        ),
                        TypeMember(
                            Object(
                                prog, prog.int_type("int", 4, True), bit_field_size=20
                            ),
                            "z",
                            44,
                        ),
                    ],
                ),
            )

    def test_bit_field_bit_offset_big_endian(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 32),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 44),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            ),
            little_endian=False,
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                [
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=12),
                        "y",
                        32,
                    ),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=20),
                        "z",
                        44,
                    ),
                ],
            ),
        )

    def test_bit_field_data_member_location_and_bit_offset_big_endian(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 0),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 12),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            ),
            little_endian=False,
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                [
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=12),
                        "y",
                        32,
                    ),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=20),
                        "z",
                        44,
                    ),
                ],
            ),
        )

    def test_bit_field_data_member_location_and_bit_offset_little_endian(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 20),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 0),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                [
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=12),
                        "y",
                        32,
                    ),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=20),
                        "z",
                        44,
                    ),
                ],
            ),
        )

    def test_bit_field_data_member_location_and_bit_offset_with_byte_size_little_endian(
        self,
    ):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 20),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 0),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "point",
                8,
                [
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=12),
                        "y",
                        32,
                    ),
                    TypeMember(
                        Object(prog, prog.int_type("int", 4, True), bit_field_size=20),
                        "z",
                        44,
                    ),
                ],
            ),
        )

    def test_union(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.union_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "option"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "f"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "float_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_float_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.union_type(
                "option",
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(prog.float_type("float", 4), "f"),
                ),
            ),
        )

    def test_class(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "coord"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 12),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 8
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.class_type(
                "coord",
                12,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                    TypeMember(prog.int_type("int", 4, True), "z", 64),
                ),
            ),
        )

    def test_class_template(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Array"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.template_type_parameter,
                            (
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.template_value_parameter,
                            (
                                DwarfAttrib(
                                    DW_AT.type, DW_FORM.ref4, "unsigned_int_die"
                                ),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.class_type(
                "Array",
                template_parameters=(
                    TypeTemplateParameter(prog.int_type("int", 4, True), "T"),
                    TypeTemplateParameter(
                        Object(prog, prog.int_type("unsigned int", 4, False), 2), "N"
                    ),
                ),
            ),
        )

    def test_template_value_parameter_missing_value(self):
        with self.assertRaisesRegex(
            Exception, "DW_AT_template_value_parameter is missing value"
        ):
            dwarf_program(
                wrap_test_type_dies(
                    DwarfDie(
                        DW_TAG.class_type,
                        (DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),),
                        (
                            DwarfDie(
                                DW_TAG.template_value_parameter,
                                (
                                    DwarfAttrib(
                                        DW_AT.type, DW_FORM.ref4, "unsigned_int_die"
                                    ),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                ),
                            ),
                        ),
                    ),
                    *labeled_unsigned_int_die,
                )
            ).type("TEST").type.template_parameters[0].argument

    def test_class_template_parameter_pack(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.class_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "ParamPack<int, 123>"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.GNU_template_parameter_pack,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "Params"),),
                            (
                                DwarfDie(
                                    DW_TAG.template_type_parameter,
                                    (
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),
                                    ),
                                ),
                                char_die,  # Unexpected die - should be ignored
                                DwarfDie(
                                    DW_TAG.template_value_parameter,
                                    (
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "unsigned_int_die"
                                        ),
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                        DwarfAttrib(
                                            DW_AT.const_value, DW_FORM.data1, 2
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.class_type(
                "ParamPack<int, 123>",
                template_parameters=(
                    TypeTemplateParameter(prog.int_type("int", 4, True), "T"),
                    TypeTemplateParameter(
                        Object(prog, prog.int_type("unsigned int", 4, False), 2), "N"
                    ),
                ),
            ),
        )

    def test_lazy_cycle(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfLabel("struct_die"),
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "foo"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "next"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "pointer_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("pointer_die"),
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "struct_die"),
                    ),
                ),
            )
        )
        type_ = prog.struct_type(
            "foo", 8, (TypeMember(lambda: prog.pointer_type(type_), "next"),)
        )
        self.assertIdentical(prog.type("TEST").type, type_)

    def test_infinite_cycle(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfLabel("pointer_die"),
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "pointer_die"),
                    ),
                ),
            )
        )
        self.assertRaisesRegex(Exception, "maximum.*depth exceeded", prog.type, "TEST")

    def test_enum(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type(
                "color",
                prog.int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )

    def test_enum_typedef(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("typedef_die"),
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "__uint32_t"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type(
                "color",
                prog.int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )

    def test_enum_anonymous(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type(
                None,
                prog.int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )

    def test_enum_no_enumerators(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type("color", prog.int_type("unsigned int", 4, False), ()),
        )

    def test_enum_incomplete(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                )
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.enum_type("color"))

    def test_enum_old_gcc(self):
        # GCC < 5.1
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type(
                "color",
                prog.int_type("<unknown>", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )

    def test_enum_old_gcc_signed(self):
        # GCC < 5.1
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.sdata, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.sdata, -1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.sdata, -2),
                            ),
                        ),
                    ),
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.enum_type(
                "color",
                prog.int_type("<unknown>", 4, True),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", -1),
                    TypeEnumerator("BLUE", -2),
                ),
            ),
        )

    def test_enum_compatible_type_not_integer(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "float_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                ),
                *labeled_float_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_AT_type of DW_TAG_enumeration_type is not an integer type",
            prog.type,
            "TEST",
        )

    def test_enum_missing_compatible_type_and_byte_size(self):
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(DW_TAG.enumeration_type, ())))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumeration_type has missing or invalid DW_AT_byte_size",
            prog.type,
            "TEST",
        )

    def test_enum_enumerator_missing_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator has missing or invalid DW_AT_name",
            prog.type,
            "TEST",
        )

    def test_enum_enumerator_missing_const_value(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "FOO"),),
                        ),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator is missing DW_AT_const_value",
            prog.type,
            "TEST",
        )

    def test_enum_enumerator_invalid_const_value(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "FOO"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.string, "FOO"),
                            ),
                        ),
                    ),
                ),
                *labeled_unsigned_int_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator has invalid DW_AT_const_value",
            prog.type,
            "TEST",
        )

    def test_tagged_by_name(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                *labeled_unsigned_int_die,
                *labeled_float_die,
                DwarfDie(
                    DW_TAG.structure_type,
                    [
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    ],
                    [
                        DwarfDie(
                            DW_TAG.member,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 0
                                ),
                                DwarfAttrib(
                                    DW_AT.type,
                                    DW_FORM.ref4,
                                    "int_die",
                                ),
                            ],
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                                DwarfAttrib(
                                    DW_AT.type,
                                    DW_FORM.ref4,
                                    "int_die",
                                ),
                            ],
                        ),
                    ],
                ),
                DwarfDie(
                    DW_TAG.union_type,
                    [
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "option"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ],
                    [
                        DwarfDie(
                            DW_TAG.member,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(
                                    DW_AT.type,
                                    DW_FORM.ref4,
                                    "int_die",
                                ),
                            ],
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "f"),
                                DwarfAttrib(
                                    DW_AT.type,
                                    DW_FORM.ref4,
                                    "float_die",
                                ),
                            ],
                        ),
                    ],
                ),
                DwarfDie(
                    DW_TAG.enumeration_type,
                    [
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(
                            DW_AT.type,
                            DW_FORM.ref4,
                            "unsigned_int_die",
                        ),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ],
                    [
                        DwarfDie(
                            DW_TAG.enumerator,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ],
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ],
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            [
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ],
                        ),
                    ],
                ),
            )
        )

        self.assertIdentical(
            prog.type("struct point"),
            prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        self.assertRaisesRegex(LookupError, "could not find", prog.type, "union point")
        self.assertIdentical(
            prog.type("union option"),
            prog.union_type(
                "option",
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(prog.float_type("float", 4), "f"),
                ),
            ),
        )
        self.assertRaisesRegex(
            LookupError, "could not find", prog.type, "struct option"
        )
        self.assertIdentical(
            prog.type("enum color"),
            prog.enum_type(
                "color",
                prog.int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        self.assertRaisesRegex(LookupError, "could not find", prog.type, "struct color")

    def test_typedef(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "INT"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.typedef_type("INT", prog.int_type("int", 4, True)),
        )

    def test_typedef_missing_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.typedef, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),)
                ),
                *labeled_int_die,
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_typedef has missing or invalid DW_AT_name",
            prog.type,
            "TEST",
        )

    def test_typedef_void(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.typedef, (DwarfAttrib(DW_AT.name, DW_FORM.string, "VOID"),)
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.typedef_type("VOID", prog.void_type())
        )

    def test_typedef_by_name(self):
        prog = dwarf_program(
            (
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "pid_t"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("pid_t"),
            prog.typedef_type("pid_t", prog.int_type("int", 4, True)),
        )

    def test_pointer(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.pointer_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.pointer_type(prog.int_type("int", 4, True))
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.pointer_type(prog.int_type("int", 4, True), 8)
        )

    def test_pointer_explicit_size(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.pointer_type(prog.int_type("int", 4, True), 4)
        )

    def test_pointer_void(self):
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(DW_TAG.pointer_type, ())))
        self.assertIdentical(
            prog.type("TEST").type, prog.pointer_type(prog.void_type())
        )

    def test_array(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 2)
        )

    def test_array_two_dimensional(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 3), 2),
        )

    def test_array_three_dimensional(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 4),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(
                prog.array_type(prog.array_type(prog.int_type("int", 4, True), 4), 3), 2
            ),
        )

    def test_array_missing_type(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                    ),
                ),
                int_die,
            )
        )
        self.assertRaisesRegex(
            Exception, "DW_TAG_array_type is missing DW_AT_type", prog.type, "TEST"
        )

    def test_array_zero_length_count(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 0)
        )

    def test_array_zero_length_upper_bound(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.sdata, -1),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 0)
        )

    def test_array_zero_length_upper_bound_cpp(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (
                                DwarfAttrib(
                                    DW_AT.upper_bound,
                                    DW_FORM.data8,
                                    18446744073709551615,
                                ),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 0)
        )

    def test_incomplete_array_no_subrange(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True))
        )

    def test_incomplete_array_empty_subrange(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True))
        )

    def test_incomplete_array_of_array(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                # int [3][]
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(DW_TAG.subrange_type, ()),
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 3)),
        )

    def test_array_of_zero_length_array(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                # int [3][0]
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 0), 3),
        )

    def test_array_of_zero_length_array_old_gcc(self):
        # GCC < 9.0
        prog = dwarf_program(
            wrap_test_type_dies(
                # int [3][0]
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                        DwarfDie(DW_TAG.subrange_type, ()),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 0), 3),
        )

    def test_array_of_zero_length_array_typedef(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                # ZARRAY [3]
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                    ),
                ),
                # typedef int ZARRAY[0];
                DwarfLabel("typedef_die"),
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(
                prog.typedef_type(
                    "ZARRAY", prog.array_type(prog.int_type("int", 4, True), 0)
                ),
                3,
            ),
        )

    def test_array_of_zero_length_array_typedef_old_gcc(self):
        # GCC actually squashes arrays of typedef arrays into one array type,
        # but let's handle it like GCC < 9.0 anyways.
        prog = dwarf_program(
            wrap_test_type_dies(
                # ZARRAY [3]
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                        ),
                    ),
                ),
                # typedef int ZARRAY[0];
                DwarfLabel("typedef_die"),
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(
                prog.typedef_type(
                    "ZARRAY", prog.array_type(prog.int_type("int", 4, True), 0)
                ),
                3,
            ),
        )

    def test_flexible_array_member(self):
        # struct {
        #   int i;
        #   int a[];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(prog.array_type(prog.int_type("int", 4, True)), "a", 32),
                ),
            ),
        )

    def test_typedef_flexible_array_member(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                # struct {
                #   int i;
                #   FARRAY a;
                # };
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),
                                DwarfAttrib(
                                    DW_AT.data_member_location, DW_FORM.data1, 4
                                ),
                            ),
                        ),
                    ),
                ),
                # typedef int FARRAY[];
                DwarfLabel("typedef_die"),
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "FARRAY"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(
                        prog.typedef_type(
                            "FARRAY", prog.array_type(prog.int_type("int", 4, True))
                        ),
                        "a",
                        32,
                    ),
                ),
            ),
        )

    def test_zero_length_array_only_member(self):
        # struct {
        #   int a[0];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),),
            ),
        )

    def test_zero_length_array_only_member_old_gcc(self):
        # GCC < 9.0.
        # struct {
        #   int a[0];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),),
            ),
        )

    def test_qualified_zero_length_array_only_member_old_gcc(self):
        # GCC < 9.0.
        # struct {
        #   const int a[0];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "const_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("const_die"),
                DwarfDie(
                    DW_TAG.const_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (
                    TypeMember(
                        prog.array_type(
                            prog.int_type("int", 4, True),
                            0,
                            qualifiers=Qualifiers.CONST,
                        ),
                        "a",
                    ),
                ),
            ),
        )

    def test_typedef_zero_length_array_only_member(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    # struct foo {
                    #   ZARRAY a;
                    # };
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "foo"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),
                            ),
                        ),
                    ),
                ),
                # typedef int ZARRAY[0];
                DwarfLabel("typedef_die"),
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "foo",
                4,
                (
                    TypeMember(
                        prog.typedef_type(
                            "ZARRAY", prog.array_type(prog.int_type("int", 4, True), 0)
                        ),
                        "a",
                    ),
                ),
            ),
        )

    def test_typedef_zero_length_array_only_member_old_gcc(self):
        # GCC < 9.0.
        dies = (
            DwarfDie(
                # struct foo {
                #   ZARRAY a;
                # };
                DW_TAG.structure_type,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "foo"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                ),
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "typedef_die"),
                        ),
                    ),
                ),
            ),
            # typedef int ZARRAY[0];
            DwarfLabel("typedef_die"),
            DwarfDie(
                DW_TAG.typedef,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                ),
            ),
            DwarfLabel("array_die"),
            DwarfDie(
                DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),)
            ),
            *labeled_int_die,
        )

        prog = dwarf_program(wrap_test_type_dies(*dies))
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "foo",
                4,
                (
                    TypeMember(
                        prog.typedef_type(
                            "ZARRAY", prog.array_type(prog.int_type("int", 4, True), 0)
                        ),
                        "a",
                    ),
                ),
            ),
        )
        # Although the ZARRAY type must be a zero-length array in the context
        # of the structure, it could still be an incomplete array if used
        # elsewhere.
        self.assertIdentical(
            prog.type("ZARRAY"),
            prog.typedef_type("ZARRAY", prog.array_type(prog.int_type("int", 4, True))),
        )

        # Make sure it still works if we parse the array type first.
        prog = dwarf_program(wrap_test_type_dies(*dies))
        self.assertIdentical(
            prog.type("ZARRAY"),
            prog.typedef_type("ZARRAY", prog.array_type(prog.int_type("int", 4, True))),
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                "foo",
                4,
                (
                    TypeMember(
                        prog.typedef_type(
                            "ZARRAY", prog.array_type(prog.int_type("int", 4, True), 0)
                        ),
                        "a",
                    ),
                ),
            ),
        )

    def test_zero_length_array_not_last_member(self):
        # struct {
        #   int a[0];
        #   int i;
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (
                    TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),
                    TypeMember(prog.int_type("int", 4, True), "i"),
                ),
            ),
        )

    def test_zero_length_array_not_last_member_old_gcc(self):
        # GCC < 9.0.
        # struct {
        #   int a[0];
        #   int i;
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.struct_type(
                None,
                4,
                (
                    TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),
                    TypeMember(prog.int_type("int", 4, True), "i"),
                ),
            ),
        )

    def test_zero_length_array_in_union(self):
        # union {
        #   int i;
        #   int a[0];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.union_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                        ),
                    ),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.union_type(
                None,
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),
                ),
            ),
        )

    def test_zero_length_array_in_union_old_gcc(self):
        # GCC < 9.0.
        # union {
        #   int i;
        #   int a[0];
        # };
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.union_type,
                    (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                    (
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.member,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.subrange_type, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.union_type(
                None,
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "i"),
                    TypeMember(prog.array_type(prog.int_type("int", 4, True), 0), "a"),
                ),
            ),
        )

    def test_pointer_size(self):
        prog = dwarf_program((int_die,), bits=32)
        self.assertIdentical(
            prog.type("int *"), prog.pointer_type(prog.int_type("int", 4, True), 4)
        )

    def test_function_no_parameters(self):
        # int foo(void)
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(prog.int_type("int", 4, True), (), False),
        )

    def test_function_void_return(self):
        # void foo(void)
        prog = dwarf_program(wrap_test_type_dies(DwarfDie(DW_TAG.subroutine_type, ())))
        self.assertIdentical(
            prog.type("TEST").type, prog.function_type(prog.void_type(), (), False)
        )

    def test_function_unnamed_parameter(self):
        # int foo(char)
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "char_die"),),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_char_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("int", 4, True),
                (TypeParameter(prog.int_type("char", 1, True)),),
                False,
            ),
        )

    def test_function_named_parameter(self):
        # int foo(char c)
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "char_die"),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "c"),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_char_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("int", 4, True),
                (TypeParameter(prog.int_type("char", 1, True), "c"),),
                False,
            ),
        )

    def test_utf_chars(self):
        # char8_t foo(char16_t a, char32_t b)
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "utf8_char_die"),),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "utf16_char_die"),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "utf32_char_die"),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "b"),
                            ),
                        ),
                    ),
                ),
                DwarfLabel("utf8_char_die"),
                utf8_char_die,
                DwarfLabel("utf16_char_die"),
                utf16_char_die,
                DwarfLabel("utf32_char_die"),
                utf32_char_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("char8_t", 1, False),
                (
                    TypeParameter(prog.int_type("char16_t", 2, False), "a"),
                    TypeParameter(prog.int_type("char32_t", 4, False), "b"),
                ),
                False,
            ),
        )

    def test_function_unspecified_parameters(self):
        # int foo()
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (DwarfDie(DW_TAG.unspecified_parameters, ()),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(prog.int_type("int", 4, True), (), True),
        )

    def test_function_variadic(self):
        # int foo(char, ...)
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "char_die"),),
                        ),
                        DwarfDie(DW_TAG.unspecified_parameters, ()),
                    ),
                ),
                *labeled_int_die,
                *labeled_char_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("int", 4, True),
                (TypeParameter(prog.int_type("char", 1, True)),),
                True,
            ),
        )

    def test_function_incomplete_array_parameter(self):
        # void foo(int [])
        # Note that in C, this is equivalent to void foo(int *), so GCC and
        # Clang emit the DWARF for the latter.
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),),
                        ),
                    ),
                ),
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                *labeled_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.void_type(),
                (TypeParameter(prog.array_type(prog.int_type("int", 4, True))),),
                False,
            ),
        )

    def test_function_template(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(DW_TAG.unspecified_parameters, ()),
                        DwarfDie(
                            DW_TAG.template_type_parameter,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),),
                        ),
                        DwarfDie(
                            DW_TAG.template_value_parameter,
                            (
                                DwarfAttrib(
                                    DW_AT.type, DW_FORM.ref4, "unsigned_int_die"
                                ),
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("int", 4, True),
                (),
                is_variadic=True,
                template_parameters=(
                    TypeTemplateParameter(prog.void_type(), "T"),
                    TypeTemplateParameter(
                        Object(prog, prog.int_type("unsigned int", 4, False), 2), "N"
                    ),
                ),
            ),
        )

    def test_function_template_parameter_pack(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.GNU_template_parameter_pack,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "Params"),),
                            (
                                DwarfDie(
                                    DW_TAG.template_type_parameter,
                                    (
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),
                                    ),
                                ),
                                char_die,  # Unexpected die - should be ignored
                                DwarfDie(
                                    DW_TAG.template_value_parameter,
                                    (
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "unsigned_int_die"
                                        ),
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                        DwarfAttrib(
                                            DW_AT.const_value, DW_FORM.data1, 2
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
                *labeled_unsigned_int_die,
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.function_type(
                prog.int_type("int", 4, True),
                (),
                is_variadic=False,
                template_parameters=(
                    TypeTemplateParameter(prog.int_type("int", 4, True), "T"),
                    TypeTemplateParameter(
                        Object(prog, prog.int_type("unsigned int", 4, False), 2), "N"
                    ),
                ),
            ),
        )

    def test_language(self):
        for name, lang in DW_LANG.__members__.items():
            if re.fullmatch("C[0-9]*", name):
                prog = dwarf_program(wrap_test_type_dies(int_die), lang=lang)
                self.assertIdentical(
                    prog.type("TEST").type,
                    prog.int_type("int", 4, True, language=Language.C),
                )
        prog = dwarf_program(wrap_test_type_dies(int_die), lang=DW_LANG.BLISS)
        self.assertIdentical(
            prog.type("TEST").type,
            prog.int_type("int", 4, True, language=DEFAULT_LANGUAGE),
        )

    def test_base_type_unit(self):
        for version in (4, 5):
            with self.subTest(version=version):
                prog = dwarf_program(
                    (
                        DwarfUnit(
                            DW_UT.compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (),
                                (
                                    DwarfLabel("signature_die"),
                                    DwarfDie(
                                        DW_TAG.base_type,
                                        (
                                            DwarfAttrib(
                                                DW_AT.signature,
                                                DW_FORM.ref_sig8,
                                                0xDEADBEEF,
                                            ),
                                        ),
                                    ),
                                    DwarfDie(
                                        DW_TAG.typedef,
                                        (
                                            DwarfAttrib(
                                                DW_AT.name, DW_FORM.string, "TEST"
                                            ),
                                            DwarfAttrib(
                                                DW_AT.type,
                                                DW_FORM.ref4,
                                                "signature_die",
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        DwarfUnit(
                            DW_UT.type,
                            DwarfDie(
                                DW_TAG.type_unit,
                                (),
                                labeled_int_die,
                            ),
                            type_signature=0xDEADBEEF,
                            type_offset="int_die",
                        ),
                    ),
                    version=version,
                )
                self.assertIdentical(
                    prog.type("TEST").type, prog.int_type("int", 4, True)
                )
                self.assertIdentical(prog.type("int"), prog.type("TEST").type)

    def test_struct_type_unit(self):
        for version in (4, 5):
            with self.subTest(version=version):
                prog = dwarf_program(
                    (
                        DwarfUnit(
                            DW_UT.compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (),
                                (
                                    DwarfLabel("signature_die"),
                                    DwarfDie(
                                        DW_TAG.structure_type,
                                        (
                                            DwarfAttrib(
                                                DW_AT.signature,
                                                DW_FORM.ref_sig8,
                                                0xDEADBEEF,
                                            ),
                                        ),
                                    ),
                                    DwarfDie(
                                        DW_TAG.typedef,
                                        (
                                            DwarfAttrib(
                                                DW_AT.name, DW_FORM.string, "TEST"
                                            ),
                                            DwarfAttrib(
                                                DW_AT.type,
                                                DW_FORM.ref4,
                                                "signature_die",
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        DwarfUnit(
                            DW_UT.type,
                            DwarfDie(
                                DW_TAG.type_unit,
                                (),
                                (
                                    DwarfLabel("struct_die"),
                                    DwarfDie(
                                        DW_TAG.structure_type,
                                        (
                                            DwarfAttrib(
                                                DW_AT.name, DW_FORM.string, "point"
                                            ),
                                            DwarfAttrib(
                                                DW_AT.byte_size, DW_FORM.data1, 8
                                            ),
                                        ),
                                        (
                                            DwarfDie(
                                                DW_TAG.member,
                                                (
                                                    DwarfAttrib(
                                                        DW_AT.name, DW_FORM.string, "x"
                                                    ),
                                                    DwarfAttrib(
                                                        DW_AT.data_member_location,
                                                        DW_FORM.data1,
                                                        0,
                                                    ),
                                                    DwarfAttrib(
                                                        DW_AT.type,
                                                        DW_FORM.ref4,
                                                        "int_die",
                                                    ),
                                                ),
                                            ),
                                            DwarfDie(
                                                DW_TAG.member,
                                                (
                                                    DwarfAttrib(
                                                        DW_AT.name, DW_FORM.string, "y"
                                                    ),
                                                    DwarfAttrib(
                                                        DW_AT.data_member_location,
                                                        DW_FORM.data1,
                                                        4,
                                                    ),
                                                    DwarfAttrib(
                                                        DW_AT.type,
                                                        DW_FORM.ref4,
                                                        "int_die",
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                    *labeled_int_die,
                                ),
                            ),
                            type_signature=0xDEADBEEF,
                            type_offset="struct_die",
                        ),
                    ),
                    version=version,
                )

                self.assertIdentical(
                    prog.type("TEST").type,
                    prog.struct_type(
                        "point",
                        8,
                        (
                            TypeMember(prog.int_type("int", 4, True), "x", 0),
                            TypeMember(prog.int_type("int", 4, True), "y", 32),
                        ),
                    ),
                )
                self.assertIdentical(prog.type("struct point"), prog.type("TEST").type)

    def test_namespaces(self):
        def make_composite_die(tag: DW_TAG, name: str) -> DwarfDie:
            return DwarfDie(
                tag,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, name),
                    DwarfAttrib(
                        DW_AT.byte_size,
                        DW_FORM.data1,
                        4 if tag == DW_TAG.union_type else 8,
                    ),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "foo.c"),
                ),
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(
                                DW_AT.data_member_location,
                                DW_FORM.data1,
                                0,
                            ),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(
                                DW_AT.data_member_location,
                                DW_FORM.data1,
                                0 if tag == DW_TAG.union_type else 4,
                            ),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "float_die"),
                        ),
                    ),
                ),
            )

        dies = (
            *labeled_int_die,
            *labeled_float_die,
            DwarfDie(
                DW_TAG.namespace,
                (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                (
                    DwarfDie(
                        DW_TAG.namespace,
                        (DwarfAttrib(DW_AT.name, DW_FORM.string, "eve"),),
                        (
                            DwarfDie(
                                DW_TAG.namespace,
                                (DwarfAttrib(DW_AT.name, DW_FORM.string, "kerbin"),),
                                (
                                    DwarfDie(
                                        DW_TAG.typedef,
                                        (
                                            DwarfAttrib(
                                                DW_AT.name,
                                                DW_FORM.string,
                                                "TEST_TYPEDEF",
                                            ),
                                            DwarfAttrib(
                                                DW_AT.type, DW_FORM.ref4, "int_die"
                                            ),
                                        ),
                                    ),
                                    make_composite_die(
                                        DW_TAG.structure_type, "TEST_STRUCT"
                                    ),
                                    make_composite_die(DW_TAG.class_type, "TEST_CLASS"),
                                    make_composite_die(DW_TAG.union_type, "TEST_UNION"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        prog = dwarf_program(dies, lang=DW_LANG.C_plus_plus)
        # Language is not set automatically when there is no DIE for `main`
        prog.language = Language.CPP

        self.assertIdentical(
            prog.type("moho::eve::kerbin::TEST_TYPEDEF"),
            prog.typedef_type("TEST_TYPEDEF", prog.int_type("int", 4, True)),
        )
        self.assertIdentical(
            prog.type("struct moho::eve::kerbin::TEST_STRUCT"),
            prog.struct_type(
                "TEST_STRUCT",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.float_type("float", 4), "y", 32),
                ),
            ),
        )
        self.assertIdentical(
            prog.type("class moho::eve::kerbin::TEST_CLASS"),
            prog.class_type(
                "TEST_CLASS",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.float_type("float", 4), "y", 32),
                ),
            ),
        )
        self.assertIdentical(
            prog.type("union moho::eve::kerbin::TEST_UNION"),
            prog.union_type(
                "TEST_UNION",
                4,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.float_type("float", 4), "y", 0),
                ),
            ),
        )

    def test_explicit_global_namespace(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(
                            DW_AT.name,
                            DW_FORM.string,
                            "TEST_TYPEDEF_GLOBAL",
                        ),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    ),
                ),
            ),
            lang=DW_LANG.C_plus_plus,
        )
        # Language is not set automatically when there is no DIE for `main`
        prog.language = Language.CPP

        self.assertIdentical(
            prog.type("TEST_TYPEDEF_GLOBAL"), prog.type("::TEST_TYPEDEF_GLOBAL")
        )

    def test_template_in_namespace(self):
        dies = (
            *labeled_int_die,
            *labeled_unsigned_int_die,
            DwarfDie(
                DW_TAG.namespace,
                (DwarfAttrib(DW_AT.name, DW_FORM.string, "containers"),),
                (
                    DwarfLabel("typedef_die"),
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(
                                DW_AT.name,
                                DW_FORM.string,
                                "MyTypedef",
                            ),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.class_type,
                        (
                            DwarfAttrib(
                                DW_AT.name,
                                DW_FORM.string,
                                "Pair<int, containers::MyTypedef>",
                            ),
                            DwarfAttrib(
                                DW_AT.byte_size,
                                DW_FORM.data1,
                                8,
                            ),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.template_type_parameter,
                                (
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.template_type_parameter,
                                (
                                    DwarfAttrib(
                                        DW_AT.type, DW_FORM.ref4, "typedef_die"
                                    ),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "V"),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "first"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location,
                                        DW_FORM.data1,
                                        0,
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "second"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location,
                                        DW_FORM.data1,
                                        4,
                                    ),
                                    DwarfAttrib(
                                        DW_AT.type, DW_FORM.ref4, "typedef_die"
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        prog = dwarf_program(dies, lang=DW_LANG.C_plus_plus)
        # Language is not set automatically when there is no DIE for `main`
        prog.language = Language.CPP

        self.assertIdentical(
            prog.type("class containers::Pair<int, containers::MyTypedef>"),
            prog.class_type(
                "Pair<int, containers::MyTypedef>",
                8,
                members=(
                    TypeMember(prog.int_type("int", 4, True), "first", 0),
                    TypeMember(prog.type("containers::MyTypedef"), "second", 32),
                ),
                template_parameters=(
                    TypeTemplateParameter(prog.int_type("int", 4, True), "T"),
                    TypeTemplateParameter(prog.type("containers::MyTypedef"), "V"),
                ),
            ),
        )

    def test_cpp_compound_type_specifiers(self):
        for keyword, tag in (
            ("struct", DW_TAG.structure_type),
            ("union", DW_TAG.union_type),
            ("class", DW_TAG.class_type),
        ):
            with self.subTest(keyword=keyword):
                prog = dwarf_program(
                    (
                        DwarfDie(
                            tag,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "Foo"),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                            ),
                            (
                                DwarfDie(
                                    DW_TAG.member,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "bar"),
                                        DwarfAttrib(
                                            DW_AT.data_member_location, DW_FORM.data1, 0
                                        ),
                                        DwarfAttrib(
                                            DW_AT.type, DW_FORM.ref4, "int_die"
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        *labeled_int_die,
                    ),
                )
                self.assertRaises(LookupError, prog.type, "Foo")
                prog.language = Language.CPP
                self.assertIdentical(prog.type("Foo"), prog.type(keyword + " Foo"))

    def test_cpp_enum_specifier(self):
        prog = dwarf_program(
            (
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Foo"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BAR"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data2, 1337),
                            ),
                        ),
                    ),
                ),
                *labeled_int_die,
            ),
        )
        self.assertRaises(LookupError, prog.type, "Foo")
        prog.language = Language.CPP
        self.assertIdentical(prog.type("Foo"), prog.type("enum Foo"))

    def test_cpp_typedef(self):
        prog = dwarf_program(
            (
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "INT"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    ),
                ),
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.subprogram,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),),
                ),
            ),
            lang=DW_LANG.C_plus_plus,
        )
        self.assertIdentical(
            prog.type("INT"),
            prog.typedef_type("INT", prog.int_type("int", 4, True)),
        )


class TestObjects(TestCase):
    def test_constant_signed_enum(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "GREEN"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "BLUE"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                            ),
                        ),
                    ),
                ),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                        ),
                    ),
                ),
            )
        )
        type_ = prog.enum_type(
            "color",
            prog.int_type("int", 4, True),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertIdentical(
            prog.object("RED", FindObjectFlags.CONSTANT), Object(prog, type_, value=0)
        )
        self.assertIdentical(prog["BLUE"], Object(prog, type_, value=2))

    def test_constant_unsigned_enum(self):
        prog = dwarf_program(
            (
                *labeled_unsigned_int_die,
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.enumerator,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "FLAG"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data2, 1 << 12),
                            ),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["FLAG"],
            Object(
                prog,
                prog.enum_type(
                    None,
                    prog.int_type("unsigned int", 4, False),
                    (TypeEnumerator("FLAG", 4096),),
                ),
                4096,
            ),
        )

    def test_function(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.subprogram,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "abs"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7FC3EB9B1C30),
                    ),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["abs"],
            Object(
                prog,
                prog.function_type(
                    prog.int_type("int", 4, True),
                    (TypeParameter(prog.int_type("int", 4, True)),),
                    False,
                ),
                address=0x7FC3EB9B1C30,
            ),
        )
        self.assertIdentical(prog.object("abs", FindObjectFlags.FUNCTION), prog["abs"])
        self.assertRaisesRegex(
            LookupError,
            "could not find variable",
            prog.object,
            "abs",
            FindObjectFlags.VARIABLE,
        )

    def test_function_no_address(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.subprogram,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "abort"),),
                )
            )
        )
        self.assertIdentical(
            prog.object("abort"), Object(prog, prog.function_type(prog.void_type(), ()))
        )

    def test_variable(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["x"],
            Object(prog, prog.int_type("int", 4, True), address=0xFFFFFFFF01020304),
        )
        self.assertIdentical(prog.object("x", FindObjectFlags.VARIABLE), prog["x"])
        self.assertRaisesRegex(
            LookupError,
            "could not find constant",
            prog.object,
            "x",
            FindObjectFlags.CONSTANT,
        )

    def test_zero_size_variable(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                ),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["x"],
            Object(
                prog,
                prog.array_type(prog.int_type("int", 4, True)),
                address=0xFFFFFFFF01020304,
            ),
        )

    def test_variable_no_address(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    ),
                ),
            )
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_empty(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.location, DW_FORM.exprloc, b""),
                    ),
                ),
            )
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_bit_piece(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFFFFFF01020304),
                                assembler.U8(DW_OP.bit_piece),
                                assembler.ULEB128(32),
                                assembler.ULEB128(4),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(
            prog.object("x"),
            Object(prog, "int", address=0xFFFFFFFF01020304, bit_offset=4),
        )

    def test_variable_expr_implicit_value(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(4),
                                        assembler.U32(0x12345678),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12345678))

    def test_variable_expr_implicit_value_pieces(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(2),
                                        assembler.U16(
                                            0x5678 if little_endian else 0x1234
                                        ),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(2),
                                        assembler.U16(
                                            0x1234 if little_endian else 0x5678
                                        ),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12345678))

    def test_variable_expr_implicit_value_pieces_too_large(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(2),
                                        assembler.U16(
                                            0x5678 if little_endian else 0x1234
                                        ),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(4),
                                        assembler.U32(
                                            0x1234 if little_endian else 0x5678
                                        ),
                                        assembler.U8(DW_OP.piece),
                                        # Piece size is larger than remaining size of object.
                                        assembler.ULEB128(4),
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(4),
                                        assembler.U32(0),
                                        # There is nothing remaining in the object.
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(4),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12345678))

    def test_variable_expr_implicit_value_too_small(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(1),
                                        assembler.U8(0x99),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x99))

    def test_variable_expr_implicit_value_bit_pieces(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(1),
                                        assembler.U8(0x8F if little_endian else 0x1F),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(4),
                                        assembler.ULEB128(4),
                                        assembler.U8(DW_OP.implicit_value),
                                        assembler.ULEB128(4),
                                        assembler.U32(
                                            0x1234567 if little_endian else 0x2345678
                                        ),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(28),
                                        assembler.ULEB128(0),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12345678))

    def test_variable_expr_implicit_value_piece_empty(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.implicit_value),
                                assembler.ULEB128(2),
                                assembler.U16(0),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_stack_value(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.lit31),
                                        assembler.U8(DW_OP.stack_value),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 31))

    def test_variable_expr_stack_value_pieces(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(
                                            DW_OP.lit2 if little_endian else DW_OP.lit1
                                        ),
                                        assembler.U8(DW_OP.stack_value),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(3 if little_endian else 1),
                                        assembler.U8(
                                            DW_OP.lit1 if little_endian else DW_OP.lit2
                                        ),
                                        assembler.U8(DW_OP.stack_value),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(1 if little_endian else 3),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x1000002))

    def test_variable_expr_stack_value_bit_pieces(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(
                                            DW_OP.lit2 if little_endian else DW_OP.lit31
                                        ),
                                        assembler.U8(DW_OP.stack_value),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(4 if little_endian else 28),
                                        assembler.ULEB128(0 if little_endian else 4),
                                        assembler.U8(
                                            DW_OP.lit31 if little_endian else DW_OP.lit2
                                        ),
                                        assembler.U8(DW_OP.stack_value),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(28 if little_endian else 4),
                                        assembler.ULEB128(4 if little_endian else 0),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12))

    def test_variable_expr_stack_value_piece_empty(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.lit1),
                                assembler.U8(DW_OP.stack_value),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_contiguous_piece_addresses(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFF0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFF0002),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int", address=0xFFFF0000))

    def test_variable_expr_contiguous_bit_piece_addresses(self):
        for bit_offset in (0, 1):
            with self.subTest(bit_offset=bit_offset):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0000),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(10),
                                        assembler.ULEB128(bit_offset),
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0001),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(22),
                                        assembler.ULEB128(bit_offset + 2),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
                self.assertIdentical(
                    prog.object("x"),
                    Object(prog, "int", address=0xFFFF0000, bit_offset=bit_offset),
                )

    def test_variable_expr_non_contiguous_piece_addresses(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0002),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0000),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                    segments=[
                        MockMemorySegment(
                            (0x12345678).to_bytes(
                                4, "little" if little_endian else "big"
                            ),
                            0xFFFF0000,
                        )
                    ],
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x56781234))

    def test_variable_expr_non_contiguous_piece_addresses_too_large(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0002),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(2),
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0000),
                                        assembler.U8(DW_OP.piece),
                                        assembler.ULEB128(256),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                    segments=[
                        MockMemorySegment(
                            (0x12345678).to_bytes(
                                4, "little" if little_endian else "big"
                            ),
                            0xFFFF0000,
                        )
                    ],
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x56781234))

    def test_variable_expr_non_contiguous_bit_piece_addresses(self):
        for little_endian in (True, False):
            with self.subTest(little_endian=little_endian):
                prog = dwarf_program(
                    wrap_test_type_dies(
                        *labeled_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    assembler.assemble(
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0000),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(4),
                                        assembler.ULEB128(0),
                                        assembler.U8(DW_OP.addr),
                                        assembler.U64(0xFFFF0000),
                                        assembler.U8(DW_OP.bit_piece),
                                        assembler.ULEB128(28),
                                        assembler.ULEB128(5),
                                        little_endian=little_endian,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    little_endian=little_endian,
                    segments=[
                        MockMemorySegment(
                            (
                                (0x2468ACE8).to_bytes(5, "little")
                                if little_endian
                                else (0x111A2B3C00).to_bytes(5, "big")
                            ),
                            0xFFFF0000,
                        )
                    ],
                )
                self.assertIdentical(prog.object("x"), Object(prog, "int", 0x12345678))

    def test_variable_expr_empty_piece_non_contiguous_address(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFF0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                                # This piece is not contiguous with
                                # the previous one, but it is zero
                                # bits so it should be ignored.
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xEEEE0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(0),
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFF0002),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(2),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int", address=0xFFFF0000))

    def test_variable_expr_previous_empty_piece_non_contiguous_address(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xEEEE0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(0),
                                # This piece is not contiguous with
                                # the previous one, but the
                                # previous one was zero bits so it
                                # should be ignored.
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xFFFF0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(4),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int", address=0xFFFF0000))

    def test_variable_expr_address_empty_piece(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.addr),
                                assembler.U64(0xEEEE0000),
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(0),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_absent_empty_piece(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.piece),
                                assembler.ULEB128(0),
                            ),
                        ),
                    ),
                ),
            ),
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_expr_unknown(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.location, DW_FORM.exprloc, b"\xdf"),
                    ),
                ),
            )
        )
        self.assertRaisesRegex(
            Exception, "unknown DWARF expression opcode", prog.object, "x"
        )

    def test_variable_expr_unknown_after_location(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                assembler.U8(DW_OP.implicit_value),
                                assembler.ULEB128(4),
                                assembler.U32(0),
                                assembler.U8(0xDF),
                            ),
                        ),
                    ),
                ),
            )
        )
        self.assertRaisesRegex(
            Exception, "unknown DWARF expression opcode", prog.object, "x"
        )

    def _eval_dwarf_expr(self, ops, **kwds):
        assemble_kwds = {
            key: value for key, value in kwds.items() if key == "little_endian"
        }
        return dwarf_program(
            wrap_test_type_dies(
                DwarfLabel("unsigned_long_long_die"),
                unsigned_long_long_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_long_long_die"),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            assembler.assemble(
                                *ops,
                                assembler.U8(DW_OP.stack_value),
                                **assemble_kwds,
                            ),
                        ),
                    ),
                ),
            ),
            **kwds,
        )["x"].value_()

    def _assert_dwarf_expr_eval(self, ops, expected, **kwds):
        self.assertEqual(self._eval_dwarf_expr(ops, **kwds), expected)

    def _assert_dwarf_expr_stack_underflow(self, ops, **kwds):
        with self.assertRaisesRegex(Exception, "stack underflow"):
            self._eval_dwarf_expr(ops, **kwds)

    def test_variable_expr_op_lit(self):
        for i in range(32):
            with self.subTest(i=i):
                self._assert_dwarf_expr_eval([assembler.U8(DW_OP.lit0 + i)], i)

    def test_variable_expr_op_addr(self):
        with self.subTest(bits=64):
            self._assert_dwarf_expr_eval(
                [assembler.U8(DW_OP.addr), assembler.U64(2**64 - 1)],
                2**64 - 1,
                bits=64,
            )
        with self.subTest(bits=32):
            self._assert_dwarf_expr_eval(
                [assembler.U8(DW_OP.addr), assembler.U32(2**32 - 1)],
                2**32 - 1,
                bits=32,
            )

    def test_variable_expr_op_constu(self):
        for bits in (64, 32):
            for size in (1, 2, 4, 8):
                op_name = f"const{size}u"
                with self.subTest(bits=bits, op=op_name):
                    op = getattr(DW_OP, op_name)
                    type_ = getattr(assembler, f"U{size * 8}")
                    self._assert_dwarf_expr_eval(
                        [assembler.U8(op), type_(2 ** (size * 8) - 1)],
                        (2 ** (size * 8) - 1) & (2**bits - 1),
                        bits=bits,
                    )
            with self.subTest(bits=bits, op="constu"):
                self._assert_dwarf_expr_eval(
                    [assembler.U8(DW_OP.constu), assembler.ULEB128(0x123456789)],
                    0x123456789 & (2**bits - 1),
                    bits=bits,
                )

    # These are really tests of our ULEB128 parsing.
    def test_variable_expr_op_constu_max(self):
        self._assert_dwarf_expr_eval(
            [assembler.U8(DW_OP.constu), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"],
            2**64 - 1,
        )

    def test_variable_expr_op_constu_non_canonical(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.constu),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x81\x00",
            ],
            2**64 - 1,
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.constu),
                b"\xfb\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00",
            ],
            123,
        )

    def test_variable_expr_op_constu_overflow(self):
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [assembler.U8(DW_OP.constu), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02"],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.constu),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x82\x00",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.constu),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x81\x01",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.constu),
                b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01",
            ],
        )

    def test_variable_expr_op_consts(self):
        for bits in (64, 32):
            for size in (1, 2, 4, 8):
                op_name = f"const{size}s"
                with self.subTest(bits=bits, op=op_name):
                    op = getattr(DW_OP, op_name)
                    type_ = getattr(assembler, f"S{size * 8}")
                    self._assert_dwarf_expr_eval(
                        [assembler.U8(op), type_(-1)],
                        -1 & (2**bits - 1),
                        bits=bits,
                    )
            with self.subTest(bits=bits, op="consts"):
                self._assert_dwarf_expr_eval(
                    [assembler.U8(DW_OP.consts), assembler.SLEB128(-0x123456789)],
                    -0x123456789 & (2**bits - 1),
                    bits=bits,
                )

    # These are really tests of our SLEB128 parsing.
    def test_variable_expr_op_consts_max(self):
        # Maximum positive value.
        self._assert_dwarf_expr_eval(
            [assembler.U8(DW_OP.consts), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"],
            2**63 - 1,
        )
        # Maximum negative value.
        self._assert_dwarf_expr_eval(
            [assembler.U8(DW_OP.consts), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f"],
            -1 & (2**64 - 1),
        )
        # Minimum negative value.
        self._assert_dwarf_expr_eval(
            [assembler.U8(DW_OP.consts), b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f"],
            -(2**63) & (2**64 - 1),
        )

    def test_variable_expr_op_consts_non_canonical(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x80\x00",
            ],
            2**63 - 1,
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
            ],
            -1 & (2**64 - 1),
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
            ],
            -1 & (2**64 - 1),
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\xff\x7f",
            ],
            -(2**63) & (2**64 - 1),
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\xff\xff\x7f",
            ],
            -(2**63) & (2**64 - 1),
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.consts),
                b"\xfb\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00",
            ],
            123,
        )

    def test_variable_expr_op_consts_overflow(self):
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [assembler.U8(DW_OP.consts), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x81\x00",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.consts),
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x80\x01",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.consts),
                b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01",
            ],
        )
        self.assertRaisesRegex(
            Exception,
            "overflow",
            self._eval_dwarf_expr,
            [
                assembler.U8(DW_OP.consts),
                b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f",
            ],
        )

    def test_variable_expr_op_dup(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit1),
                assembler.U8(DW_OP.dup),
                assembler.U8(DW_OP.plus),
            ],
            2,
        )

    def test_variable_expr_op_drop(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit1),
                assembler.U8(DW_OP.lit2),
                assembler.U8(DW_OP.drop),
                assembler.U8(DW_OP.lit3),
                assembler.U8(DW_OP.plus),
            ],
            4,
        )

    def test_variable_expr_op_pick(self):
        for i, value in enumerate((30, 20, 10)):
            with self.subTest(i=i):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit10),
                        assembler.U8(DW_OP.lit20),
                        assembler.U8(DW_OP.lit30),
                        assembler.U8(DW_OP.pick),
                        assembler.U8(i),
                    ],
                    value,
                )

    def test_variable_expr_op_pick_underflow(self):
        for i in (3, 255):
            with self.subTest(i=i):
                self._assert_dwarf_expr_stack_underflow(
                    [
                        assembler.U8(DW_OP.lit10),
                        assembler.U8(DW_OP.lit20),
                        assembler.U8(DW_OP.lit30),
                        assembler.U8(DW_OP.pick),
                        assembler.U8(i),
                    ]
                )

    def test_variable_expr_op_over(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit10),
                assembler.U8(DW_OP.lit20),
                assembler.U8(DW_OP.over),
            ],
            10,
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit10),
                assembler.U8(DW_OP.lit20),
                assembler.U8(DW_OP.lit30),
                assembler.U8(DW_OP.over),
            ],
            20,
        )

    def test_variable_expr_op_swap(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit3),
                assembler.U8(DW_OP.lit5),
                assembler.U8(DW_OP.swap),
                assembler.U8(DW_OP.minus),
            ],
            2,
        )

    def test_variable_expr_op_rot(self):
        for i, value in enumerate((5, 3, 7, 1)):
            self._assert_dwarf_expr_eval(
                [
                    assembler.U8(DW_OP.lit1),
                    assembler.U8(DW_OP.lit3),
                    assembler.U8(DW_OP.lit5),
                    assembler.U8(DW_OP.lit7),
                    assembler.U8(DW_OP.rot),
                    assembler.U8(DW_OP.pick),
                    assembler.U8(i),
                ],
                value,
            )

    def test_variable_expr_op_deref(self):
        for bits in (64, 32):
            for little_endian in (True, False):
                with self.subTest(bits=bits, little_endian=little_endian):
                    self._assert_dwarf_expr_eval(
                        [
                            assembler.U8(DW_OP.addr),
                            (assembler.U64 if bits == 64 else assembler.U32)(
                                0xFFFF0000
                            ),
                            assembler.U8(DW_OP.deref),
                        ],
                        0x12345678,
                        bits=bits,
                        little_endian=little_endian,
                        segments=[
                            MockMemorySegment(
                                (0x12345678).to_bytes(
                                    bits // 8, "little" if little_endian else "big"
                                ),
                                0xFFFF0000,
                            )
                        ],
                    )

    def test_variable_expr_op_deref_fault(self):
        with self.assertRaises(FaultError):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.addr),
                    assembler.U64(0xFFFF0000),
                    assembler.U8(DW_OP.deref),
                ]
            )

    def test_variable_expr_op_deref_size(self):
        for bits in (64, 32):
            for little_endian in (True, False):
                with self.subTest(bits=bits, little_endian=little_endian):
                    self._assert_dwarf_expr_eval(
                        [
                            assembler.U8(DW_OP.addr),
                            (assembler.U64 if bits == 64 else assembler.U32)(
                                0xFFFF0000
                            ),
                            assembler.U8(DW_OP.deref_size),
                            assembler.U8(2),
                        ],
                        0x1337,
                        bits=bits,
                        little_endian=little_endian,
                        segments=[
                            MockMemorySegment(
                                (0x1337).to_bytes(
                                    2, "little" if little_endian else "big"
                                ),
                                0xFFFF0000,
                            )
                        ],
                    )

    def test_variable_expr_op_deref_size_fault(self):
        with self.assertRaises(FaultError):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.addr),
                    assembler.U64(0xFFFF0000),
                    assembler.U8(DW_OP.deref_size),
                    assembler.U8(1),
                ]
            )

    def test_variable_expr_stack_underflow(self):
        for case in [
            (DW_OP.dup, 1),
            (DW_OP.drop, 1),
            (DW_OP.over, 2),
            (DW_OP.swap, 2),
            (DW_OP.rot, 3),
            (DW_OP.deref, 1),
            (DW_OP.deref_size, 1, assembler.U8(1)),
            (DW_OP.abs, 1),
            (DW_OP.and_, 2),
            (DW_OP.div, 2),
            (DW_OP.minus, 2),
            (DW_OP.mod, 2),
            (DW_OP.mul, 2),
            (DW_OP.neg, 1),
            (DW_OP.not_, 1),
            (DW_OP.or_, 2),
            (DW_OP.plus, 2),
            (DW_OP.plus_uconst, 1, assembler.ULEB128(1)),
            (DW_OP.shl, 2),
            (DW_OP.shr, 2),
            (DW_OP.shra, 2),
            (DW_OP.xor, 2),
            (DW_OP.le, 2),
            (DW_OP.ge, 2),
            (DW_OP.eq, 2),
            (DW_OP.lt, 2),
            (DW_OP.gt, 2),
            (DW_OP.ne, 2),
            (DW_OP.bra, 1, assembler.S16(1)),
        ]:
            op = case[0]
            min_entries = case[1]
            extra_args = case[2:]
            with self.subTest(op=op):
                for i in range(min_entries):
                    self._assert_dwarf_expr_stack_underflow(
                        [assembler.U8(DW_OP.lit1)] * i + [assembler.U8(op), *extra_args]
                    )

    def test_variable_expr_op_abs(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-9),
                        assembler.U8(DW_OP.abs),
                    ],
                    9,
                    bits=bits,
                )

    def test_variable_expr_op_and(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.and_),
                    ],
                    1,
                    bits=bits,
                )

    def test_variable_expr_op_div(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.div),
                    ],
                    2,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit0),
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.div),
                    ],
                    0,
                    bits=bits,
                )
                # The DWARF 5 specification doesn't specify how signed division
                # should be rounded. We assume truncation towards zero like C.
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.div),
                    ],
                    -2 & (2**bits - 1),
                    bits=bits,
                )

    def test_variable_expr_op_div_by_zero(self):
        with self.assertRaisesRegex(Exception, "division by zero"):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.lit1),
                    assembler.U8(DW_OP.lit0),
                    assembler.U8(DW_OP.div),
                ]
            )

    def test_variable_expr_op_minus(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.minus),
                    ],
                    3,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.minus),
                    ],
                    -3 & (2**bits - 1),
                    bits=bits,
                )

    def test_variable_expr_op_mod(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.mod),
                    ],
                    1,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit0),
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.mod),
                    ],
                    0,
                    bits=bits,
                )
                # Although DW_OP_div is signed, DW_OP_mod is unsigned.
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.mod),
                    ],
                    1,
                    bits=bits,
                )

    def test_variable_expr_op_mod_by_zero(self):
        with self.assertRaisesRegex(Exception, "modulo by zero"):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.lit1),
                    assembler.U8(DW_OP.lit0),
                    assembler.U8(DW_OP.mod),
                ]
            )

    def test_variable_expr_op_mul(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.mul),
                    ],
                    10,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-5),
                        assembler.U8(DW_OP.lit2),
                        assembler.U8(DW_OP.mul),
                    ],
                    ((-5 & (2**bits - 1)) * 2) & (2**bits - 1),
                    bits=bits,
                )

    def test_variable_expr_op_neg(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit7),
                        assembler.U8(DW_OP.neg),
                    ],
                    -7 & (2**bits - 1),
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-7),
                        assembler.U8(DW_OP.neg),
                    ],
                    7,
                    bits=bits,
                )

    def test_variable_expr_op_not(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit0),
                        assembler.U8(DW_OP.not_),
                    ],
                    2**bits - 1,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit31),
                        assembler.U8(DW_OP.not_),
                    ],
                    ~31 & (2**bits - 1),
                    bits=bits,
                )

    def test_variable_expr_op_or(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.or_),
                    ],
                    7,
                    bits=bits,
                )

    def test_variable_expr_op_plus(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit6),
                        assembler.U8(DW_OP.lit7),
                        assembler.U8(DW_OP.plus),
                    ],
                    13,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.S8(DW_OP.const1s),
                        assembler.S8(-3),
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.plus),
                    ],
                    2,
                    bits=bits,
                )

    def test_variable_expr_op_plus_uconst(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit6),
                        assembler.U8(DW_OP.plus_uconst),
                        assembler.ULEB128(7),
                    ],
                    13,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.S8(DW_OP.const1s),
                        assembler.S8(-3),
                        assembler.U8(DW_OP.plus_uconst),
                        assembler.ULEB128(5),
                    ],
                    2,
                    bits=bits,
                )

    def test_variable_expr_op_shl(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.lit4),
                        assembler.U8(DW_OP.shl),
                    ],
                    48,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.constu),
                        assembler.ULEB128(2 ** (bits - 2)),
                        assembler.U8(DW_OP.lit1),
                        assembler.U8(DW_OP.shl),
                    ],
                    2 ** (bits - 1),
                    bits=bits,
                )
                # The DWARF specification doesn't define the behavior of
                # shifting by a number of bits larger than the width of the
                # type. We evaluate it to zero.
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.const1u),
                        assembler.U8(bits),
                        assembler.U8(DW_OP.shl),
                    ],
                    0,
                    bits=bits,
                )

    def test_variable_expr_op_shr(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1u),
                        assembler.U8(48),
                        assembler.U8(DW_OP.lit4),
                        assembler.U8(DW_OP.shr),
                    ],
                    3,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.constu),
                        assembler.ULEB128(2 ** (bits - 1)),
                        assembler.U8(DW_OP.lit1),
                        assembler.U8(DW_OP.shr),
                    ],
                    2 ** (bits - 2),
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-1),
                        assembler.U8(DW_OP.const1u),
                        assembler.U8(bits),
                        assembler.U8(DW_OP.shr),
                    ],
                    0,
                    bits=bits,
                )

    def test_variable_expr_op_shra(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1u),
                        assembler.U8(48),
                        assembler.U8(DW_OP.lit4),
                        assembler.U8(DW_OP.shra),
                    ],
                    3,
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-48),
                        assembler.U8(DW_OP.lit4),
                        assembler.U8(DW_OP.shra),
                    ],
                    -3 & (2**bits - 1),
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.constu),
                        assembler.ULEB128(2 ** (bits - 1)),
                        assembler.U8(DW_OP.lit1),
                        assembler.U8(DW_OP.shra),
                    ],
                    2 ** (bits - 2) + 2 ** (bits - 1),
                    bits=bits,
                )
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.const1s),
                        assembler.S8(-2),
                        assembler.U8(DW_OP.const1u),
                        assembler.U8(bits),
                        assembler.U8(DW_OP.shra),
                    ],
                    -1 & (2**bits - 1),
                    bits=bits,
                )

    def test_variable_expr_op_xor(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self._assert_dwarf_expr_eval(
                    [
                        assembler.U8(DW_OP.lit3),
                        assembler.U8(DW_OP.lit5),
                        assembler.U8(DW_OP.xor),
                    ],
                    6,
                    bits=bits,
                )

    def test_variable_expr_relational(self):
        for op, py_op in [
            (DW_OP.le, operator.le),
            (DW_OP.ge, operator.ge),
            (DW_OP.eq, operator.eq),
            (DW_OP.lt, operator.lt),
            (DW_OP.gt, operator.gt),
            (DW_OP.ne, operator.ne),
        ]:
            for bits in (64, 32):
                for val1, val2 in [
                    (3, 5),
                    (3, -5),
                    (-3, 5),
                    (-3, -5),
                    (5, 5),
                    (5, -5),
                    (-5, 5),
                    (-5, -5),
                    (6, 5),
                    (6, -5),
                    (-6, 5),
                    (-6, -5),
                ]:
                    with self.subTest(bits=bits, val1=val1, val2=val2):
                        self._assert_dwarf_expr_eval(
                            [
                                assembler.U8(DW_OP.const1s),
                                assembler.S8(val1),
                                assembler.U8(DW_OP.const1s),
                                assembler.S8(val2),
                                assembler.U8(op),
                            ],
                            int(py_op(val1, val2)),
                        )

    def test_variable_expr_op_skip(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.skip),
                assembler.S16(3),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.div),
                assembler.U8(DW_OP.lit20),
            ],
            20,
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit1),
                assembler.U8(DW_OP.skip),
                assembler.S16(4),
                assembler.U8(DW_OP.lit3),
                assembler.U8(DW_OP.skip),
                assembler.S16(4),
                assembler.U8(DW_OP.lit2),
                assembler.U8(DW_OP.skip),
                assembler.S16(-8),
            ],
            3,
        )

    def test_variable_expr_op_skip_infinite(self):
        with self.assertRaisesRegex(Exception, "too many operations"):
            self._eval_dwarf_expr([assembler.U8(DW_OP.skip), assembler.S16(-3)])

    def test_variable_expr_op_skip_out_of_bounds(self):
        with self.assertRaisesRegex(Exception, "out of bounds"):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.skip),
                    # 1 extra for for the DW_OP_stack_value added by
                    # _eval_dwarf_expr().
                    assembler.U16(3),
                    assembler.U8(DW_OP.nop),
                ],
            )

    def test_variable_expr_op_bra(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit31),
                assembler.U8(DW_OP.bra),
                assembler.S16(3),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.div),
                assembler.U8(DW_OP.lit20),
            ],
            20,
        )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit1),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.bra),
                assembler.S16(1),
                assembler.U8(DW_OP.lit2),
            ],
            2,
        )
        # More complicated expression implementing something like this:
        # i = 0
        # x = 0
        # do {
        #     x += 2;
        #     i += 1;
        # while (i <= 5);
        # return x;
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.plus_uconst),
                assembler.ULEB128(2),
                assembler.U8(DW_OP.swap),
                assembler.U8(DW_OP.plus_uconst),
                assembler.ULEB128(1),
                assembler.U8(DW_OP.swap),
                assembler.U8(DW_OP.over),
                assembler.U8(DW_OP.lit5),
                assembler.U8(DW_OP.lt),
                assembler.U8(DW_OP.bra),
                assembler.S16(-12),
            ],
            10,
        )

    def test_variable_expr_op_bra_out_of_bounds(self):
        with self.assertRaisesRegex(Exception, "out of bounds"):
            self._eval_dwarf_expr(
                [
                    assembler.U8(DW_OP.lit1),
                    assembler.U8(DW_OP.bra),
                    # 1 extra for for the DW_OP_stack_value added by
                    # _eval_dwarf_expr().
                    assembler.U16(3),
                    assembler.U8(DW_OP.nop),
                ],
            )
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.lit0),
                assembler.U8(DW_OP.bra),
                assembler.U16(3),
                assembler.U8(DW_OP.lit2),
            ],
            2,
        )

    def test_variable_expr_op_nop(self):
        self._assert_dwarf_expr_eval(
            [
                assembler.U8(DW_OP.nop),
                assembler.U8(DW_OP.nop),
                assembler.U8(DW_OP.lit25),
                assembler.U8(DW_OP.nop),
                assembler.U8(DW_OP.nop),
            ],
            25,
        )

    def test_variable_const_signed(self):
        for form in (
            DW_FORM.data1,
            DW_FORM.data2,
            DW_FORM.data4,
            DW_FORM.data8,
            DW_FORM.sdata,
        ):
            prog = dwarf_program(
                wrap_test_type_dies(
                    *labeled_int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                            DwarfAttrib(DW_AT.const_value, form, 1),
                        ),
                    ),
                )
            )
            self.assertIdentical(
                prog["x"], Object(prog, prog.int_type("int", 4, True), 1)
            )

    def test_variable_const_unsigned(self):
        for form in (
            DW_FORM.data1,
            DW_FORM.data2,
            DW_FORM.data4,
            DW_FORM.data8,
            DW_FORM.udata,
        ):
            prog = dwarf_program(
                wrap_test_type_dies(
                    *labeled_unsigned_int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "unsigned_int_die"),
                            DwarfAttrib(DW_AT.const_value, form, 1),
                        ),
                    ),
                )
            )
            self.assertIdentical(
                prog["x"], Object(prog, prog.int_type("unsigned int", 4, False), 1)
            )

    def test_variable_const_block(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                    ),
                ),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "p"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                        DwarfAttrib(
                            DW_AT.const_value,
                            DW_FORM.block1,
                            b"\x01\x00\x00\x00\x02\x00\x00\x00",
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["p"],
            Object(prog, prog.array_type(prog.int_type("int", 4, True), 2), [1, 2]),
        )

    def test_variable_const_block_too_small(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfLabel("array_die"),
                DwarfDie(
                    DW_TAG.array_type,
                    (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    (
                        DwarfDie(
                            DW_TAG.subrange_type,
                            (DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1),),
                        ),
                    ),
                ),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "p"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "array_die"),
                        DwarfAttrib(
                            DW_AT.const_value,
                            DW_FORM.block,
                            b"\x01\x00\x00\x00\x02\x00\x00",
                        ),
                    ),
                ),
            )
        )
        self.assertRaisesRegex(Exception, "too small", prog.variable, "p")

    @with_and_without_dw_form_indirect
    def test_specification(self, use_dw_form_indirect):
        prog = dwarf_program(
            wrap_test_type_dies(
                *labeled_int_die,
                DwarfLabel("declaration_die"),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                ),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(
                            DW_AT.specification, DW_FORM.ref4, "declaration_die"
                        ),
                        DwarfAttrib(
                            DW_AT.location,
                            DW_FORM.exprloc,
                            b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                        ),
                    ),
                ),
            ),
            use_dw_form_indirect=use_dw_form_indirect,
        )

        self.assertIdentical(
            prog["x"],
            Object(prog, prog.int_type("int", 4, True), address=0xFFFFFFFF01020304),
        )

    @with_and_without_dw_form_indirect
    def test_namespace_reverse_specification(self, use_dw_form_indirect):
        """Test specification inside namespace while declaration is outside of it."""
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    [
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),
                        DwarfAttrib(DW_AT.sibling, DW_FORM.ref4, "declaration_die"),
                    ],
                    [
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(
                                    DW_AT.specification, DW_FORM.ref4, "declaration_die"
                                ),
                                DwarfAttrib(
                                    DW_AT.location,
                                    DW_FORM.exprloc,
                                    b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                                ),
                            ),
                        )
                    ],
                ),
                DwarfLabel("declaration_die"),
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                    ),
                ),
            ),
            use_dw_form_indirect=use_dw_form_indirect,
        )

        self.assertIdentical(
            prog["x"],
            Object(prog, prog.int_type("int", 4, True), address=0xFFFFFFFF01020304),
        )

    def test_not_found(self):
        prog = dwarf_program(int_die)
        self.assertRaisesRegex(LookupError, "could not find", prog.object, "y")


class TestScopes(TestCase):
    def test_global_namespace(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 123),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["::target"], Object(prog, prog.int_type("int", 4, True), 123)
        )
        self.assertIdentical(prog["::target"], prog["target"])

    def test_namespaces_single(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                    (
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 123),
                            ),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["moho::target"], Object(prog, prog.int_type("int", 4, True), 123)
        )

    def test_namespaces_gcc(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                    (
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                                DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 123),
                            ),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["moho::target"], Object(prog, prog.int_type("int", 4, True), 123)
        )

    def test_namespaces_nested(self):
        prog = dwarf_program(
            (
                *labeled_int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                    (
                        DwarfDie(
                            DW_TAG.namespace,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "eve"),),
                            (
                                DwarfDie(
                                    DW_TAG.namespace,
                                    (
                                        DwarfAttrib(
                                            DW_AT.name, DW_FORM.string, "kerbin"
                                        ),
                                    ),
                                    (
                                        DwarfDie(
                                            DW_TAG.variable,
                                            (
                                                DwarfAttrib(
                                                    DW_AT.name, DW_FORM.string, "minmus"
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.type, DW_FORM.ref4, "int_die"
                                                ),
                                                DwarfAttrib(
                                                    DW_AT.const_value, DW_FORM.data1, 47
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog["moho::eve::kerbin::minmus"],
            Object(prog, prog.int_type("int", 4, True), 47),
        )

    def test_nested_classes(self):
        for kind, tag in (
            ("class", DW_TAG.class_type),
            ("struct", DW_TAG.structure_type),
            ("union", DW_TAG.union_type),
        ):
            with self.subTest(kind=kind):
                prog = dwarf_program(
                    (
                        DwarfDie(
                            tag,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "Foo"),
                                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                            ),
                            (
                                DwarfDie(
                                    tag,
                                    (
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "Bar"),
                                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                                    ),
                                ),
                            ),
                        ),
                        DwarfDie(
                            DW_TAG.subprogram,
                            (DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),),
                        ),
                    ),
                    lang=DW_LANG.C_plus_plus,
                )
                self.assertIdentical(
                    prog.type(kind + " Foo::Bar"),
                    getattr(prog, kind + "_type")("Bar", 0, ()),
                )


class TestProgram(TestCase):
    def test_language(self):
        dies = (
            DwarfDie(
                DW_TAG.subprogram,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7FC3EB9B1C30),
                ),
            ),
            *labeled_int_die,
        )
        self.assertEqual(dwarf_program(()).language, DEFAULT_LANGUAGE)
        self.assertEqual(dwarf_program(dies).language, DEFAULT_LANGUAGE)
        self.assertEqual(dwarf_program(dies, lang=DW_LANG.C).language, Language.C)
        self.assertEqual(
            dwarf_program(dies, lang=DW_LANG.BLISS).language, DEFAULT_LANGUAGE
        )
        self.assertEqual(
            dwarf_program(dies, lang=DW_LANG.C_plus_plus_14).language, Language.CPP
        )

        self.assertEqual(
            dwarf_program(dies, lang=DW_LANG.C_plus_plus).object("main").type_.language,
            Language.CPP,
        )

    def test_reference_counting(self):
        # Test that we keep the appropriate objects alive even if we don't have
        # an explicit reference (e.g., from a temporary variable).
        dies = (
            *labeled_int_die,
            DwarfDie(
                DW_TAG.variable,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                    DwarfAttrib(
                        DW_AT.location,
                        DW_FORM.exprloc,
                        b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                    ),
                ],
            ),
        )
        self.assertEqual(dwarf_program(dies)["x"].address_, 0xFFFFFFFF01020304)
        self.assertEqual(
            dwarf_program(dies)["x"].prog_["x"].address_, 0xFFFFFFFF01020304
        )
        self.assertFalse(dwarf_program(dies)["x"].prog_.flags & ProgramFlags.IS_LIVE)
        self.assertEqual(dwarf_program(dies)["x"].type_.name, "int")

    def test_reference_counting_type_member(self):
        dies = (
            DwarfDie(
                DW_TAG.structure_type,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "foo"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                ),
                (
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "bar"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),
                        ),
                    ),
                ),
            ),
            *labeled_int_die,
        )
        self.assertIsNotNone(repr(dwarf_program(dies).type("struct foo").members[0]))

    def test_reference_counting_type_parameter(self):
        dies = wrap_test_type_dies(
            DwarfDie(
                DW_TAG.subroutine_type,
                (),
                (
                    DwarfDie(
                        DW_TAG.formal_parameter,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, "int_die"),),
                    ),
                ),
            ),
            *labeled_int_die,
        )
        self.assertIsNotNone(repr(dwarf_program(dies).type("TEST").type.parameters[0]))


class TestCompressedDebugSections(TestCase):
    def test_zlib_gnu(self):
        prog = dwarf_program(wrap_test_type_dies(int_die), compress="zlib-gnu")
        self.assertIdentical(prog.type("TEST").type, prog.int_type("int", 4, True))

    def test_zlib_gabi(self):
        prog = dwarf_program(wrap_test_type_dies(int_die), compress="zlib-gabi")
        self.assertIdentical(prog.type("TEST").type, prog.int_type("int", 4, True))


class TestSplitDwarf(TestCase):
    def test_dwo4(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "split.dwo"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.split_compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_id,
                                        DW_FORM.data8,
                                        0xDDEEAADDBBEEFFFF,
                                    ),
                                ),
                                wrap_test_type_dies(int_die),
                            ),
                        ),
                        split="dwo",
                    )
                )
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_id,
                                        DW_FORM.data8,
                                        0xDDEEAADDBBEEFFFF,
                                    ),
                                ),
                            ),
                        )
                    )
                )
            prog.load_debug_info([f.name])
            self.assertIdentical(prog.type("TEST").type, prog.int_type("int", 4, True))

    def test_dwo4_not_found(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_id,
                                        DW_FORM.data8,
                                        0xDDEEAADDBBEEFFFF,
                                    ),
                                ),
                            ),
                        )
                    )
                )
            with self.assertLogs(logging.getLogger("drgn"), "WARNING") as log:
                prog.load_debug_info([f.name])
            self.assertTrue(
                any(
                    "split DWARF file split.dwo not found" in output
                    for output in log.output
                )
            )

    def test_dwo4_id_mismatch(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "split.dwo"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.split_compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_id,
                                        DW_FORM.data8,
                                        0xBBBBBBBB00000000,
                                    ),
                                ),
                            ),
                        ),
                        split="dwo",
                    )
                )
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                    DwarfAttrib(
                                        DW_AT.GNU_dwo_id,
                                        DW_FORM.data8,
                                        0xDDEEAADDBBEEFFFF,
                                    ),
                                ),
                            ),
                        )
                    )
                )
            with self.assertLogs(logging.getLogger("drgn"), "WARNING") as log:
                prog.load_debug_info([f.name])
            self.assertTrue(
                any(
                    "split DWARF file split.dwo not found" in output
                    for output in log.output
                )
            )

    def test_dwo5(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "split.dwo"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.split_compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (),
                                wrap_test_type_dies(int_die),
                            ),
                            dwo_id=0xDDEEAADDBBEEFFFF,
                        ),
                        version=5,
                        split="dwo",
                    )
                )
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                ),
                            ),
                            dwo_id=0xDDEEAADDBBEEFFFF,
                        ),
                        version=5,
                    )
                )
            prog.load_debug_info([f.name])
            self.assertIdentical(prog.type("TEST").type, prog.int_type("int", 4, True))

    def test_dwo5_not_found(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                ),
                            ),
                            dwo_id=0xDDEEAADDBBEEFFFF,
                        ),
                        version=5,
                    )
                )
            with self.assertLogs(logging.getLogger("drgn"), "WARNING") as log:
                prog.load_debug_info([f.name])
            self.assertTrue(
                any(
                    "split DWARF file split.dwo not found" in output
                    for output in log.output
                )
            )

    def test_dwo5_id_mismatch(self):
        prog = Program()
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "split.dwo"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.split_compile,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (),
                                wrap_test_type_dies(int_die),
                            ),
                            dwo_id=0xBBBBBBBB00000000,
                        ),
                        version=5,
                        split="dwo",
                    )
                )
            with open(os.path.join(temp_dir, "skeleton"), "wb") as f:
                f.write(
                    compile_dwarf(
                        DwarfUnit(
                            DW_UT.skeleton,
                            DwarfDie(
                                DW_TAG.compile_unit,
                                (
                                    DwarfAttrib(
                                        DW_AT.dwo_name, DW_FORM.string, "split.dwo"
                                    ),
                                ),
                            ),
                            dwo_id=0xDDEEAADDBBEEFFFF,
                        ),
                        version=5,
                    )
                )
            with self.assertLogs(logging.getLogger("drgn"), "WARNING") as log:
                prog.load_debug_info([f.name])
            self.assertTrue(
                any(
                    "split DWARF file split.dwo not found" in output
                    for output in log.output
                )
            )
