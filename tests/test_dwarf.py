# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os.path
import re
import tempfile
import unittest

from drgn import (
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
from tests import DEFAULT_LANGUAGE, TestCase, identical
from tests.dwarf import DW_AT, DW_ATE, DW_END, DW_FORM, DW_LANG, DW_TAG
from tests.dwarfwriter import DwarfAttrib, DwarfDie, compile_dwarf

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


base_type_dies = (
    bool_die,
    char_die,
    signed_char_die,
    unsigned_char_die,
    short_die,
    unsigned_short_die,
    int_die,
    unsigned_int_die,
    long_die,
    unsigned_long_die,
    long_long_die,
    unsigned_long_long_die,
    float_die,
    double_die,
    long_double_die,
)
base_type_dies += (
    DwarfDie(
        DW_TAG.typedef,
        (
            DwarfAttrib(DW_AT.name, DW_FORM.string, "size_t"),
            DwarfAttrib(
                DW_AT.type, DW_FORM.ref4, base_type_dies.index(unsigned_long_die)
            ),
        ),
    ),
    DwarfDie(
        DW_TAG.typedef,
        (
            DwarfAttrib(DW_AT.name, DW_FORM.string, "ptrdiff_t"),
            DwarfAttrib(DW_AT.type, DW_FORM.ref4, base_type_dies.index(long_die)),
        ),
    ),
)


def dwarf_program(*args, **kwds):
    prog = Program()
    with tempfile.NamedTemporaryFile() as f:
        f.write(compile_dwarf(*args, **kwds))
        f.flush()
        prog.load_debug_info([f.name])
    return prog


def wrap_test_type_dies(dies):
    if isinstance(dies, DwarfDie):
        dies = (dies,)
    return tuple(dies) + (
        DwarfDie(
            DW_TAG.typedef,
            [
                DwarfAttrib(DW_AT.name, DW_FORM.string, "TEST"),
                DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ],
        ),
    )


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
                (
                    DwarfDie(
                        DW_TAG.base_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "int"),
                            DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.int_type("int", 4, True, "big")
        )

    def test_bool_type_byteorder(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.base_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 1),
                            DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.boolean),
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "_Bool"),
                            DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                        ),
                    ),
                ),
            )
        )
        self.assertIdentical(prog.type("TEST").type, prog.bool_type("_Bool", 1, "big"))

    def test_float_type_byteorder(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.base_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.float),
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "float"),
                            DwarfAttrib(DW_AT.endianity, DW_FORM.data1, DW_END.big),
                        ),
                    ),
                ),
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
                (
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
                ),
            )
        )
        self.assertIdentical(prog.type("int"), prog.int_type("int", 4, True, "little"))

    def test_qualifier(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.const_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),)
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST),
        )

    def test_multiple_qualifiers(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.const_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),)
                    ),
                    DwarfDie(
                        DW_TAG.restrict_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                    ),
                    DwarfDie(
                        DW_TAG.volatile_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),),
                    ),
                    DwarfDie(
                        DW_TAG.atomic_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 4),)
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.const_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),)
                    ),
                    DwarfDie(
                        DW_TAG.restrict_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                    ),
                    DwarfDie(
                        DW_TAG.volatile_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),),
                    ),
                    DwarfDie(DW_TAG.atomic_type, ()),
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                ),
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
                ),
            )
        )
        with self.assertRaisesRegex(Exception, "DW_TAG_member has invalid DW_AT_type"):
            prog.type("TEST").type.members[0].type

    def test_struct_member_invalid_location(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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

    def test_struct_invalid_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.structure_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.data1, 0),
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 0),
                    ),
                )
            )
        )
        self.assertRaisesRegex(
            Exception, "DW_TAG_structure_type has invalid DW_AT_name", prog.type, "TEST"
        )

    def test_incomplete_to_complete(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.structure_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
            )
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

    def test_incomplete_to_complete_ambiguous(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.structure_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                    DwarfDie(
                        DW_TAG.structure_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "bar.c"),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 0
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "b"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                        ),
                    ),
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.pointer_type(prog.struct_type("point"))
        )

    def test_incomplete_to_complete_specification(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.structure_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.structure_type,
                        (
                            DwarfAttrib(DW_AT.specification, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
            )
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

    def test_filename(self):
        dies = list(base_type_dies) + [
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "foo.c"),
                ],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(
                                DW_AT.type, DW_FORM.ref4, base_type_dies.index(int_die)
                            ),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(
                                DW_AT.type, DW_FORM.ref4, base_type_dies.index(int_die)
                            ),
                        ],
                    ),
                ],
            ),
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "bar/baz.c"),
                ],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(
                                DW_AT.type, DW_FORM.ref4, base_type_dies.index(int_die)
                            ),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "b"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(
                                DW_AT.type, DW_FORM.ref4, base_type_dies.index(int_die)
                            ),
                        ],
                    ),
                ],
            ),
        ]

        point_type = lambda prog: prog.struct_type(
            "point",
            8,
            (
                TypeMember(prog.int_type("int", 4, True), "x"),
                TypeMember(prog.int_type("int", 4, True), "y", 32),
            ),
        )
        other_point_type = lambda prog: prog.struct_type(
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

        dies[len(base_type_dies)].attribs[-1] = DwarfAttrib(
            DW_AT.decl_file, DW_FORM.udata, "xy/foo.h"
        )
        dies[len(base_type_dies) + 1].attribs[-1] = DwarfAttrib(
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 32),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 44),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                ),
            ),
            int_die,
        )

        for little_endian in [True, False]:
            prog = dwarf_program(wrap_test_type_dies(dies), little_endian=little_endian)
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                                    DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 32),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                    DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                                    DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 44),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "f"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                    float_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 8
                                    ),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.template_value_parameter,
                                (
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                    DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                    unsigned_int_die,
                )
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
                    (
                        DwarfDie(
                            DW_TAG.class_type,
                            (
                                DwarfAttrib(
                                    DW_AT.declaration, DW_FORM.flag_present, True
                                ),
                            ),
                            (
                                DwarfDie(
                                    DW_TAG.template_value_parameter,
                                    (
                                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                        DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                    ),
                                ),
                            ),
                        ),
                        unsigned_int_die,
                    )
                )
            ).type("TEST").type.template_parameters[0].argument

    def test_lazy_cycle(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                        ),
                    ),
                )
            )
        )
        type_ = prog.struct_type(
            "foo", 8, (TypeMember(lambda: prog.pointer_type(type_), "next"),)
        )
        self.assertIdentical(prog.type("TEST").type, type_)

    def test_infinite_cycle(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                DwarfDie(
                    DW_TAG.pointer_type,
                    (
                        DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    ),
                )
            )
        )
        self.assertRaisesRegex(Exception, "maximum.*depth exceeded", prog.type, "TEST")

    def test_enum(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                    unsigned_int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
                    unsigned_int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                    ),
                    unsigned_int_die,
                )
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
                ),
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
                ),
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
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                    ),
                    float_die,
                )
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

    def test_enum_invalid_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                    ),
                    unsigned_int_die,
                )
            )
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumeration_type has invalid DW_AT_name",
            prog.type,
            "TEST",
        )

    def test_enum_enumerator_missing_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.enumerator,
                                (DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    unsigned_int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.enumerator,
                                (DwarfAttrib(DW_AT.name, DW_FORM.string, "FOO"),),
                            ),
                        ),
                    ),
                    unsigned_int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.enumeration_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.enumerator,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "FOO"),
                                    DwarfAttrib(
                                        DW_AT.const_value, DW_FORM.string, "FOO"
                                    ),
                                ),
                            ),
                        ),
                    ),
                    unsigned_int_die,
                )
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
            base_type_dies
            + (
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
                                    base_type_dies.index(int_die),
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
                                    base_type_dies.index(int_die),
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
                                    base_type_dies.index(int_die),
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
                                    base_type_dies.index(float_die),
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
                            base_type_dies.index(unsigned_int_die),
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
                (
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "INT"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.typedef_type("INT", prog.int_type("int", 4, True)),
        )

    def test_typedef_missing_name(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.typedef, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),)
                    ),
                    int_die,
                )
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
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    ),
                ),
                int_die,
            )
        )
        self.assertIdentical(
            prog.type("pid_t"),
            prog.typedef_type("pid_t", prog.int_type("int", 4, True)),
        )

    def test_pointer(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.pointer_type,
                        (
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                        ),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
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
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 2)
        )

    def test_array_two_dimensional(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
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
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 3), 2),
        )

    def test_array_three_dimensional(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
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
                    int_die,
                )
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
                (
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
        )
        self.assertRaisesRegex(
            Exception, "DW_TAG_array_type is missing DW_AT_type", prog.type, "TEST"
        )

    def test_array_zero_length_count(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 0)
        )

    def test_array_zero_length_upper_bound(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.upper_bound, DW_FORM.sdata, -1),),
                            ),
                        ),
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True), 0)
        )

    def test_incomplete_array_no_subrange(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),)
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True))
        )

    def test_incomplete_array_empty_subrange(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type, prog.array_type(prog.int_type("int", 4, True))
        )

    def test_incomplete_array_of_array(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                # int [3][]
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(DW_TAG.subrange_type, ()),
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
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
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                            ),
                            DwarfDie(DW_TAG.subrange_type, ()),
                        ),
                    ),
                    int_die,
                )
            )
        )
        self.assertIdentical(
            prog.type("TEST").type,
            prog.array_type(prog.array_type(prog.int_type("int", 4, True), 0), 3),
        )

    def test_array_of_zero_length_array_typedef(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    # ZARRAY [3]
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                            ),
                        ),
                    ),
                    # typedef int ZARRAY[0];
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
                    # ZARRAY [3]
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 3),),
                            ),
                        ),
                    ),
                    # typedef int ZARRAY[0];
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),)
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                    DwarfAttrib(
                                        DW_AT.data_member_location, DW_FORM.data1, 4
                                    ),
                                ),
                            ),
                        ),
                    ),
                    # typedef int FARRAY[];
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "FARRAY"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),)
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.const_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),)
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
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
                (
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
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    # typedef int ZARRAY[0];
                    DwarfDie(
                        DW_TAG.typedef,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),)
                    ),
                    int_die,
                )
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                ),
            ),
            # typedef int ZARRAY[0];
            DwarfDie(
                DW_TAG.typedef,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                ),
            ),
            DwarfDie(DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),)),
            int_die,
        )

        prog = dwarf_program(wrap_test_type_dies(dies))
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
        prog = dwarf_program(wrap_test_type_dies(dies))
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.structure_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.union_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (
                            DwarfDie(
                                DW_TAG.subrange_type,
                                (DwarfAttrib(DW_AT.count, DW_FORM.data1, 0),),
                            ),
                        ),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.union_type,
                        (DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),),
                        (
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                ),
                            ),
                            DwarfDie(
                                DW_TAG.member,
                                (
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                                ),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                        (DwarfDie(DW_TAG.subrange_type, ()),),
                    ),
                    int_die,
                )
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
        prog = dwarf_program(base_type_dies, bits=32)
        self.assertIdentical(
            prog.type("int *"), prog.pointer_type(prog.int_type("int", 4, True), 4)
        )

    def test_function_no_parameters(self):
        # int foo(void)
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.formal_parameter,
                                (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                            ),
                        ),
                    ),
                    int_die,
                    char_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.formal_parameter,
                                (
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "c"),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                    char_die,
                )
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

    def test_function_unspecified_parameters(self):
        # int foo()
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (DwarfDie(DW_TAG.unspecified_parameters, ()),),
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(
                                DW_TAG.formal_parameter,
                                (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),),
                            ),
                            DwarfDie(DW_TAG.unspecified_parameters, ()),
                        ),
                    ),
                    int_die,
                    char_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (),
                        (
                            DwarfDie(
                                DW_TAG.formal_parameter,
                                (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                            ),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.array_type, (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),)
                    ),
                    int_die,
                )
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
                (
                    DwarfDie(
                        DW_TAG.subroutine_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        (
                            DwarfDie(DW_TAG.unspecified_parameters, ()),
                            DwarfDie(
                                DW_TAG.template_type_parameter,
                                (DwarfAttrib(DW_AT.name, DW_FORM.string, "T"),),
                            ),
                            DwarfDie(
                                DW_TAG.template_value_parameter,
                                (
                                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                                    DwarfAttrib(DW_AT.name, DW_FORM.string, "N"),
                                    DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                                ),
                            ),
                        ),
                    ),
                    int_die,
                    unsigned_int_die,
                )
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


class TestObjects(TestCase):
    def test_constant_signed_enum(self):
        prog = dwarf_program(
            (
                int_die,
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                unsigned_int_die,
                DwarfDie(
                    DW_TAG.enumeration_type,
                    (
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.subprogram,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "abs"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                            DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7FC3EB9B1C30),
                        ),
                        (
                            DwarfDie(
                                DW_TAG.formal_parameter,
                                (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),),
                            ),
                        ),
                    ),
                )
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
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                            DwarfAttrib(
                                DW_AT.location,
                                DW_FORM.exprloc,
                                b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                            ),
                        ),
                    ),
                )
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

    def test_variable_no_address(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                        ),
                    ),
                )
            )
        )
        self.assertIdentical(prog.object("x"), Object(prog, "int"))

    def test_variable_unimplemented_location(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                            DwarfAttrib(DW_AT.location, DW_FORM.exprloc, b"\xe0"),
                        ),
                    ),
                )
            )
        )
        self.assertRaisesRegex(Exception, "unimplemented operation", prog.object, "x")

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
                    (
                        int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                                DwarfAttrib(DW_AT.const_value, form, 1),
                            ),
                        ),
                    )
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
                    (
                        unsigned_int_die,
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                                DwarfAttrib(DW_AT.const_value, form, 1),
                            ),
                        ),
                    )
                )
            )
            self.assertIdentical(
                prog["x"], Object(prog, prog.int_type("unsigned int", 4, False), 1)
            )

    def test_variable_const_block(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),),
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(
                                DW_AT.const_value,
                                DW_FORM.block1,
                                b"\x01\x00\x00\x00\x02\x00\x00\x00",
                            ),
                        ),
                    ),
                )
            )
        )
        self.assertIdentical(
            prog["p"],
            Object(prog, prog.array_type(prog.int_type("int", 4, True), 2), [1, 2]),
        )

    def test_variable_const_block_too_small(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.array_type,
                        (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),),
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(
                                DW_AT.const_value,
                                DW_FORM.block1,
                                b"\x01\x00\x00\x00\x02\x00\x00",
                            ),
                        ),
                    ),
                )
            )
        )
        self.assertRaisesRegex(Exception, "too small", prog.variable, "p")

    def test_specification(self):
        prog = dwarf_program(
            wrap_test_type_dies(
                (
                    int_die,
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                        ),
                    ),
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.specification, DW_FORM.ref4, 1),
                            DwarfAttrib(
                                DW_AT.location,
                                DW_FORM.exprloc,
                                b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                            ),
                        ),
                    ),
                )
            )
        )

        self.assertIdentical(
            prog["x"],
            Object(prog, prog.int_type("int", 4, True), address=0xFFFFFFFF01020304),
        )

    def test_namespace_reverse_specification(self):
        """Test specification inside namespace while declaration is outside of it."""
        dies = (
            int_die,
            DwarfDie(
                DW_TAG.namespace,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),
                    DwarfAttrib(DW_AT.sibling, DW_FORM.ref4, 2),
                ],
                [
                    DwarfDie(
                        DW_TAG.variable,
                        (
                            DwarfAttrib(DW_AT.specification, DW_FORM.ref4, 2),
                            DwarfAttrib(
                                DW_AT.location,
                                DW_FORM.exprloc,
                                b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                            ),
                        ),
                    )
                ],
            ),
            DwarfDie(
                DW_TAG.variable,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                ),
            ),
        )

        prog = dwarf_program(dies)
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
                int_die,
                DwarfDie(
                    DW_TAG.variable,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                        DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                    (
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                int_die,
                DwarfDie(
                    DW_TAG.namespace,
                    (DwarfAttrib(DW_AT.name, DW_FORM.string, "moho"),),
                    (
                        DwarfDie(
                            DW_TAG.variable,
                            (
                                DwarfAttrib(DW_AT.name, DW_FORM.string, "target"),
                                DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                int_die,
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
                                                    DW_AT.type, DW_FORM.ref4, 0
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


class TestProgram(TestCase):
    def test_language(self):
        dies = (
            DwarfDie(
                DW_TAG.subprogram,
                (
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "main"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7FC3EB9B1C30),
                ),
            ),
            int_die,
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
            int_die,
            DwarfDie(
                DW_TAG.variable,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ),
                    ),
                ),
            ),
            int_die,
        )
        self.assertIsNotNone(repr(dwarf_program(dies).type("struct foo").members[0]))

    def test_reference_counting_type_parameter(self):
        dies = wrap_test_type_dies(
            (
                DwarfDie(
                    DW_TAG.subroutine_type,
                    (),
                    (
                        DwarfDie(
                            DW_TAG.formal_parameter,
                            (DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),),
                        ),
                    ),
                ),
                int_die,
            )
        )
        self.assertIsNotNone(repr(dwarf_program(dies).type("TEST").type.parameters[0]))
