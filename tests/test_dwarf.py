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
    array_type,
    class_type,
    complex_type,
    enum_type,
    float_type,
    function_type,
    int_type,
    pointer_type,
    struct_type,
    typedef_type,
    union_type,
    void_type,
)
from tests import (
    DEFAULT_LANGUAGE,
    ObjectTestCase,
    color_type,
    coord_type,
    option_type,
    pid_type,
    point_type,
)
from tests.dwarf import DW_AT, DW_ATE, DW_FORM, DW_LANG, DW_TAG
from tests.dwarfwriter import compile_dwarf, DwarfDie, DwarfAttrib


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


class TestTypes(unittest.TestCase):
    @staticmethod
    def type_from_dwarf(dies, *args, **kwds):
        if isinstance(dies, DwarfDie):
            dies = (dies,)
        dies = tuple(dies) + (
            DwarfDie(
                DW_TAG.typedef,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "__TEST__"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                ],
            ),
        )
        prog = dwarf_program(dies, *args, **kwds)
        return prog.type("__TEST__").type

    def assertFromDwarf(self, dies, type, *args, **kwds):
        self.assertEqual(self.type_from_dwarf(dies, *args, **kwds), type)

    def test_unknown_tag(self):
        die = DwarfDie(0x9999, ())
        self.assertRaisesRegex(
            Exception, "unknown DWARF type tag 0x9999", self.type_from_dwarf, die
        )

    def test_bad_base_type(self):
        die = DwarfDie(
            DW_TAG.base_type,
            [
                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.signed),
                DwarfAttrib(DW_AT.name, DW_FORM.string, "bad egg"),
            ],
        )

        byte_size = die.attribs.pop(0)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_byte_size",
            self.type_from_dwarf,
            die,
        )
        die.attribs.insert(0, byte_size)

        encoding = die.attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_encoding",
            self.type_from_dwarf,
            die,
        )
        die.attribs.insert(1, encoding)

        del die.attribs[2]
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_base_type has missing or invalid DW_AT_name",
            self.type_from_dwarf,
            die,
        )

    def test_complex(self):
        dies = [
            DwarfDie(
                DW_TAG.base_type,
                (
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 16),
                    DwarfAttrib(DW_AT.encoding, DW_FORM.data1, DW_ATE.complex_float),
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "double _Complex"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                ),
            ),
            double_die,
        ]
        self.assertFromDwarf(
            dies, complex_type("double _Complex", 16, float_type("double", 8))
        )

    def test_unknown_base_type_encoding(self):
        die = DwarfDie(
            DW_TAG.base_type,
            (
                DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                DwarfAttrib(DW_AT.encoding, DW_FORM.data1, 99),
                DwarfAttrib(DW_AT.name, DW_FORM.string, "magic int"),
            ),
        )
        self.assertRaisesRegex(
            Exception, "unknown DWARF encoding", self.type_from_dwarf, die
        )

    def test_qualifiers(self):
        dies = [
            DwarfDie(DW_TAG.const_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],),
            int_die,
        ]
        self.assertFromDwarf(dies, int_type("int", 4, True, Qualifiers.CONST))

        del dies[0].attribs[0]
        self.assertFromDwarf(dies, void_type(Qualifiers.CONST))

        dies = [
            DwarfDie(DW_TAG.const_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],),
            DwarfDie(DW_TAG.restrict_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],),
            DwarfDie(DW_TAG.volatile_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3)],),
            DwarfDie(DW_TAG.atomic_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 4)],),
            int_die,
        ]
        self.assertFromDwarf(
            dies,
            int_type(
                "int",
                4,
                True,
                Qualifiers.CONST
                | Qualifiers.RESTRICT
                | Qualifiers.VOLATILE
                | Qualifiers.ATOMIC,
            ),
        )

        del dies[3].attribs[0]
        self.assertFromDwarf(
            dies,
            void_type(
                Qualifiers.CONST
                | Qualifiers.RESTRICT
                | Qualifiers.VOLATILE
                | Qualifiers.ATOMIC
            ),
        )

    def test_struct(self):
        dies = [
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
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            int_die,
        ]

        self.assertFromDwarf(dies, point_type)

        tag = dies[0].attribs.pop(0)
        self.assertFromDwarf(
            dies, struct_type(None, point_type.size, point_type.members)
        )
        dies[0].attribs.insert(0, tag)

        children = list(dies[0].children)
        dies[0].children.clear()
        self.assertFromDwarf(dies, struct_type("point", point_type.size, ()))
        size = dies[0].attribs.pop(1)
        dies[0].attribs.append(
            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True)
        )
        self.assertFromDwarf(dies, struct_type("point"))
        del dies[0].attribs[-1]
        dies[0].attribs.insert(1, size)
        dies[0].children.extend(children)

        name = dies[0].children[0].attribs.pop(0)
        self.assertFromDwarf(
            dies,
            struct_type(
                "point",
                point_type.size,
                (
                    TypeMember(int_type("int", 4, True), None, 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        dies[0].children[0].attribs.insert(0, name)

        tag = dies[0].attribs.pop(0)
        dies[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_structure_type has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs[0] = tag

        size = dies[0].attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_structure_type has missing or invalid DW_AT_byte_size",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs.insert(1, size)

        name = dies[0].children[0].attribs.pop(0)
        dies[0].children[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[0] = name

        location = dies[0].children[0].attribs[1]
        dies[0].children[0].attribs[1] = DwarfAttrib(
            DW_AT.data_member_location, DW_FORM.string, "foo"
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_data_member_location",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[1] = location

        type_ = dies[0].children[0].attribs.pop(2)
        self.assertRaisesRegex(
            Exception, "DW_TAG_member is missing DW_AT_type", self.type_from_dwarf, dies
        )
        dies[0].children[0].attribs.insert(
            2, DwarfAttrib(DW_AT.type, DW_FORM.string, "foo")
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_type",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[2] = type_

    def test_incomplete_to_complete(self):
        dies = [
            DwarfDie(
                DW_TAG.pointer_type,
                [
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                ],
            ),
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True),
                ],
            ),
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                        ],
                    ),
                ],
            ),
            int_die,
        ]
        self.assertFromDwarf(dies, pointer_type(8, point_type))

        # Ambiguous incomplete type.
        dies.append(
            DwarfDie(
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "point"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.decl_file, DW_FORM.udata, "bar.c"),
                ],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "b"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                        ],
                    ),
                ],
            )
        )
        type_ = pointer_type(8, struct_type("point"))
        self.assertFromDwarf(dies, type_)

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

        other_point_type = struct_type(
            "point",
            8,
            (
                TypeMember(int_type("int", 4, True), "a"),
                TypeMember(int_type("int", 4, True), "b", 32),
            ),
        )

        prog = dwarf_program(dies)
        for dir in ["", "src", "usr/src", "/usr/src"]:
            with self.subTest(dir=dir):
                self.assertEqual(
                    prog.type("struct point", os.path.join(dir, "foo.c")), point_type
                )
        for dir in ["", "bar", "src/bar", "usr/src/bar", "/usr/src/bar"]:
            with self.subTest(dir=dir):
                self.assertEqual(
                    prog.type("struct point", os.path.join(dir, "baz.c")),
                    other_point_type,
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
                self.assertEqual(
                    prog.type("struct point", os.path.join(dir, "foo.h")), point_type
                )
        for dir in ["ab", "include/ab", "usr/include/ab", "/usr/include/ab"]:
            with self.subTest(dir=dir):
                self.assertEqual(
                    prog.type("struct point", os.path.join(dir, "foo.h")),
                    other_point_type,
                )
        for filename in [None, "foo.h"]:
            with self.subTest(filename=filename):
                self.assertIn(
                    prog.type("struct point", filename), (point_type, other_point_type)
                )

    def test_bit_field(self):
        dies = [
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
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 12),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 32),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                            DwarfAttrib(DW_AT.bit_size, DW_FORM.data1, 20),
                            DwarfAttrib(DW_AT.data_bit_offset, DW_FORM.data1, 44),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            int_die,
        ]

        t = struct_type(
            "point",
            8,
            [
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 32, 12),
                TypeMember(int_type("int", 4, True), "z", 44, 20),
            ],
        )

        # With DW_AT_data_bit_offset.
        self.assertFromDwarf(dies, t, little_endian=True)
        self.assertFromDwarf(dies, t, little_endian=False)

        # With DW_AT_bit_offset on big-endian.
        dies[0].children[1].attribs[2] = DwarfAttrib(
            DW_AT.bit_offset, DW_FORM.data1, 32
        )
        dies[0].children[2].attribs[2] = DwarfAttrib(
            DW_AT.bit_offset, DW_FORM.data1, 44
        )
        self.assertFromDwarf(dies, t, little_endian=False)

        # With DW_AT_data_member_location and DW_AT_bit_offset on big-endian.
        dies[0].children[1].attribs.append(
            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4)
        )
        dies[0].children[1].attribs[2] = DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 0)
        dies[0].children[2].attribs.append(
            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4)
        )
        dies[0].children[2].attribs[2] = DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 4)

        # With DW_AT_data_member_location and DW_AT_bit_offset on little-endian.
        dies[0].children[1].attribs[2] = DwarfAttrib(
            DW_AT.bit_offset, DW_FORM.data1, 20
        )
        dies[0].children[2].attribs[2] = DwarfAttrib(DW_AT.bit_offset, DW_FORM.data1, 0)
        self.assertFromDwarf(dies, t, little_endian=True)

        # With DW_AT_data_member_location, DW_AT_bit_offset, and
        # DW_AT_byte_size on little-endian.
        dies[0].children[1].attribs.append(
            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4)
        )
        dies[0].children[2].attribs.append(
            DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4)
        )
        self.assertFromDwarf(dies, t, little_endian=True)

    def test_union(self):
        dies = [
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
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "f"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ],
                    ),
                ],
            ),
            int_die,
            float_die,
        ]

        self.assertFromDwarf(dies, option_type)

        tag = dies[0].attribs.pop(0)
        dies[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_union_type has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs[0] = tag

        size = dies[0].attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_union_type has missing or invalid DW_AT_byte_size",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs.insert(1, size)

    def test_class(self):
        dies = [
            DwarfDie(
                DW_TAG.class_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "coord"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 12),
                ],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "x"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "y"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "z"),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 8),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            int_die,
        ]

        self.assertFromDwarf(dies, coord_type)

        tag = dies[0].attribs.pop(0)
        self.assertFromDwarf(
            dies, class_type(None, coord_type.size, coord_type.members)
        )
        dies[0].attribs.insert(0, tag)

        children = list(dies[0].children)
        dies[0].children.clear()
        self.assertFromDwarf(dies, class_type("coord", coord_type.size, ()))
        size = dies[0].attribs.pop(1)
        dies[0].attribs.append(
            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True)
        )
        self.assertFromDwarf(dies, class_type("coord"))
        del dies[0].attribs[-1]
        dies[0].attribs.insert(1, size)
        dies[0].children.extend(children)

        name = dies[0].children[0].attribs.pop(0)
        self.assertFromDwarf(
            dies,
            class_type(
                "coord",
                coord_type.size,
                (
                    TypeMember(int_type("int", 4, True), None, 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        dies[0].children[0].attribs.insert(0, name)

        tag = dies[0].attribs.pop(0)
        dies[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_class_type has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs[0] = tag

        size = dies[0].attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_class_type has missing or invalid DW_AT_byte_size",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs.insert(1, size)

        name = dies[0].children[0].attribs.pop(0)
        dies[0].children[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[0] = name

        location = dies[0].children[0].attribs[1]
        dies[0].children[0].attribs[1] = DwarfAttrib(
            DW_AT.data_member_location, DW_FORM.string, "foo"
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_data_member_location",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[1] = location

        type_ = dies[0].children[0].attribs.pop(2)
        self.assertRaisesRegex(
            Exception, "DW_TAG_member is missing DW_AT_type", self.type_from_dwarf, dies
        )
        dies[0].children[0].attribs.insert(
            2, DwarfAttrib(DW_AT.type, DW_FORM.string, "foo")
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_member has invalid DW_AT_type",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[2] = type_

    def test_lazy_cycle(self):
        dies = [
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
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 0),
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
        ]

        type_ = struct_type(
            "foo", 8, (TypeMember(lambda: pointer_type(8, type_), "next"),)
        )
        self.assertFromDwarf(dies, type_)

    def test_infinite_cycle(self):
        dies = [
            DwarfDie(
                DW_TAG.pointer_type,
                [
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 8),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                ],
            ),
        ]
        self.assertRaisesRegex(
            Exception, "maximum.*depth exceeded", self.type_from_dwarf, dies
        )

    def test_enum(self):
        dies = [
            DwarfDie(
                DW_TAG.enumeration_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
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
            unsigned_int_die,
            double_die,
        ]

        self.assertFromDwarf(dies, color_type)

        tag = dies[0].attribs.pop(0)
        self.assertFromDwarf(
            dies, enum_type(None, color_type.type, color_type.enumerators)
        )
        dies[0].attribs.insert(0, tag)

        children = list(dies[0].children)
        dies[0].children.clear()
        self.assertFromDwarf(dies, enum_type("color", color_type.type, ()))
        type_ = dies[0].attribs.pop(1)
        dies[0].attribs.append(
            DwarfAttrib(DW_AT.declaration, DW_FORM.flag_present, True)
        )
        self.assertFromDwarf(dies, enum_type("color"))
        del dies[0].attribs[-1]
        dies[0].attribs.insert(1, type_)
        dies[0].children.extend(children)

        # A la GCC before 5.1.
        del dies[0].attribs[1]
        self.assertFromDwarf(
            dies,
            enum_type("color", int_type("<unknown>", 4, False), color_type.enumerators),
        )
        for i, child in enumerate(dies[0].children):
            child.attribs[1] = DwarfAttrib(DW_AT.const_value, DW_FORM.sdata, -i)
        self.assertFromDwarf(
            dies,
            enum_type(
                "color",
                int_type("<unknown>", 4, True),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", -1),
                    TypeEnumerator("BLUE", -2),
                ),
            ),
        )

        dies[0].attribs.insert(1, DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2))
        self.assertRaisesRegex(
            Exception,
            "DW_AT_type of DW_TAG_enumeration_type is not an integer type",
            self.type_from_dwarf,
            dies,
        )
        del dies[0].attribs[1]

        size = dies[0].attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumeration_type has missing or invalid DW_AT_byte_size",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs.insert(1, size)

        tag = dies[0].attribs.pop(0)
        dies[0].attribs.insert(0, DwarfAttrib(DW_AT.name, DW_FORM.data1, 0))
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumeration_type has invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].attribs[0] = tag

        name = dies[0].children[0].attribs.pop(0)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator has missing or invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs.insert(0, name)

        const_value = dies[0].children[0].attribs.pop(1)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator is missing DW_AT_const_value",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs.insert(
            1, DwarfAttrib(DW_AT.const_value, DW_FORM.string, "asdf")
        )
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_enumerator has invalid DW_AT_const_value",
            self.type_from_dwarf,
            dies,
        )
        dies[0].children[0].attribs[1] = const_value

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

        self.assertEqual(prog.type("struct point"), point_type)
        self.assertRaisesRegex(LookupError, "could not find", prog.type, "union point")
        self.assertEqual(prog.type("union option"), option_type)
        self.assertRaisesRegex(
            LookupError, "could not find", prog.type, "struct option"
        )
        self.assertEqual(prog.type("enum color"), color_type)
        self.assertRaisesRegex(LookupError, "could not find", prog.type, "struct color")

    def test_typedef(self):
        dies = [
            DwarfDie(
                DW_TAG.typedef,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "INT"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                ],
            ),
            int_die,
        ]
        self.assertFromDwarf(dies, typedef_type("INT", int_type("int", 4, True)))

        dies[0].attribs.pop(0)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_typedef has missing or invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )

    def test_void_typedef(self):
        dies = [
            DwarfDie(
                DW_TAG.typedef, [DwarfAttrib(DW_AT.name, DW_FORM.string, "VOID"),],
            ),
        ]
        self.assertFromDwarf(dies, typedef_type("VOID", void_type()))

        dies[0].attribs.pop(0)
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_typedef has missing or invalid DW_AT_name",
            self.type_from_dwarf,
            dies,
        )

    def test_typedef_by_name(self):
        prog = dwarf_program(
            base_type_dies
            + (
                DwarfDie(
                    DW_TAG.typedef,
                    (
                        DwarfAttrib(DW_AT.name, DW_FORM.string, "pid_t"),
                        DwarfAttrib(
                            DW_AT.type, DW_FORM.ref4, base_type_dies.index(int_die)
                        ),
                    ),
                ),
            )
        )
        self.assertEqual(prog.type("pid_t"), pid_type)

    def test_pointer(self):
        dies = [
            DwarfDie(DW_TAG.pointer_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),],),
            int_die,
        ]
        self.assertFromDwarf(dies, pointer_type(8, int_type("int", 4, True)))

        del dies[0].attribs[0]
        self.assertFromDwarf(dies, pointer_type(8, void_type()))

    def test_array(self):
        dies = [
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.upper_bound, DW_FORM.data1, 1)],
                    ),
                ],
            ),
            int_die,
        ]
        self.assertFromDwarf(dies, array_type(2, int_type("int", 4, True)))

        dies[0].children.append(
            DwarfDie(
                DW_TAG.subrange_type, [DwarfAttrib(DW_AT.count, DW_FORM.data1, 3)]
            ),
        )
        self.assertFromDwarf(
            dies, array_type(2, array_type(3, int_type("int", 4, True)))
        )

        dies[0].children.append(
            DwarfDie(
                DW_TAG.subrange_type, [DwarfAttrib(DW_AT.count, DW_FORM.data1, 4)]
            ),
        )
        self.assertFromDwarf(
            dies, array_type(2, array_type(3, array_type(4, int_type("int", 4, True))))
        )

        del dies[0].attribs[0]
        self.assertRaisesRegex(
            Exception,
            "DW_TAG_array_type is missing DW_AT_type",
            self.type_from_dwarf,
            dies,
        )

    def test_zero_length_array(self):
        dies = [
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]
        self.assertFromDwarf(dies, array_type(0, int_type("int", 4, True)))

        dies[0].children[0].attribs[0] = DwarfAttrib(
            DW_AT.upper_bound, DW_FORM.sdata, -1
        )
        self.assertFromDwarf(dies, array_type(0, int_type("int", 4, True)))

    def test_incomplete_array(self):
        dies = [
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [DwarfDie(DW_TAG.subrange_type, [])],
            ),
            int_die,
        ]
        self.assertFromDwarf(dies, array_type(None, int_type("int", 4, True)))

        del dies[0].children[0]
        self.assertFromDwarf(dies, array_type(None, int_type("int", 4, True)))

    def test_incomplete_array_of_array(self):
        # int [3][]
        dies = [
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(DW_TAG.subrange_type, []),
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 3)],
                    ),
                ],
            ),
            int_die,
        ]
        self.assertFromDwarf(
            dies, array_type(None, array_type(3, int_type("int", 4, True)))
        )

    def test_array_of_zero_length_array(self):
        # int [3][0]
        dies = [
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 3)],
                    ),
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]

        type_ = array_type(3, array_type(0, int_type("int", 4, True)))
        self.assertFromDwarf(dies, type_)

        # GCC < 9.0.
        del dies[0].children[1].attribs[0]
        self.assertFromDwarf(dies, type_)

    def test_array_of_zero_length_array_typedef(self):
        dies = [
            # ZARRAY [3]
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 3)],
                    ),
                ],
            ),
            # typedef int ZARRAY[0];
            DwarfDie(
                DW_TAG.typedef,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                ],
            ),
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]

        type_ = array_type(
            3, typedef_type("ZARRAY", array_type(0, int_type("int", 4, True)))
        )
        self.assertFromDwarf(dies, type_)

        # GCC actually squashes arrays of typedef arrays into one array type,
        # but let's handle it like GCC < 9.0 anyways.
        del dies[2].children[0]
        self.assertFromDwarf(dies, type_)

    def test_flexible_array_member(self):
        # struct {
        #   int i;
        #   int a[];
        # };
        dies = [
            DwarfDie(
                DW_TAG.structure_type,
                [DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                        ],
                    ),
                ],
            ),
            DwarfDie(DW_TAG.array_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],),
            int_die,
        ]

        self.assertFromDwarf(
            dies,
            struct_type(
                None,
                4,
                (
                    TypeMember(int_type("int", 4, True), "i"),
                    TypeMember(array_type(None, int_type("int", 4, True)), "a", 32),
                ),
            ),
        )

    def test_typedef_flexible_array_member(self):
        dies = [
            # struct {
            #   int i;
            #   FARRAY a;
            # };
            DwarfDie(
                DW_TAG.structure_type,
                [DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                            DwarfAttrib(DW_AT.data_member_location, DW_FORM.data1, 4),
                        ],
                    ),
                ],
            ),
            # typedef int FARRAY[];
            DwarfDie(
                DW_TAG.typedef,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "FARRAY"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                ],
            ),
            DwarfDie(DW_TAG.array_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3)],),
            int_die,
        ]

        self.assertFromDwarf(
            dies,
            struct_type(
                None,
                4,
                (
                    TypeMember(int_type("int", 4, True), "i"),
                    TypeMember(
                        typedef_type(
                            "FARRAY", array_type(None, int_type("int", 4, True))
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
        dies = [
            DwarfDie(
                DW_TAG.structure_type,
                [DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]

        type_ = struct_type(
            None, 4, (TypeMember(array_type(0, int_type("int", 4, True)), "a"),)
        )
        self.assertFromDwarf(dies, type_)

        # GCC < 9.0.
        del dies[1].children[0].attribs[0]
        self.assertFromDwarf(dies, type_)

    def test_typedef_zero_length_array_only_member(self):
        dies = [
            DwarfDie(
                # struct foo {
                #   ZARRAY a;
                # };
                DW_TAG.structure_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "foo"),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                ],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            # typedef int ZARRAY[0];
            DwarfDie(
                DW_TAG.typedef,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "ZARRAY"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                ],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            DwarfDie(DW_TAG.array_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 3)],),
            int_die,
        ]

        type_ = struct_type(
            "foo",
            4,
            (
                TypeMember(
                    typedef_type("ZARRAY", array_type(0, int_type("int", 4, True))), "a"
                ),
            ),
        )
        self.assertFromDwarf(dies, type_)

        farray_zarray = typedef_type(
            "ZARRAY", array_type(None, int_type("int", 4, True))
        )

        # GCC < 9.0.
        del dies[1].children[0]
        prog = dwarf_program(dies)
        self.assertEqual(prog.type("struct foo"), type_)
        # Although the ZARRAY type must be a zero-length array in the context
        # of the structure, it could still be an incomplete array if used
        # elsewhere.
        self.assertEqual(prog.type("ZARRAY"), farray_zarray)

        # Make sure it still works if we parse the array type first.
        prog = dwarf_program(dies)
        self.assertEqual(prog.type("ZARRAY"), farray_zarray)
        self.assertEqual(prog.type("struct foo"), type_)

    def test_zero_length_array_not_last_member(self):
        # struct {
        #   int a[0];
        #   int i;
        # };
        dies = [
            DwarfDie(
                DW_TAG.structure_type,
                [DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ],
                    ),
                ],
            ),
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]

        type_ = struct_type(
            None,
            4,
            (
                TypeMember(array_type(0, int_type("int", 4, True)), "a"),
                TypeMember(int_type("int", 4, True), "i"),
            ),
        )
        self.assertFromDwarf(dies, type_)

        # GCC < 9.0.
        del dies[1].children[0].attribs[0]
        self.assertFromDwarf(dies, type_)

    def test_zero_length_array_in_union(self):
        # union {
        #   int i;
        #   int a[0];
        # };
        dies = [
            DwarfDie(
                DW_TAG.union_type,
                [DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),],
                [
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "i"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2),
                        ],
                    ),
                    DwarfDie(
                        DW_TAG.member,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, "a"),
                            DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1),
                        ],
                    ),
                ],
            ),
            DwarfDie(
                DW_TAG.array_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],
                [
                    DwarfDie(
                        DW_TAG.subrange_type,
                        [DwarfAttrib(DW_AT.count, DW_FORM.data1, 0)],
                    ),
                ],
            ),
            int_die,
        ]

        type_ = union_type(
            None,
            4,
            (
                TypeMember(int_type("int", 4, True), "i"),
                TypeMember(array_type(0, int_type("int", 4, True)), "a"),
            ),
        )
        self.assertFromDwarf(dies, type_)

        # GCC < 9.0.
        del dies[1].children[0].attribs[0]
        self.assertFromDwarf(dies, type_)

    def test_pointer_size(self):
        prog = dwarf_program(base_type_dies, bits=32)
        self.assertEqual(prog.type("int *"), pointer_type(4, int_type("int", 4, True)))

    def test_function(self):
        # int foo(char)
        dies = [
            DwarfDie(
                DW_TAG.subroutine_type,
                [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                [
                    DwarfDie(
                        DW_TAG.formal_parameter,
                        [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],
                    ),
                ],
            ),
            int_die,
            char_die,
        ]
        self.assertFromDwarf(
            dies,
            function_type(
                int_type("int", 4, True),
                (TypeParameter(int_type("char", 1, True)),),
                False,
            ),
        )

        # int foo(char c)
        dies[0].children[0].attribs.append(DwarfAttrib(DW_AT.name, DW_FORM.string, "c"))
        self.assertFromDwarf(
            dies,
            function_type(
                int_type("int", 4, True),
                (TypeParameter(int_type("char", 1, True), "c"),),
                False,
            ),
        )

        # int foo(char, ...)
        del dies[0].children[0].attribs[-1]
        dies[0].children.append(DwarfDie(DW_TAG.unspecified_parameters, []))
        self.assertFromDwarf(
            dies,
            function_type(
                int_type("int", 4, True),
                (TypeParameter(int_type("char", 1, True)),),
                True,
            ),
        )

        # int foo()
        del dies[0].children[0]
        self.assertFromDwarf(dies, function_type(int_type("int", 4, True), (), True))

        # int foo(void)
        del dies[0].children[0]
        self.assertFromDwarf(dies, function_type(int_type("int", 4, True), (), False))

        # void foo(void)
        del dies[0].attribs[0]
        self.assertFromDwarf(dies, function_type(void_type(), (), False))

    def test_incomplete_array_parameter(self):
        # void foo(int [])
        # Note that in C, this is equivalent to void foo(int *), so GCC and
        # Clang emit the DWARF for the latter.
        dies = [
            DwarfDie(
                DW_TAG.subroutine_type,
                [],
                [
                    DwarfDie(
                        DW_TAG.formal_parameter,
                        [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 1)],
                    ),
                ],
            ),
            DwarfDie(DW_TAG.array_type, [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 2)],),
            int_die,
        ]
        self.assertFromDwarf(
            dies,
            function_type(
                void_type(),
                (TypeParameter(array_type(None, int_type("int", 4, True))),),
                False,
            ),
        )

    def test_language(self):
        for name, lang in DW_LANG.__members__.items():
            if re.fullmatch("C[0-9]*", name):
                self.assertFromDwarf(
                    (int_die,),
                    int_type("int", 4, True, language=Language.C),
                    lang=lang,
                )

        self.assertFromDwarf(
            (int_die,),
            int_type("int", 4, True, language=DEFAULT_LANGUAGE),
            lang=DW_LANG.BLISS,
        )


class TestObjects(ObjectTestCase):
    def test_constant(self):
        dies = [
            int_die,
            DwarfDie(
                DW_TAG.enumeration_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "color"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
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
            DwarfDie(
                DW_TAG.variable,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "RED"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(
                        DW_AT.location,
                        DW_FORM.exprloc,
                        b"\x03\x04\x03\x02\x01\xff\xff\xff\xff",
                    ),
                ],
            ),
        ]

        type_ = enum_type(
            "color",
            int_type("int", 4, True),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        prog = dwarf_program(dies)
        self.assertEqual(prog["BLUE"], Object(prog, type_, value=2))

        dies[0] = unsigned_int_die
        type_ = enum_type(
            "color",
            int_type("unsigned int", 4, False),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        prog = dwarf_program(dies)
        self.assertEqual(prog["GREEN"], Object(prog, type_, value=1))

        del dies[1].attribs[0]
        type_ = enum_type(
            None,
            int_type("unsigned int", 4, False),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        prog = dwarf_program(dies)
        self.assertEqual(
            prog.object("RED", FindObjectFlags.CONSTANT), Object(prog, type_, value=0)
        )

    def test_function(self):
        dies = [
            int_die,
            DwarfDie(
                DW_TAG.subprogram,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, "abs"),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7FC3EB9B1C30),
                ],
                [
                    DwarfDie(
                        DW_TAG.formal_parameter,
                        [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0)],
                    ),
                ],
            ),
        ]
        type_ = function_type(
            int_type("int", 4, True), (TypeParameter(int_type("int", 1, True)),), False
        )

        prog = dwarf_program(dies)
        self.assertEqual(prog["abs"], Object(prog, type_, address=0x7FC3EB9B1C30))
        self.assertEqual(prog.object("abs", FindObjectFlags.FUNCTION), prog["abs"])
        self.assertRaisesRegex(
            LookupError,
            "could not find variable",
            prog.object,
            "abs",
            FindObjectFlags.VARIABLE,
        )

        del dies[1].attribs[2]
        prog = dwarf_program(dies)
        self.assertRaisesRegex(
            LookupError, "could not find address", prog.object, "abs"
        )

    def test_variable(self):
        dies = [
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
        ]

        prog = dwarf_program(dies)
        self.assertEqual(
            prog["x"],
            Object(prog, int_type("int", 4, True), address=0xFFFFFFFF01020304),
        )
        self.assertEqual(prog.object("x", FindObjectFlags.VARIABLE), prog["x"])
        self.assertRaisesRegex(
            LookupError,
            "could not find constant",
            prog.object,
            "x",
            FindObjectFlags.CONSTANT,
        )

        del dies[1].attribs[2]
        prog = dwarf_program(dies)
        self.assertRaisesRegex(LookupError, "could not find address", prog.object, "x")

        dies[1].attribs.insert(2, DwarfAttrib(DW_AT.location, DW_FORM.exprloc, b"\xe0"))
        prog = dwarf_program(dies)
        self.assertRaisesRegex(Exception, "unimplemented operation", prog.object, "x")

    def test_not_found(self):
        prog = dwarf_program([int_die])
        self.assertRaisesRegex(LookupError, "could not find", prog.object, "y")


class TestProgram(unittest.TestCase):
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
