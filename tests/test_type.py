# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import operator

from drgn import (
    Language,
    Object,
    PrimitiveType,
    Qualifiers,
    TypeEnumerator,
    TypeKind,
    TypeMember,
    TypeParameter,
    TypeTemplateParameter,
    offsetof,
    sizeof,
)
from tests import DEFAULT_LANGUAGE, MockProgramTestCase, mock_program


class TestType(MockProgramTestCase):
    def test_void(self):
        t = self.prog.void_type()
        self.assertEqual(t.kind, TypeKind.VOID)
        self.assertEqual(t.primitive, PrimitiveType.C_VOID)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertIdentical(t, self.prog.void_type())
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "prog.void_type()")

    def test_int(self):
        t = self.prog.int_type("int", 4, True)
        self.assertEqual(t.kind, TypeKind.INT)
        self.assertEqual(t.primitive, PrimitiveType.C_INT)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "int")
        self.assertEqual(t.size, 4)
        self.assertTrue(t.is_signed)
        self.assertEqual(t.byteorder, "little")
        self.assertTrue(t.is_complete())

        self.assertEqual(repr(t), "prog.int_type(name='int', size=4, is_signed=True)")
        self.assertEqual(sizeof(t), 4)

        self.assertRaises(TypeError, self.prog.int_type, None, 4, True)

        self.assertIsNone(self.prog.int_type("my_int", 4, True).primitive)
        self.assertIsNone(self.prog.int_type("int", 4, False).primitive)

    def test_int_byteorder(self):
        self.assertIdentical(
            self.prog.int_type("int", 4, True),
            self.prog.int_type("int", 4, True, byteorder="little"),
        )
        t = self.prog.int_type("int", 4, True, "big")
        self.assertEqual(t.byteorder, "big")
        self.assertEqual(
            repr(t),
            "prog.int_type(name='int', size=4, is_signed=True, byteorder='big')",
        )
        self.assertRaises(ValueError, self.prog.int_type, "int", 4, True, "middle")

    def test_bool(self):
        t = self.prog.bool_type("_Bool", 1)
        self.assertEqual(t.kind, TypeKind.BOOL)
        self.assertEqual(t.primitive, PrimitiveType.C_BOOL)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "_Bool")
        self.assertEqual(t.size, 1)
        self.assertEqual(t.byteorder, "little")
        self.assertTrue(t.is_complete())

        self.assertEqual(repr(t), "prog.bool_type(name='_Bool', size=1)")
        self.assertEqual(sizeof(t), 1)

        self.assertRaises(TypeError, self.prog.bool_type, None, 1)

    def test_bool_byteorder(self):
        self.assertIdentical(
            self.prog.bool_type("_Bool", 1),
            self.prog.bool_type("_Bool", 1, byteorder="little"),
        )
        t = self.prog.bool_type("_Bool", 1, "big")
        self.assertEqual(t.byteorder, "big")
        self.assertEqual(
            repr(t), "prog.bool_type(name='_Bool', size=1, byteorder='big')"
        )
        self.assertRaises(ValueError, self.prog.bool_type, "_Bool", 1, "middle")

    def test_float(self):
        t = self.prog.float_type("float", 4)
        self.assertEqual(t.primitive, PrimitiveType.C_FLOAT)
        self.assertEqual(t.kind, TypeKind.FLOAT)
        self.assertEqual(t.name, "float")
        self.assertEqual(t.size, 4)
        self.assertEqual(t.byteorder, "little")
        self.assertTrue(t.is_complete())

        self.assertEqual(repr(t), "prog.float_type(name='float', size=4)")
        self.assertEqual(sizeof(t), 4)

        self.assertRaises(TypeError, self.prog.float_type, None, 4)

    def test_float_byteorder(self):
        self.assertIdentical(
            self.prog.bool_type("float", 1),
            self.prog.bool_type("float", 1, byteorder="little"),
        )
        t = self.prog.float_type("float", 4, "big")
        self.assertEqual(t.byteorder, "big")
        self.assertEqual(
            repr(t), "prog.float_type(name='float', size=4, byteorder='big')"
        )
        self.assertRaises(ValueError, self.prog.float_type, "float", 4, "middle")

    def test_struct(self):
        t = self.prog.struct_type(
            "point",
            8,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "point")
        self.assertEqual(t.size, 8)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.struct_type(tag='point', size=8, members=(TypeMember(prog.type('int'), name='x', bit_offset=0), TypeMember(prog.type('int'), name='y', bit_offset=32)))",
        )
        self.assertEqual(sizeof(t), 8)

        t = self.prog.struct_type(
            None,
            8,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 8)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertTrue(t.is_complete())

        t = self.prog.struct_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "prog.struct_type(tag='color', size=0, members=())")

        t = self.prog.struct_type("color")
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(
            repr(t), "prog.struct_type(tag='color', size=None, members=None)"
        )

        t = self.prog.struct_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "prog.struct_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, self.prog.struct_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", self.prog.struct_type, "point", 8, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", self.prog.struct_type, "point", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", self.prog.struct_type, "point", 8, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", self.prog.struct_type, "point", 8, (4,)
        )

        # Bit size.
        t = self.prog.struct_type(
            "point",
            8,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "y",
                    32,
                ),
            ),
        )
        self.assertIdentical(
            t.members,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "y",
                    32,
                ),
            ),
        )

    def test_union(self):
        t = self.prog.union_type(
            "option",
            4,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x"),
                TypeMember(self.prog.int_type("unsigned int", 4, False), "y"),
            ),
        )
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "option")
        self.assertEqual(t.size, 4)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("unsigned int", 4, False), "y", 0),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.union_type(tag='option', size=4, members=(TypeMember(prog.type('int'), name='x', bit_offset=0), TypeMember(prog.type('unsigned int'), name='y', bit_offset=0)))",
        )
        self.assertEqual(sizeof(t), 4)

        t = self.prog.union_type(
            None,
            4,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x"),
                TypeMember(self.prog.int_type("unsigned int", 4, False), "y"),
            ),
        )
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 4)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("unsigned int", 4, False), "y", 0),
            ),
        )
        self.assertTrue(t.is_complete())

        t = self.prog.union_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "prog.union_type(tag='color', size=0, members=())")

        t = self.prog.union_type("color")
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(
            repr(t), "prog.union_type(tag='color', size=None, members=None)"
        )

        t = self.prog.union_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "prog.union_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, self.prog.union_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", self.prog.union_type, "option", 8, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", self.prog.union_type, "option", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", self.prog.union_type, "option", 8, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", self.prog.union_type, "option", 8, (4,)
        )

        # Bit size.
        t = self.prog.union_type(
            "option",
            4,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned int", 4, False),
                        bit_field_size=4,
                    ),
                    "y",
                    0,
                ),
            ),
        )
        self.assertIdentical(
            t.members,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned int", 4, False),
                        bit_field_size=4,
                    ),
                    "y",
                    0,
                ),
            ),
        )

    def test_class(self):
        t = self.prog.class_type(
            "coord",
            12,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                TypeMember(self.prog.int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "coord")
        self.assertEqual(t.size, 12)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                TypeMember(self.prog.int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.class_type(tag='coord', size=12, members=(TypeMember(prog.type('int'), name='x', bit_offset=0), TypeMember(prog.type('int'), name='y', bit_offset=32), TypeMember(prog.type('int'), name='z', bit_offset=64)))",
        )
        self.assertEqual(sizeof(t), 12)

        t = self.prog.class_type(
            None,
            12,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                TypeMember(self.prog.int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 12)
        self.assertIdentical(
            t.members,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                TypeMember(self.prog.int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertTrue(t.is_complete())

        t = self.prog.class_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "prog.class_type(tag='color', size=0, members=())")

        t = self.prog.class_type("color")
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(
            repr(t), "prog.class_type(tag='color', size=None, members=None)"
        )

        t = self.prog.class_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "prog.class_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, self.prog.class_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", self.prog.class_type, "coord", 12, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", self.prog.class_type, "coord", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", self.prog.class_type, "coord", 12, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", self.prog.class_type, "coord", 12, (4,)
        )

        # Bit size.
        t = self.prog.class_type(
            "coord",
            12,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "y",
                    32,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "z",
                    64,
                ),
            ),
        )
        self.assertIdentical(
            t.members,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "y",
                    32,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "z",
                    64,
                ),
            ),
        )

    def test_member(self):
        t = self.prog.struct_type(
            None,
            8,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(
                    self.prog.struct_type(
                        None,
                        4,
                        (TypeMember(self.prog.int_type("int", 4, True), "y", 0),),
                    ),
                    None,
                    32,
                ),
            ),
        )
        self.assertIdentical(
            t.member("x"), TypeMember(self.prog.int_type("int", 4, True), "x", 0)
        )
        self.assertIdentical(
            t.member("y"), TypeMember(self.prog.int_type("int", 4, True), "y", 32)
        )
        self.assertRaises(LookupError, t.member, "z")

        self.assertIdentical(
            t.members[1].type.member("y"),
            TypeMember(self.prog.int_type("int", 4, True), "y", 0),
        )

        self.assertRaises(TypeError, self.prog.int_type("int", 4, True).member, "foo")

    def test_offsetof(self):
        self.assertEqual(offsetof(self.line_segment_type, "b"), 8)
        self.assertEqual(offsetof(self.line_segment_type, "a.y"), 4)
        self.assertRaisesRegex(
            LookupError,
            "'struct line_segment' has no member 'c'",
            offsetof,
            self.line_segment_type,
            "c.x",
        )

        small_point_type = self.prog.struct_type(
            "small_point",
            1,
            (
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "x",
                    0,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=4
                    ),
                    "y",
                    4,
                ),
            ),
        )
        self.assertEqual(offsetof(small_point_type, "x"), 0)
        self.assertRaisesRegex(
            ValueError,
            "member is not byte-aligned",
            offsetof,
            small_point_type,
            "y",
        )

    def test_enum(self):
        t = self.prog.enum_type(
            "color",
            self.prog.int_type("unsigned int", 4, False),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertEqual(t.kind, TypeKind.ENUM)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "color")
        self.assertIdentical(t.type, self.prog.int_type("unsigned int", 4, False))
        self.assertEqual(
            t.enumerators,
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.enum_type(tag='color', type=prog.int_type(name='unsigned int', size=4, is_signed=False), enumerators=(TypeEnumerator('RED', 0), TypeEnumerator('GREEN', 1), TypeEnumerator('BLUE', 2)))",
        )
        self.assertEqual(sizeof(t), 4)

        t = self.prog.enum_type("color", None, None)
        self.assertEqual(t.kind, TypeKind.ENUM)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.type)
        self.assertIsNone(t.enumerators)
        self.assertFalse(t.is_complete())

        self.assertEqual(
            repr(t), "prog.enum_type(tag='color', type=None, enumerators=None)"
        )

        # A type with no enumerators isn't valid in C, but we allow it.
        t = self.prog.enum_type(
            "color", self.prog.int_type("unsigned int", 4, False), ()
        )
        self.assertEqual(t.kind, TypeKind.ENUM)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIdentical(t.type, self.prog.int_type("unsigned int", 4, False))
        self.assertEqual(t.enumerators, ())
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.enum_type(tag='color', type=prog.int_type(name='unsigned int', size=4, is_signed=False), enumerators=())",
        )

        self.assertRaisesRegex(
            TypeError, "must be Type", self.prog.enum_type, "color", 4, ()
        )
        self.assertRaisesRegex(
            ValueError,
            "must be integer type",
            self.prog.enum_type,
            "color",
            self.prog.void_type(),
            (),
        )
        self.assertRaisesRegex(
            ValueError,
            "must be unqualified",
            self.prog.enum_type,
            "color",
            self.prog.int_type("unsigned int", 4, True, qualifiers=Qualifiers.CONST),
            (),
        )
        self.assertRaisesRegex(
            ValueError,
            "must not have compatible type",
            self.prog.enum_type,
            "color",
            self.prog.int_type("unsigned int", 4, False),
            None,
        )
        self.assertRaisesRegex(
            ValueError,
            "must have compatible type",
            self.prog.enum_type,
            "color",
            None,
            (),
        )
        self.assertRaisesRegex(
            TypeError,
            "must be sequence or None",
            self.prog.enum_type,
            "color",
            self.prog.int_type("unsigned int", 4, False),
            4,
        )
        self.assertRaisesRegex(
            TypeError,
            "must be TypeEnumerator",
            self.prog.enum_type,
            "color",
            self.prog.int_type("unsigned int", 4, False),
            (4,),
        )

    def test_typedef(self):
        t = self.prog.typedef_type("INT", self.prog.int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.TYPEDEF)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "INT")
        self.assertIdentical(t.type, self.prog.int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.typedef_type(name='INT', type=prog.int_type(name='int', size=4, is_signed=True))",
        )
        self.assertEqual(sizeof(t), 4)

        t = self.prog.typedef_type("VOID", self.prog.void_type())
        self.assertFalse(t.is_complete())

        self.assertRaises(
            TypeError, self.prog.typedef_type, None, self.prog.int_type("int", 4, True)
        )
        self.assertRaises(TypeError, self.prog.typedef_type, "INT", 4)

        self.assertEqual(
            self.prog.typedef_type(
                "size_t", self.prog.int_type("unsigned long", 8, False)
            ).primitive,
            PrimitiveType.C_SIZE_T,
        )
        self.assertEqual(
            self.prog.typedef_type(
                "ptrdiff_t", self.prog.int_type("long", 8, True)
            ).primitive,
            PrimitiveType.C_PTRDIFF_T,
        )

    def test_pointer(self):
        t = self.prog.pointer_type(self.prog.int_type("int", 4, True), 8)
        self.assertEqual(t.kind, TypeKind.POINTER)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.size, 8)
        self.assertIdentical(t.type, self.prog.int_type("int", 4, True))
        self.assertEqual(t.byteorder, "little")
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.pointer_type(type=prog.int_type(name='int', size=4, is_signed=True))",
        )
        self.assertEqual(
            repr(self.prog.pointer_type(self.prog.int_type("int", 4, True), 4)),
            "prog.pointer_type(type=prog.int_type(name='int', size=4, is_signed=True), size=4)",
        )

        self.assertEqual(sizeof(t), 8)

        self.assertRaises(TypeError, self.prog.pointer_type, 4)

    def test_pointer_byteorder(self):
        self.assertIdentical(
            self.prog.pointer_type(self.prog.int_type("int", 4, True)),
            self.prog.pointer_type(
                self.prog.int_type("int", 4, True), byteorder="little"
            ),
        )
        t = self.prog.pointer_type(self.prog.int_type("int", 4, True), 8, "big")
        self.assertEqual(t.byteorder, "big")
        self.assertEqual(t.type.byteorder, "little")
        self.assertEqual(
            repr(t),
            "prog.pointer_type(type=prog.int_type(name='int', size=4, is_signed=True), byteorder='big')",
        )
        self.assertRaises(
            ValueError,
            self.prog.pointer_type,
            self.prog.int_type("int", 4, True),
            8,
            "middle",
        )

    def test_array(self):
        t = self.prog.array_type(self.prog.int_type("int", 4, True), 10)
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.length, 10)
        self.assertIdentical(t.type, self.prog.int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.array_type(type=prog.int_type(name='int', size=4, is_signed=True), length=10)",
        )
        self.assertEqual(sizeof(t), 40)

        t = self.prog.array_type(self.prog.int_type("int", 4, True), 0)
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.length, 0)
        self.assertIdentical(t.type, self.prog.int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        t = self.prog.array_type(self.prog.int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.length)
        self.assertIdentical(t.type, self.prog.int_type("int", 4, True))
        self.assertFalse(t.is_complete())

        self.assertRaises(TypeError, self.prog.array_type, 10, 4)

    def test_function(self):
        t = self.prog.function_type(
            self.prog.void_type(),
            (TypeParameter(self.prog.int_type("int", 4, True), "n"),),
        )
        self.assertEqual(t.kind, TypeKind.FUNCTION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertIdentical(t.type, self.prog.void_type())
        self.assertIdentical(
            t.parameters, (TypeParameter(self.prog.int_type("int", 4, True), "n"),)
        )
        self.assertFalse(t.is_variadic)
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "prog.function_type(type=prog.void_type(), parameters=(TypeParameter(prog.type('int'), name='n'),), is_variadic=False)",
        )
        self.assertRaises(TypeError, sizeof, t)

        self.assertFalse(
            self.prog.function_type(self.prog.void_type(), (), False).is_variadic
        )
        self.assertTrue(
            self.prog.function_type(self.prog.void_type(), (), True).is_variadic
        )

        self.assertRaisesRegex(
            TypeError, r"must be _drgn\.Type", self.prog.function_type, None, ()
        )
        self.assertRaisesRegex(
            TypeError,
            "must be sequence",
            self.prog.function_type,
            self.prog.void_type(),
            None,
        )
        self.assertRaisesRegex(
            TypeError,
            "must be TypeParameter",
            self.prog.function_type,
            self.prog.void_type(),
            (4,),
        )

    def test_cycle(self):
        t1 = self.prog.struct_type(
            "foo", 8, (TypeMember(lambda: self.prog.pointer_type(t1), "next"),)
        )
        t2 = self.prog.struct_type(
            "foo", 8, (TypeMember(lambda: self.prog.pointer_type(t2), "next"),)
        )
        t3, t4 = (
            self.prog.struct_type(
                "foo", 8, (TypeMember(lambda: self.prog.pointer_type(t4), "next"),)
            ),
            self.prog.struct_type(
                "foo", 8, (TypeMember(lambda: self.prog.pointer_type(t3), "next"),)
            ),
        )
        self.assertIdentical(t1, t2)
        self.assertIdentical(t2, t3)
        self.assertIdentical(t3, t4)

        self.assertEqual(
            repr(t1),
            "prog.struct_type(tag='foo', size=8, members=(TypeMember(prog.type('struct foo *'), name='next', bit_offset=0),))",
        )

    def test_cycle2(self):
        t1 = self.prog.struct_type(
            "list_head",
            16,
            (
                TypeMember(lambda: self.prog.pointer_type(t1), "next"),
                TypeMember(lambda: self.prog.pointer_type(t1), "prev", 8),
            ),
        )
        t2 = self.prog.struct_type(
            "list_head",
            16,
            (
                TypeMember(lambda: self.prog.pointer_type(t2), "next"),
                TypeMember(lambda: self.prog.pointer_type(t2), "prev", 8),
            ),
        )
        self.assertIdentical(t1, t2)

        self.assertEqual(
            repr(t1),
            "prog.struct_type(tag='list_head', size=16, members=(TypeMember(prog.type('struct list_head *'), name='next', bit_offset=0), TypeMember(prog.type('struct list_head *'), name='prev', bit_offset=8)))",
        )

    def test_bad_thunk(self):
        t1 = self.prog.struct_type(
            "foo", 16, (TypeMember(lambda: exec('raise Exception("test")'), "bar"),)
        )
        with self.assertRaisesRegex(Exception, "test"):
            t1.members[0].type
        t1 = self.prog.struct_type("foo", 16, (TypeMember(lambda: 0, "bar"),))
        with self.assertRaisesRegex(
            TypeError, r"TypeMember\(\) callable must return Object or Type"
        ):
            t1.members[0].type

    def test_qualifiers(self):
        self.assertEqual(self.prog.void_type().qualifiers, Qualifiers(0))

        t = self.prog.void_type(qualifiers=Qualifiers.CONST | Qualifiers.VOLATILE)
        self.assertEqual(t.qualifiers, Qualifiers.CONST | Qualifiers.VOLATILE)
        self.assertEqual(
            repr(t), "prog.void_type(qualifiers=<Qualifiers.VOLATILE|CONST: 3>)"
        )

        self.assertIdentical(
            t.qualified(Qualifiers.ATOMIC),
            self.prog.void_type(qualifiers=Qualifiers.ATOMIC),
        )
        self.assertIdentical(t.unqualified(), self.prog.void_type())
        self.assertIdentical(t.qualified(Qualifiers(0)), t.unqualified())

        self.assertRaisesRegex(
            TypeError, "expected Qualifiers", self.prog.void_type, qualifiers=1.5
        )

    def test_language(self):
        self.assertEqual(self.prog.void_type(language=None).language, DEFAULT_LANGUAGE)
        self.assertEqual(self.prog.void_type(language=Language.C).language, Language.C)

        self.assertEqual(
            self.prog.int_type("int", 4, True, language=Language.CPP).language,
            Language.CPP,
        )

    def test_language_repr(self):
        self.assertEqual(
            repr(self.prog.void_type(language=Language.CPP)),
            "prog.void_type(language=Language.CPP)",
        )

    def test_different_programs_compound(self):
        self.assertRaisesRegex(
            ValueError,
            "object is from different program",
            self.prog.struct_type,
            None,
            4,
            (TypeMember(mock_program().int_type("int", 4, True)),),
        )

    def test_different_programs_compound_callback(self):
        with self.assertRaisesRegex(ValueError, "objects are from different program"):
            self.prog.struct_type(
                None, 4, (TypeMember(lambda: mock_program().int_type("int", 4, True)),)
            ).members[0].type

    def test_different_programs_enum(self):
        self.assertRaisesRegex(
            ValueError,
            "type is from different program",
            self.prog.enum_type,
            None,
            mock_program().int_type("int", 4, True),
            (),
        )

    def test_different_programs_typedef(self):
        self.assertRaisesRegex(
            ValueError,
            "type is from different program",
            self.prog.typedef_type,
            "INT",
            mock_program().int_type("int", 4, True),
        )

    def test_different_programs_pointer(self):
        self.assertRaisesRegex(
            ValueError,
            "type is from different program",
            self.prog.pointer_type,
            mock_program().int_type("int", 4, True),
        )

    def test_different_programs_array(self):
        self.assertRaisesRegex(
            ValueError,
            "type is from different program",
            self.prog.pointer_type,
            mock_program().int_type("int", 4, True),
        )

    def test_different_programs_function_return(self):
        self.assertRaisesRegex(
            ValueError,
            "type is from different program",
            self.prog.function_type,
            mock_program().int_type("int", 4, True),
            (),
        )

    def test_different_programs_function_parameter(self):
        self.assertRaisesRegex(
            ValueError,
            "object is from different program",
            self.prog.function_type,
            self.prog.void_type(),
            (TypeParameter(mock_program().int_type("int", 4, True)),),
        )

    def test_different_programs_function_parameter_callback(self):
        with self.assertRaisesRegex(ValueError, "objects are from different programs"):
            self.prog.function_type(
                self.prog.void_type(),
                (TypeParameter(lambda: mock_program().int_type("int", 4, True)),),
            ).parameters[0].type


class TestTypeEnumerator(MockProgramTestCase):
    def test_init(self):
        e = TypeEnumerator("a", 1)
        self.assertEqual(e.name, "a")
        self.assertEqual(e.value, 1)

        self.assertRaises(TypeError, TypeEnumerator, "a", None)
        self.assertRaises(TypeError, TypeEnumerator, None, 1)

    def test_repr(self):
        e = TypeEnumerator("a", 1)
        self.assertEqual(repr(e), "TypeEnumerator('a', 1)")

    def test_sequence(self):
        e = TypeEnumerator("a", 1)
        name, value = e
        self.assertEqual(name, "a")
        self.assertEqual(value, 1)
        self.assertEqual(list(e), ["a", 1])

    def test_cmp(self):
        self.assertEqual(TypeEnumerator("a", 1), TypeEnumerator(name="a", value=1))
        self.assertNotEqual(TypeEnumerator("a", 1), TypeEnumerator("a", 2))
        self.assertNotEqual(TypeEnumerator("b", 1), TypeEnumerator("a", 1))


class TestTypeMember(MockProgramTestCase):
    def test_init(self):
        m = TypeMember(self.prog.void_type())
        self.assertIdentical(m.object, Object(self.prog, self.prog.void_type()))
        self.assertIdentical(m.type, self.prog.void_type())
        self.assertIsNone(m.name)
        self.assertEqual(m.bit_offset, 0)
        self.assertEqual(m.offset, 0)
        self.assertIsNone(m.bit_field_size)

        m = TypeMember(Object(self.prog, self.prog.void_type()), "foo")
        self.assertIdentical(m.object, Object(self.prog, self.prog.void_type()))
        self.assertIdentical(m.type, self.prog.void_type())
        self.assertEqual(m.name, "foo")
        self.assertEqual(m.bit_offset, 0)
        self.assertEqual(m.offset, 0)
        self.assertIsNone(m.bit_field_size)

        m = TypeMember(self.prog.void_type(), "foo", 8)
        self.assertIdentical(m.object, Object(self.prog, self.prog.void_type()))
        self.assertIdentical(m.type, self.prog.void_type())
        self.assertEqual(m.name, "foo")
        self.assertEqual(m.bit_offset, 8)
        self.assertEqual(m.offset, 1)
        self.assertIsNone(m.bit_field_size)

        self.assertRaises(TypeError, TypeMember, None)
        self.assertRaises(TypeError, TypeMember, self.prog.void_type(), 1)
        self.assertRaises(TypeError, TypeMember, self.prog.void_type(), "foo", None)

    def test_callable(self):
        m = TypeMember(self.prog.void_type)
        self.assertIdentical(m.object, Object(self.prog, self.prog.void_type()))
        self.assertIdentical(m.type, self.prog.void_type())

        m = TypeMember(lambda: Object(self.prog, self.prog.int_type("int", 4, True)))
        self.assertIdentical(
            m.object, Object(self.prog, self.prog.int_type("int", 4, True))
        )
        self.assertIdentical(m.type, self.prog.int_type("int", 4, True))

        m = TypeMember(lambda: None)
        self.assertRaises(TypeError, getattr, m, "type")

    def test_repr(self):
        m = TypeMember(self.prog.void_type, name="foo")
        self.assertEqual(
            repr(m), "TypeMember(prog.type('void'), name='foo', bit_offset=0)"
        )

        m = TypeMember(self.prog.void_type)
        self.assertEqual(repr(m), "TypeMember(prog.type('void'), bit_offset=0)")

        m = TypeMember(
            Object(self.prog, self.prog.int_type("int", 4, True), bit_field_size=1)
        )
        self.assertEqual(
            repr(m), "TypeMember(Object(prog, 'int', bit_field_size=1), bit_offset=0)"
        )

        m = TypeMember(lambda: None)
        self.assertRaises(TypeError, repr, m)


class TestTypeParameter(MockProgramTestCase):
    def test_init(self):
        p = TypeParameter(self.prog.void_type())
        self.assertIdentical(
            p.default_argument, Object(self.prog, self.prog.void_type())
        )
        self.assertIdentical(p.type, self.prog.void_type())
        self.assertIsNone(p.name)

        p = TypeParameter(
            Object(self.prog, self.prog.int_type("int", 4, True), 5), "foo"
        )
        self.assertIdentical(
            p.default_argument, Object(self.prog, self.prog.int_type("int", 4, True), 5)
        )
        self.assertIdentical(p.type, self.prog.int_type("int", 4, True))
        self.assertEqual(p.name, "foo")

        self.assertRaises(TypeError, TypeParameter, None)
        self.assertRaises(TypeError, TypeParameter, self.prog.void_type(), 1)

    def test_callable(self):
        p = TypeParameter(self.prog.void_type)
        self.assertIdentical(
            p.default_argument, Object(self.prog, self.prog.void_type())
        )
        self.assertIdentical(p.type, self.prog.void_type())

        p = TypeParameter(lambda: Object(self.prog, self.prog.int_type("int", 4, True)))
        self.assertIdentical(
            p.default_argument, Object(self.prog, self.prog.int_type("int", 4, True))
        )
        self.assertIdentical(p.type, self.prog.int_type("int", 4, True))

        p = TypeParameter(lambda: None)
        self.assertRaises(TypeError, getattr, p, "type")

    def test_repr(self):
        p = TypeParameter(self.prog.void_type, name="foo")
        self.assertEqual(repr(p), "TypeParameter(prog.type('void'), name='foo')")

        p = TypeParameter(self.prog.void_type)
        self.assertEqual(repr(p), "TypeParameter(prog.type('void'))")

        p = TypeParameter(lambda: None)
        self.assertRaises(TypeError, repr, p)


class TestTypeTemplateParameter(MockProgramTestCase):
    def test_init(self):
        p = TypeTemplateParameter(self.prog.void_type())
        self.assertIdentical(p.argument, self.prog.void_type())
        self.assertIsNone(p.name)
        self.assertFalse(p.is_default)

        p = TypeTemplateParameter(
            Object(self.prog, self.prog.int_type("int", 4, True), 5), "foo", True
        )
        self.assertIdentical(
            p.argument, Object(self.prog, self.prog.int_type("int", 4, True), 5)
        )
        self.assertEqual(p.name, "foo")
        self.assertTrue(p.is_default)

        self.assertRaises(TypeError, TypeTemplateParameter, None)
        self.assertRaisesRegex(
            ValueError,
            "must not be absent Object",
            TypeTemplateParameter,
            Object(self.prog, "int"),
        )
        self.assertRaises(TypeError, TypeTemplateParameter, self.prog.void_type(), 1)
        self.assertRaises(
            TypeError, TypeTemplateParameter, self.prog.void_type(), None, None
        )

    def test_callable(self):
        p = TypeTemplateParameter(self.prog.void_type)
        self.assertIdentical(p.argument, self.prog.void_type())

        p = TypeTemplateParameter(
            lambda: Object(self.prog, self.prog.int_type("int", 4, True), 5)
        )
        self.assertIdentical(
            p.argument, Object(self.prog, self.prog.int_type("int", 4, True), 5)
        )

        p = TypeTemplateParameter(lambda: None)
        self.assertRaises(TypeError, getattr, p, "argument")
        p = TypeTemplateParameter(lambda: Object(self.prog, "int"))
        self.assertRaisesRegex(
            ValueError, "must not return absent Object", getattr, p, "argument"
        )

    def test_repr(self):
        p = TypeTemplateParameter(self.prog.void_type, name="foo", is_default=True)
        self.assertEqual(
            repr(p),
            "TypeTemplateParameter(prog.type('void'), name='foo', is_default=True)",
        )

        p = TypeTemplateParameter(self.prog.void_type)
        self.assertEqual(repr(p), "TypeTemplateParameter(prog.type('void'))")

        p = TypeTemplateParameter(lambda: None)
        self.assertRaises(TypeError, repr, p)
