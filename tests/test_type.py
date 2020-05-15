# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import unittest

from drgn import (
    Language,
    PrimitiveType,
    Qualifiers,
    TypeEnumerator,
    TypeKind,
    TypeMember,
    TypeParameter,
    array_type,
    bool_type,
    class_type,
    complex_type,
    enum_type,
    float_type,
    function_type,
    int_type,
    pointer_type,
    sizeof,
    struct_type,
    typedef_type,
    union_type,
    void_type,
)

from tests import DEFAULT_LANGUAGE


class TestType(unittest.TestCase):
    def test_void(self):
        t = void_type()
        self.assertEqual(t.kind, TypeKind.VOID)
        self.assertEqual(t.primitive, PrimitiveType.C_VOID)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t, void_type())
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "void_type()")

    def test_int(self):
        t = int_type("int", 4, True)
        self.assertEqual(t.kind, TypeKind.INT)
        self.assertEqual(t.primitive, PrimitiveType.C_INT)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "int")
        self.assertEqual(t.size, 4)
        self.assertTrue(t.is_signed)
        self.assertTrue(t.is_complete())

        self.assertEqual(t, int_type("int", 4, True))
        self.assertNotEqual(t, int_type("long", 4, True))
        self.assertNotEqual(t, int_type("int", 2, True))
        self.assertNotEqual(t, int_type("int", 4, False))

        self.assertEqual(repr(t), "int_type(name='int', size=4, is_signed=True)")
        self.assertEqual(sizeof(t), 4)

        self.assertRaises(TypeError, int_type, None, 4, True)

        self.assertIsNone(int_type("my_int", 4, True).primitive)
        self.assertIsNone(int_type("int", 4, False).primitive)

    def test_bool(self):
        t = bool_type("_Bool", 1)
        self.assertEqual(t.kind, TypeKind.BOOL)
        self.assertEqual(t.primitive, PrimitiveType.C_BOOL)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "_Bool")
        self.assertEqual(t.size, 1)
        self.assertTrue(t.is_complete())

        self.assertEqual(t, bool_type("_Bool", 1))
        self.assertNotEqual(t, bool_type("bool", 1))
        self.assertNotEqual(t, bool_type("_Bool", 2))

        self.assertEqual(repr(t), "bool_type(name='_Bool', size=1)")
        self.assertEqual(sizeof(t), 1)

        self.assertRaises(TypeError, bool_type, None, 1)

    def test_float(self):
        t = float_type("float", 4)
        self.assertEqual(t.primitive, PrimitiveType.C_FLOAT)
        self.assertEqual(t.kind, TypeKind.FLOAT)
        self.assertEqual(t.name, "float")
        self.assertEqual(t.size, 4)
        self.assertTrue(t.is_complete())

        self.assertEqual(t, float_type("float", 4))
        self.assertNotEqual(t, float_type("double", 4))
        self.assertNotEqual(t, float_type("float", 8))

        self.assertEqual(repr(t), "float_type(name='float', size=4)")
        self.assertEqual(sizeof(t), 4)

        self.assertRaises(TypeError, float_type, None, 4)

    def test_complex(self):
        t = complex_type("double _Complex", 16, float_type("double", 8))
        self.assertEqual(t.kind, TypeKind.COMPLEX)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "double _Complex")
        self.assertEqual(t.size, 16)
        self.assertEqual(t.type, float_type("double", 8))
        self.assertTrue(t.is_complete())

        self.assertEqual(
            t, complex_type("double _Complex", 16, float_type("double", 8))
        )
        self.assertNotEqual(
            t, complex_type("float _Complex", 16, float_type("double", 8))
        )
        self.assertNotEqual(
            t, complex_type("double _Complex", 32, float_type("double", 8))
        )
        self.assertNotEqual(
            t, complex_type("double _Complex", 16, float_type("float", 4))
        )

        self.assertEqual(
            repr(t),
            "complex_type(name='double _Complex', size=16, type=float_type(name='double', size=8))",
        )
        self.assertEqual(sizeof(t), 16)

        self.assertRaises(TypeError, complex_type, None, 16, float_type("double", 8))
        self.assertRaises(TypeError, complex_type, "double _Complex", 16, None)
        self.assertRaisesRegex(
            ValueError,
            "must be floating-point or integer type",
            complex_type,
            "double _Complex",
            16,
            void_type(),
        )
        self.assertRaisesRegex(
            ValueError,
            "must be unqualified",
            complex_type,
            "double _Complex",
            16,
            float_type("double", 8, Qualifiers.CONST),
        )

    def test_struct(self):
        t = struct_type(
            "point",
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "point")
        self.assertEqual(t.size, 8)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("int", 4, True), "y", 32, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            t,
            struct_type(
                "point",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        # Different tag.
        self.assertNotEqual(
            t,
            struct_type(
                "pt",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        # Different size.
        self.assertNotEqual(
            t,
            struct_type(
                "point",
                16,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        # One is anonymous.
        self.assertNotEqual(
            t,
            struct_type(
                None,
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        # Different members.
        self.assertNotEqual(
            t,
            struct_type(
                "point",
                8,
                (
                    TypeMember(int_type("long", 8, True), "x", 0),
                    TypeMember(int_type("long", 8, True), "y", 64),
                ),
            ),
        )
        # Different number of members.
        self.assertNotEqual(
            t,
            struct_type(
                "point",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        # One member is anonymous.
        self.assertNotEqual(
            t,
            struct_type(
                "point",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), None, 32),
                ),
            ),
        )
        # One is incomplete.
        self.assertNotEqual(t, struct_type("point"))

        self.assertEqual(
            repr(t),
            "struct_type(tag='point', size=8, members=(TypeMember(type=int_type(name='int', size=4, is_signed=True), name='x', bit_offset=0), TypeMember(type=int_type(name='int', size=4, is_signed=True), name='y', bit_offset=32)))",
        )
        self.assertEqual(sizeof(t), 8)

        t = struct_type(
            None,
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 8)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("int", 4, True), "y", 32, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        t = struct_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "struct_type(tag='color', size=0, members=())")

        t = struct_type("color")
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "struct_type(tag='color', size=None, members=None)")

        t = struct_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.STRUCT)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "struct_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, struct_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", struct_type, "point", 8, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", struct_type, "point", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", struct_type, "point", 8, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", struct_type, "point", 8, (4,)
        )

        # Bit size.
        t = struct_type(
            "point",
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 32, 4),
            ),
        )
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 32, 4),
            ),
        )

    def test_union(self):
        t = union_type(
            "option",
            4,
            (
                TypeMember(int_type("int", 4, True), "x"),
                TypeMember(int_type("unsigned int", 4, False), "y"),
            ),
        )
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "option")
        self.assertEqual(t.size, 4)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("unsigned int", 4, False), "y", 0, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            t,
            union_type(
                "option",
                4,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False), "y"),
                ),
            ),
        )
        # Different tag.
        self.assertNotEqual(
            t,
            union_type(
                "pt",
                4,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False), "y"),
                ),
            ),
        )
        # Different size.
        self.assertNotEqual(
            t,
            union_type(
                "option",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False), "y"),
                ),
            ),
        )
        # One is anonymous.
        self.assertNotEqual(
            t,
            union_type(
                None,
                4,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False), "y"),
                ),
            ),
        )
        # Different members.
        self.assertNotEqual(
            t,
            union_type(
                "option",
                4,
                (
                    TypeMember(int_type("long", 8, True), "x"),
                    TypeMember(int_type("unsigned long", 8, False), "y"),
                ),
            ),
        )
        # Different number of members.
        self.assertNotEqual(
            t,
            union_type(
                "option",
                4,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False), "y"),
                    TypeMember(float_type("float", 4), "z"),
                ),
            ),
        )
        # One member is anonymous.
        self.assertNotEqual(
            t,
            union_type(
                "option",
                4,
                (
                    TypeMember(int_type("int", 4, True), "x"),
                    TypeMember(int_type("unsigned int", 4, False),),
                ),
            ),
        )
        # One is incomplete.
        self.assertNotEqual(t, union_type("option"))

        self.assertEqual(
            repr(t),
            "union_type(tag='option', size=4, members=(TypeMember(type=int_type(name='int', size=4, is_signed=True), name='x', bit_offset=0), TypeMember(type=int_type(name='unsigned int', size=4, is_signed=False), name='y', bit_offset=0)))",
        )
        self.assertEqual(sizeof(t), 4)

        t = union_type(
            None,
            4,
            (
                TypeMember(int_type("int", 4, True), "x"),
                TypeMember(int_type("unsigned int", 4, False), "y"),
            ),
        )
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 4)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("unsigned int", 4, False), "y", 0, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        t = union_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "union_type(tag='color', size=0, members=())")

        t = union_type("color")
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "union_type(tag='color', size=None, members=None)")

        t = union_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.UNION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "union_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, union_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", union_type, "option", 8, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", union_type, "option", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", union_type, "option", 8, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", union_type, "option", 8, (4,)
        )

        # Bit size.
        t = union_type(
            "option",
            4,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("unsigned int", 4, False), "y", 0, 4),
            ),
        )
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("unsigned int", 4, False), "y", 0, 4),
            ),
        )

    def test_class(self):
        t = class_type(
            "coord",
            12,
            (
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 32),
                TypeMember(int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.tag, "coord")
        self.assertEqual(t.size, 12)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("int", 4, True), "y", 32, 0),
                TypeMember(int_type("int", 4, True), "z", 64, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        self.assertEqual(
            t,
            class_type(
                "coord",
                12,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        # Different tag.
        self.assertNotEqual(
            t,
            class_type(
                "crd",
                12,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        # Different size.
        self.assertNotEqual(
            t,
            class_type(
                "coord",
                16,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        # One is anonymous.
        self.assertNotEqual(
            t,
            class_type(
                None,
                12,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                    TypeMember(int_type("int", 4, True), "z", 64),
                ),
            ),
        )
        # Different members.
        self.assertNotEqual(
            t,
            class_type(
                "coord",
                12,
                (
                    TypeMember(int_type("long", 8, True), "x", 0),
                    TypeMember(int_type("long", 8, True), "y", 64),
                    TypeMember(int_type("long", 8, True), "z", 128),
                ),
            ),
        )
        # Different number of members.
        self.assertNotEqual(
            t,
            class_type(
                "coord",
                12,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        # One member is anonymous.
        self.assertNotEqual(
            t,
            class_type(
                "coord",
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0, 0),
                    TypeMember(int_type("int", 4, True), None, 32, 0),
                    TypeMember(int_type("int", 4, True), "z", 64, 0),
                ),
            ),
        )
        # One is incomplete.
        self.assertNotEqual(t, class_type("coord"))

        self.assertEqual(
            repr(t),
            "class_type(tag='coord', size=12, members=(TypeMember(type=int_type(name='int', size=4, is_signed=True), name='x', bit_offset=0), TypeMember(type=int_type(name='int', size=4, is_signed=True), name='y', bit_offset=32), TypeMember(type=int_type(name='int', size=4, is_signed=True), name='z', bit_offset=64)))",
        )
        self.assertEqual(sizeof(t), 12)

        t = class_type(
            None,
            12,
            (
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 32),
                TypeMember(int_type("int", 4, True), "z", 64),
            ),
        )
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.tag)
        self.assertEqual(t.size, 12)
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 0),
                TypeMember(int_type("int", 4, True), "y", 32, 0),
                TypeMember(int_type("int", 4, True), "z", 64, 0),
            ),
        )
        self.assertTrue(t.is_complete())

        t = class_type("color", 0, ())
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.size, 0)
        self.assertEqual(t.members, ())
        self.assertTrue(t.is_complete())
        self.assertEqual(repr(t), "class_type(tag='color', size=0, members=())")

        t = class_type("color")
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "class_type(tag='color', size=None, members=None)")

        t = class_type(None, None, None)
        self.assertEqual(t.kind, TypeKind.CLASS)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, None)
        self.assertIsNone(t.size)
        self.assertIsNone(t.members)
        self.assertFalse(t.is_complete())
        self.assertEqual(repr(t), "class_type(tag=None, size=None, members=None)")

        self.assertRaises(TypeError, class_type, 4)
        self.assertRaisesRegex(
            ValueError, "must not have size", class_type, "coord", 12, None
        )
        self.assertRaisesRegex(
            ValueError, "must have size", class_type, "coord", None, ()
        )
        self.assertRaisesRegex(
            TypeError, "must be sequence or None", class_type, "coord", 12, 4
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeMember", class_type, "coord", 12, (4,)
        )

        # Bit size.
        t = class_type(
            "coord",
            12,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 32, 4),
                TypeMember(int_type("int", 4, True), "z", 64, 4),
            ),
        )
        self.assertEqual(
            t.members,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 32, 4),
                TypeMember(int_type("int", 4, True), "z", 64, 4),
            ),
        )

    def test_enum(self):
        t = enum_type(
            "color",
            int_type("unsigned int", 4, False),
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
        self.assertEqual(t.type, int_type("unsigned int", 4, False))
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
            t,
            enum_type(
                "color",
                int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        # Different tag.
        self.assertNotEqual(
            t,
            enum_type(
                "COLOR",
                int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        # One is anonymous.
        self.assertNotEqual(
            t,
            enum_type(
                None,
                int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        # Different compatible type.
        self.assertNotEqual(
            t,
            enum_type(
                "color",
                int_type("int", 4, True),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        # Different enumerators.
        self.assertNotEqual(
            t,
            enum_type(
                "color",
                int_type("unsigned int", 4, False),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("YELLOW", 1),
                    TypeEnumerator("BLUE", 2),
                ),
            ),
        )
        # Different number of enumerators.
        self.assertNotEqual(
            t,
            enum_type(
                "color",
                int_type("unsigned int", 4, False),
                (TypeEnumerator("RED", 0), TypeEnumerator("GREEN", 1)),
            ),
        )
        # One is incomplete.
        self.assertNotEqual(t, enum_type("color"))

        self.assertEqual(
            repr(t),
            "enum_type(tag='color', type=int_type(name='unsigned int', size=4, is_signed=False), enumerators=(TypeEnumerator('RED', 0), TypeEnumerator('GREEN', 1), TypeEnumerator('BLUE', 2)))",
        )
        self.assertEqual(sizeof(t), 4)

        t = enum_type("color", None, None)
        self.assertEqual(t.kind, TypeKind.ENUM)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertIsNone(t.type)
        self.assertIsNone(t.enumerators)
        self.assertFalse(t.is_complete())

        self.assertEqual(repr(t), "enum_type(tag='color', type=None, enumerators=None)")

        # A type with no enumerators isn't valid in C, but we allow it.
        t = enum_type("color", int_type("unsigned int", 4, False), ())
        self.assertEqual(t.kind, TypeKind.ENUM)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.tag, "color")
        self.assertEqual(t.type, int_type("unsigned int", 4, False))
        self.assertEqual(t.enumerators, ())
        self.assertTrue(t.is_complete())

        self.assertEqual(
            repr(t),
            "enum_type(tag='color', type=int_type(name='unsigned int', size=4, is_signed=False), enumerators=())",
        )

        self.assertRaisesRegex(TypeError, "must be Type", enum_type, "color", 4, ())
        self.assertRaisesRegex(
            ValueError, "must be integer type", enum_type, "color", void_type(), ()
        )
        self.assertRaisesRegex(
            ValueError,
            "must be unqualified",
            enum_type,
            "color",
            int_type("unsigned int", 4, True, Qualifiers.CONST),
            (),
        )
        self.assertRaisesRegex(
            ValueError,
            "must not have compatible type",
            enum_type,
            "color",
            int_type("unsigned int", 4, False),
            None,
        )
        self.assertRaisesRegex(
            ValueError, "must have compatible type", enum_type, "color", None, ()
        )
        self.assertRaisesRegex(
            TypeError,
            "must be sequence or None",
            enum_type,
            "color",
            int_type("unsigned int", 4, False),
            4,
        )
        self.assertRaisesRegex(
            TypeError,
            "must be TypeEnumerator",
            enum_type,
            "color",
            int_type("unsigned int", 4, False),
            (4,),
        )

    def test_typedef(self):
        t = typedef_type("INT", int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.TYPEDEF)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.name, "INT")
        self.assertEqual(t.type, int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        self.assertEqual(t, typedef_type("INT", int_type("int", 4, True)))
        # Qualified type argument.
        self.assertEqual(t, typedef_type("INT", int_type("int", 4, True)))
        # Different name.
        self.assertNotEqual(t, typedef_type("integer", int_type("int", 4, True)))
        # Different type.
        self.assertNotEqual(
            t, typedef_type("integer", int_type("unsigned int", 4, False))
        )
        self.assertNotEqual(
            t, typedef_type("INT", int_type("int", 4, True, Qualifiers.CONST))
        )

        self.assertEqual(
            repr(t),
            "typedef_type(name='INT', type=int_type(name='int', size=4, is_signed=True))",
        )
        self.assertEqual(sizeof(t), 4)

        t = typedef_type("VOID", void_type())
        self.assertFalse(t.is_complete())

        self.assertRaises(TypeError, typedef_type, None, int_type("int", 4, True))
        self.assertRaises(TypeError, typedef_type, "INT", 4)

        self.assertEqual(
            typedef_type("size_t", int_type("unsigned long", 8, False)).primitive,
            PrimitiveType.C_SIZE_T,
        )
        self.assertEqual(
            typedef_type("ptrdiff_t", int_type("long", 8, True)).primitive,
            PrimitiveType.C_PTRDIFF_T,
        )

    def test_pointer(self):
        t = pointer_type(8, int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.POINTER)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.size, 8)
        self.assertEqual(t.type, int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        self.assertEqual(t, pointer_type(8, int_type("int", 4, True)))
        # Qualified type argument.
        self.assertEqual(t, pointer_type(8, int_type("int", 4, True)))
        # Different size.
        self.assertNotEqual(t, pointer_type(4, int_type("int", 4, True)))
        # Different type.
        self.assertNotEqual(t, pointer_type(8, void_type()))
        self.assertNotEqual(t, pointer_type(8, void_type(Qualifiers.CONST)))

        self.assertEqual(
            repr(t),
            "pointer_type(size=8, type=int_type(name='int', size=4, is_signed=True))",
        )
        self.assertEqual(sizeof(t), 8)

        self.assertRaises(TypeError, pointer_type, None, int_type("int", 4, True))
        self.assertRaises(TypeError, pointer_type, 8, 4)

    def test_array(self):
        t = array_type(10, int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.length, 10)
        self.assertEqual(t.type, int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        self.assertEqual(t, array_type(10, int_type("int", 4, True)))
        # Qualified type argument.
        self.assertEqual(t, array_type(10, int_type("int", 4, True)))
        # Different length.
        self.assertNotEqual(t, array_type(4, int_type("int", 4, True)))
        # Different type.
        self.assertNotEqual(t, array_type(10, void_type()))
        self.assertNotEqual(t, array_type(10, void_type(Qualifiers.CONST)))

        self.assertEqual(
            repr(t),
            "array_type(length=10, type=int_type(name='int', size=4, is_signed=True))",
        )
        self.assertEqual(sizeof(t), 40)

        t = array_type(0, int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.length, 0)
        self.assertEqual(t.type, int_type("int", 4, True))
        self.assertTrue(t.is_complete())

        t = array_type(None, int_type("int", 4, True))
        self.assertEqual(t.kind, TypeKind.ARRAY)
        self.assertIsNone(t.primitive)
        self.assertIsNone(t.length)
        self.assertEqual(t.type, int_type("int", 4, True))
        self.assertFalse(t.is_complete())

        self.assertRaises(TypeError, array_type, 10, 4)

    def test_function(self):
        t = function_type(void_type(), (TypeParameter(int_type("int", 4, True), "n"),))
        self.assertEqual(t.kind, TypeKind.FUNCTION)
        self.assertIsNone(t.primitive)
        self.assertEqual(t.language, DEFAULT_LANGUAGE)
        self.assertEqual(t.type, void_type())
        self.assertEqual(t.parameters, (TypeParameter(int_type("int", 4, True), "n"),))
        self.assertFalse(t.is_variadic)
        self.assertTrue(t.is_complete())

        self.assertEqual(
            t,
            function_type(void_type(), (TypeParameter(int_type("int", 4, True), "n"),)),
        )
        # Different return type.
        self.assertNotEqual(
            t,
            function_type(
                int_type("int", 4, True),
                (TypeParameter(int_type("int", 4, True), "n"),),
            ),
        )
        # Different parameter name.
        self.assertNotEqual(
            t,
            function_type(void_type(), (TypeParameter(int_type("int", 4, True), "x"),)),
        )
        # Unnamed parameter.
        self.assertNotEqual(
            t, function_type(void_type(), (TypeParameter(int_type("int", 4, True),),))
        )
        # Different number of parameters.
        self.assertNotEqual(
            t,
            function_type(
                void_type(),
                (
                    TypeParameter(int_type("int", 4, True), "n"),
                    TypeParameter(pointer_type(8, void_type()), "p"),
                ),
            ),
        )
        # One is variadic.
        self.assertNotEqual(
            t,
            function_type(
                void_type(), (TypeParameter(int_type("int", 4, True), "n"),), True
            ),
        )

        self.assertEqual(
            repr(t),
            "function_type(type=void_type(), parameters=(TypeParameter(type=int_type(name='int', size=4, is_signed=True), name='n'),), is_variadic=False)",
        )
        self.assertRaises(TypeError, sizeof, t)

        self.assertFalse(function_type(void_type(), (), False).is_variadic)
        self.assertTrue(function_type(void_type(), (), True).is_variadic)

        self.assertRaisesRegex(TypeError, "must be Type", function_type, None, ())
        self.assertRaisesRegex(
            TypeError, "must be sequence", function_type, void_type(), None
        )
        self.assertRaisesRegex(
            TypeError, "must be TypeParameter", function_type, void_type(), (4,)
        )

    def test_cycle(self):
        t1 = struct_type("foo", 8, (TypeMember(lambda: pointer_type(8, t1), "next"),))
        t2 = struct_type("foo", 8, (TypeMember(lambda: pointer_type(8, t2), "next"),))
        t3, t4 = (
            struct_type("foo", 8, (TypeMember(lambda: pointer_type(8, t4), "next"),)),
            struct_type("foo", 8, (TypeMember(lambda: pointer_type(8, t3), "next"),)),
        )
        self.assertEqual(t1, t2)
        self.assertEqual(t2, t3)
        self.assertEqual(t3, t4)

        self.assertEqual(
            repr(t1),
            "struct_type(tag='foo', size=8, members=(TypeMember(type=pointer_type(size=8, type=struct_type(tag='foo', ...)), name='next', bit_offset=0),))",
        )

    def test_cycle2(self):
        t1 = struct_type(
            "list_head",
            16,
            (
                TypeMember(lambda: pointer_type(8, t1), "next"),
                TypeMember(lambda: pointer_type(8, t1), "prev", 8),
            ),
        )
        t2 = struct_type(
            "list_head",
            16,
            (
                TypeMember(lambda: pointer_type(8, t2), "next"),
                TypeMember(lambda: pointer_type(8, t2), "prev", 8),
            ),
        )
        self.assertEqual(t1, t2)

        self.assertEqual(
            repr(t1),
            "struct_type(tag='list_head', size=16, members=(TypeMember(type=pointer_type(size=8, type=struct_type(tag='list_head', ...)), name='next', bit_offset=0), TypeMember(type=pointer_type(size=8, type=struct_type(tag='list_head', ...)), name='prev', bit_offset=8)))",
        )

    def test_infinite(self):
        f = lambda: struct_type("foo", 0, (TypeMember(f, "next"),))
        self.assertEqual(
            repr(f()),
            "struct_type(tag='foo', size=0, members=(TypeMember(type=struct_type(tag='foo', ...), name='next', bit_offset=0),))",
        )
        with self.assertRaisesRegex(RecursionError, "maximum.*depth"):
            f() == f()

    def test_bad_thunk(self):
        t1 = struct_type(
            "foo", 16, (TypeMember(lambda: exec('raise Exception("test")'), "bar"),)
        )
        with self.assertRaisesRegex(Exception, "test"):
            t1.members[0].type
        t1 = struct_type("foo", 16, (TypeMember(lambda: 0, "bar"),))
        with self.assertRaisesRegex(TypeError, "type callable must return Type"):
            t1.members[0].type

    def test_qualifiers(self):
        self.assertEqual(void_type().qualifiers, Qualifiers(0))

        t = void_type(Qualifiers.CONST | Qualifiers.VOLATILE)
        self.assertEqual(t.qualifiers, Qualifiers.CONST | Qualifiers.VOLATILE)
        self.assertEqual(
            repr(t), "void_type(qualifiers=<Qualifiers.VOLATILE|CONST: 3>)"
        )

        self.assertEqual(t.qualified(Qualifiers.ATOMIC), void_type(Qualifiers.ATOMIC))
        self.assertEqual(t.unqualified(), void_type())
        self.assertEqual(t.qualified(Qualifiers(0)), t.unqualified())

        self.assertRaisesRegex(TypeError, "expected Qualifiers or None", void_type, 1.5)

    def test_language(self):
        self.assertEqual(void_type(language=None).language, DEFAULT_LANGUAGE)
        self.assertEqual(void_type(language=Language.C).language, Language.C)

        self.assertEqual(
            int_type("int", 4, True, language=Language.CPP).language, Language.CPP
        )

    def test_cmp(self):
        self.assertEqual(void_type(), void_type())
        self.assertEqual(void_type(Qualifiers.CONST), void_type(Qualifiers.CONST))
        self.assertNotEqual(void_type(), void_type(Qualifiers.CONST))
        self.assertNotEqual(void_type(), int_type("int", 4, True))
        self.assertNotEqual(void_type(), 1)
        self.assertNotEqual(1, void_type())


class TestTypeEnumerator(unittest.TestCase):
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


class TestTypeMember(unittest.TestCase):
    def test_init(self):
        m = TypeMember(void_type())
        self.assertEqual(m.type, void_type())
        self.assertIsNone(m.name)
        self.assertEqual(m.bit_offset, 0)
        self.assertEqual(m.offset, 0)
        self.assertEqual(m.bit_field_size, 0)

        m = TypeMember(void_type(), "foo")
        self.assertEqual(m.type, void_type())
        self.assertEqual(m.name, "foo")
        self.assertEqual(m.bit_offset, 0)
        self.assertEqual(m.offset, 0)
        self.assertEqual(m.bit_field_size, 0)

        m = TypeMember(void_type(), "foo", 8)
        self.assertEqual(m.type, void_type())
        self.assertEqual(m.name, "foo")
        self.assertEqual(m.bit_offset, 8)
        self.assertEqual(m.offset, 1)
        self.assertEqual(m.bit_field_size, 0)

        m = TypeMember(void_type(), "foo", 9, 7)
        self.assertEqual(m.type, void_type())
        self.assertEqual(m.name, "foo")
        self.assertEqual(m.bit_offset, 9)
        self.assertRaises(ValueError, getattr, m, "offset")
        self.assertEqual(m.bit_field_size, 7)

        self.assertRaises(TypeError, TypeMember, None)
        self.assertRaises(TypeError, TypeMember, void_type(), 1)
        self.assertRaises(TypeError, TypeMember, void_type(), "foo", None)
        self.assertRaises(TypeError, TypeMember, void_type(), "foo", 0, None)

    def test_callable(self):
        m = TypeMember(void_type)
        self.assertEqual(m.type, void_type())

        m = TypeMember(lambda: int_type("int", 4, True))
        self.assertEqual(m.type, int_type("int", 4, True))

        m = TypeMember(lambda: None)
        self.assertRaises(TypeError, getattr, m, "type")

    def test_repr(self):
        m = TypeMember(type=void_type, name="foo")
        self.assertEqual(
            repr(m), "TypeMember(type=void_type(), name='foo', bit_offset=0)"
        )

        m = TypeMember(type=void_type, bit_field_size=4)
        self.assertEqual(
            repr(m),
            "TypeMember(type=void_type(), name=None, bit_offset=0, bit_field_size=4)",
        )

        m = TypeMember(lambda: None)
        self.assertRaises(TypeError, repr, m)

    def test_cmp(self):
        self.assertEqual(TypeMember(void_type()), TypeMember(void_type(), None, 0, 0))
        self.assertEqual(
            TypeMember(bit_offset=9, bit_field_size=7, type=void_type, name="foo"),
            TypeMember(void_type(), "foo", 9, 7),
        )
        self.assertNotEqual(
            TypeMember(int_type("int", 4, True)), TypeMember(void_type(), None, 0, 0)
        )
        self.assertNotEqual(
            TypeMember(void_type(), "foo"), TypeMember(void_type(), None, 0, 0)
        )
        self.assertNotEqual(
            TypeMember(void_type(), bit_offset=8), TypeMember(void_type(), None, 0, 0)
        )
        self.assertNotEqual(
            TypeMember(void_type(), bit_field_size=8),
            TypeMember(void_type(), None, 0, 0),
        )


class TestTypeParameter(unittest.TestCase):
    def test_init(self):
        p = TypeParameter(void_type())
        self.assertEqual(p.type, void_type())
        self.assertIsNone(p.name)

        p = TypeParameter(void_type(), "foo")
        self.assertEqual(p.type, void_type())
        self.assertEqual(p.name, "foo")

        self.assertRaises(TypeError, TypeParameter, None)
        self.assertRaises(TypeError, TypeParameter, void_type(), 1)

    def test_callable(self):
        p = TypeParameter(void_type)
        self.assertEqual(p.type, void_type())

        p = TypeParameter(lambda: int_type("int", 4, True))
        self.assertEqual(p.type, int_type("int", 4, True))

        p = TypeParameter(lambda: None)
        self.assertRaises(TypeError, getattr, p, "type")

    def test_repr(self):
        p = TypeParameter(type=void_type, name="foo")
        self.assertEqual(repr(p), "TypeParameter(type=void_type(), name='foo')")

        p = TypeParameter(type=void_type)
        self.assertEqual(repr(p), "TypeParameter(type=void_type(), name=None)")

        p = TypeParameter(lambda: None)
        self.assertRaises(TypeError, repr, p)

    def test_cmp(self):
        self.assertEqual(TypeParameter(void_type()), TypeParameter(void_type(), None))
        self.assertEqual(
            TypeParameter(name="foo", type=void_type), TypeParameter(void_type(), "foo")
        )
        self.assertNotEqual(
            TypeParameter(int_type("int", 4, True)), TypeParameter(void_type(), None)
        )
        self.assertNotEqual(
            TypeParameter(void_type(), "foo"), TypeParameter(void_type(), None)
        )
