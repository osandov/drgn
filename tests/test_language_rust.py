# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Language, Object, Qualifiers, TypeMember, TypeParameter
from tests import MockProgramTestCase


class RustTestCase(MockProgramTestCase):
    def setUp(self):
        super().setUp()
        self.prog.language = Language.RUST
        self.i32 = self.prog.int_type("i32", 4, True)
        self.u8 = self.prog.int_type("u8", 1, False)
        self.point = self.prog.struct_type(
            "Point", 8, (TypeMember(self.i32, "x", 0), TypeMember(self.i32, "y", 32))
        )


class TestFormatTypeName(RustTestCase):
    def assertTypeName(self, type, expected):
        self.assertEqual(type.type_name(), expected)

    def test_void(self):
        self.assertTypeName(self.prog.void_type(), "()")

    def test_int(self):
        self.assertTypeName(self.i32, "i32")
        self.assertTypeName(self.i32.qualified(Qualifiers.CONST), "i32")

    def test_bool(self):
        self.assertTypeName(self.prog.bool_type("bool", 1), "bool")

    def test_float(self):
        self.assertTypeName(self.prog.float_type("f64", 8), "f64")

    def test_typedef(self):
        self.assertTypeName(self.prog.typedef_type("Alias", self.i32), "Alias")

    def test_tagged(self):
        self.assertTypeName(self.point, "Point")
        self.assertTypeName(self.prog.union_type("U", 4, ()), "U")
        self.assertTypeName(self.prog.enum_type("Color", self.u8, ()), "Color")
        self.assertTypeName(self.prog.struct_type("Option<u32>", 8, ()), "Option<u32>")

    def test_anonymous(self):
        self.assertTypeName(self.prog.struct_type(None, 0, ()), "struct <anonymous>")
        self.assertTypeName(self.prog.union_type(None, 0, ()), "union <anonymous>")

    def test_named_pointer(self):
        self.assertTypeName(
            self.prog.pointer_type(self.point, name="&rtest::Point"), "&rtest::Point"
        )
        self.assertTypeName(
            self.prog.pointer_type(
                self.point.qualified(Qualifiers.CONST), name="&mut rtest::Point"
            ),
            "&mut rtest::Point",
        )

    def test_unnamed_pointer(self):
        self.assertTypeName(self.prog.pointer_type(self.point), "*mut Point")
        self.assertTypeName(
            self.prog.pointer_type(self.point.qualified(Qualifiers.CONST)),
            "*const Point",
        )
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.pointer_type(self.i32.qualified(Qualifiers.CONST))
            ),
            "*mut *const i32",
        )
        self.assertTypeName(self.prog.pointer_type(self.prog.void_type()), "*mut ()")

    def test_array(self):
        self.assertTypeName(self.prog.array_type(self.i32, 4), "[i32; 4]")
        self.assertTypeName(self.prog.array_type(self.i32), "[i32]")
        self.assertTypeName(
            self.prog.array_type(self.prog.array_type(self.u8, 2), 3), "[[u8; 2]; 3]"
        )
        self.assertTypeName(
            self.prog.array_type(self.prog.pointer_type(self.u8), 2), "[*mut u8; 2]"
        )

    def test_function(self):
        self.assertTypeName(
            self.prog.function_type(
                self.i32, (TypeParameter(self.u8), TypeParameter(self.point))
            ),
            "fn(u8, Point) -> i32",
        )
        self.assertTypeName(
            self.prog.function_type(self.prog.void_type(), (TypeParameter(self.u8),)),
            "fn(u8)",
        )
        self.assertTypeName(
            self.prog.function_type(
                self.prog.void_type(), (TypeParameter(self.u8),), True
            ),
            "fn(u8, ...)",
        )
        self.assertTypeName(
            self.prog.function_type(self.i32, (), True), "fn(...) -> i32"
        )

    def test_function_pointer(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(self.i32, (TypeParameter(self.u8),))
            ),
            "fn(u8) -> i32",
        )


class TestFormatObject(RustTestCase):
    def test_struct(self):
        self.assertEqual(
            str(Object(self.prog, self.point, {"x": 1, "y": 2})),
            """\
(Point){
	.x = (i32)1,
	.y = (i32)2,
}""",
        )

    def test_pointer(self):
        self.assertEqual(
            str(
                Object(
                    self.prog,
                    self.prog.pointer_type(self.point, name="&rtest::Point"),
                    0xFFFF0000,
                )
            ),
            "(&rtest::Point)0xffff0000",
        )

    def test_array(self):
        self.assertEqual(
            str(Object(self.prog, self.prog.array_type(self.u8, 2), [1, 2])),
            "([u8; 2]){ 1, 2 }",
        )
