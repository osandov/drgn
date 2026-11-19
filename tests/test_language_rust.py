# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Language, Object, Qualifiers, TypeEnumerator, TypeMember, TypeParameter
from tests import MockProgramTestCase, TestCase, mock_program


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


class TestFormatType(RustTestCase):
    def assertPrettyPrint(self, type, expected):
        self.assertEqual(str(type), expected)

    def test_struct(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "Node",
                16,
                (
                    TypeMember(
                        self.prog.pointer_type(self.point, name="&mut Point"), "next"
                    ),
                    TypeMember(self.prog.array_type(self.u8, 4), "buf", 64),
                ),
            ),
            """\
struct Node {
	next: &mut Point,
	buf: [u8; 4],
}""",
        )

    def test_bit_field(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "S",
                4,
                (TypeMember(Object(self.prog, self.i32, bit_field_size=3), "x"),),
            ),
            """\
struct S {
	x: i32 /* : 3 */,
}""",
        )

    def test_tuple_struct(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "Pair",
                16,
                (
                    TypeMember(self.u8, "__0"),
                    TypeMember(self.prog.int_type("u64", 8, False), "__1", 64),
                ),
            ),
            "struct Pair(u8, u64);",
        )

    def test_not_tuple_struct(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "S", 2, (TypeMember(self.u8, "__1"), TypeMember(self.u8, "__0", 8))
            ),
            """\
struct S {
	__1: u8,
	__0: u8,
}""",
        )

    def test_unit_struct(self):
        self.assertPrettyPrint(self.prog.struct_type("Unit", 0, ()), "struct Unit;")

    def test_anonymous_struct(self):
        self.assertPrettyPrint(
            self.prog.struct_type(None, 4, (TypeMember(self.i32, "x"),)),
            """\
struct {
	x: i32,
}""",
        )

    def test_incomplete_struct(self):
        self.assertPrettyPrint(self.prog.struct_type("Point"), "Point")

    def test_tuple(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "(i32, u8)",
                8,
                (TypeMember(self.i32, "__0"), TypeMember(self.u8, "__1", 32)),
            ),
            "(i32, u8)",
        )

    def test_union(self):
        self.assertPrettyPrint(
            self.prog.union_type(
                "U",
                4,
                (
                    TypeMember(self.prog.int_type("u32", 4, False), "i"),
                    TypeMember(self.prog.float_type("f32", 4), "f"),
                ),
            ),
            """\
union U {
	i: u32,
	f: f32,
}""",
        )
        self.assertPrettyPrint(self.prog.union_type("U", 0, ()), "union U {}")

    def test_enum(self):
        self.assertPrettyPrint(
            self.prog.enum_type(
                "Color", self.u8, (TypeEnumerator("Red", 1), TypeEnumerator("Blue", 4))
            ),
            """\
enum Color {
	Red = 1,
	Blue = 4,
}""",
        )
        self.assertPrettyPrint(
            self.prog.enum_type(
                "Sign",
                self.prog.int_type("i8", 1, True),
                (TypeEnumerator("Minus", -1), TypeEnumerator("Plus", 1)),
            ),
            """\
enum Sign {
	Minus = -1,
	Plus = 1,
}""",
        )
        self.assertPrettyPrint(
            self.prog.enum_type("Never", self.u8, ()), "enum Never {}"
        )

    def test_discr_union(self):
        u32 = self.prog.int_type("u32", 4, False)
        f64 = self.prog.float_type("f64", 8)
        self.assertPrettyPrint(
            self.prog.union_type(
                "Shape",
                24,
                (
                    TypeMember(u32),
                    TypeMember(
                        self.prog.struct_type(
                            "Circle",
                            24,
                            (
                                TypeMember(self.point, "center", 32),
                                TypeMember(f64, "radius", 128),
                            ),
                        ),
                        "Circle",
                    ),
                    TypeMember(
                        self.prog.struct_type(
                            "Rect",
                            20,
                            (
                                TypeMember(self.point, "__0", 32),
                                TypeMember(self.point, "__1", 96),
                            ),
                        ),
                        "Rect",
                    ),
                    TypeMember(self.prog.struct_type("Empty", 24, ()), "Empty"),
                    TypeMember(u32, "Raw"),
                ),
                discriminants=(0, 1, 2, None),
            ),
            """\
enum Shape {
	/* discriminant: u32 */
	Circle { center: Point, radius: f64 }, /* 0 */
	Rect(Point, Point), /* 1 */
	Empty, /* 2 */
	Raw(u32), /* default */
}""",
        )

    def test_discr_union_signed(self):
        i8 = self.prog.int_type("i8", 1, True)
        self.assertPrettyPrint(
            self.prog.union_type(
                "S",
                2,
                (
                    TypeMember(i8),
                    TypeMember(self.prog.struct_type("A", 2, ()), "A"),
                    TypeMember(self.prog.struct_type("B", 2, ()), "B"),
                ),
                discriminants=(-1, 1),
            ),
            """\
enum S {
	/* discriminant: i8 */
	A, /* -1 */
	B, /* 1 */
}""",
        )

    def test_typedef(self):
        self.assertPrettyPrint(
            self.prog.typedef_type("Bytes", self.prog.array_type(self.u8, 4)),
            "type Bytes = [u8; 4];",
        )

    def test_name_only(self):
        self.assertPrettyPrint(self.i32, "i32")
        self.assertPrettyPrint(self.prog.pointer_type(self.point), "*mut Point")
        self.assertPrettyPrint(self.prog.array_type(self.point, 2), "[Point; 2]")


class TestVariableDeclaration(RustTestCase):
    def test_variable_declaration(self):
        self.assertEqual(self.i32.variable_declaration("x"), "x: i32")
        self.assertEqual(
            self.prog.array_type(self.u8, 4).variable_declaration("buf"), "buf: [u8; 4]"
        )
        self.assertEqual(
            self.prog.pointer_type(self.point, name="&Point").variable_declaration("p"),
            "p: &Point",
        )


class TestFindType(TestCase):
    def setUp(self):
        super().setUp()
        self.types = []
        self.prog = mock_program(types=self.types)
        self.prog.language = Language.RUST
        self.point = self.prog.struct_type("Point", 8, ())

        def rust_struct(name, size=8):
            return self.prog.struct_type(name, size, ())

        self.types.extend(
            [
                self.point,
                self.prog.int_type("u32", 4, False),
                rust_struct("Vec<i32, Global>", 24),
                rust_struct("Option<&[u8]>", 16),
                rust_struct("Pin<Box<dyn Future<Output=()>>>", 16),
                rust_struct("Array<3>", 3),
                rust_struct("Ref<u8>"),
                rust_struct("(i32, u8)"),
                rust_struct("(u8,)", 1),
                rust_struct("()", 0),
                rust_struct("!", 0),
                rust_struct("dyn Foo + Send", 0),
                rust_struct("&str", 16),
                rust_struct("<Dog as Animal>::{vtable_type}", 24),
                rust_struct("core::{impl#0}::Foo"),
            ]
        )

    def assertFindType(self, name, expected):
        self.assertIdentical(self.prog.type(name), expected)

    def test_found(self):
        for name, expected in (
            ("Point", self.point),
            ("u32", self.types[1]),
            ("Vec< i32 ,Global >", self.types[2]),
            ("Option<&[u8]>", self.types[3]),
            ("Pin<Box<dyn Future<Output = ()>>>", self.types[4]),
            ("Array<3>", self.types[5]),
            ("Ref<'a, u8>", self.types[6]),
            ("( i32 , u8 )", self.types[7]),
            ("(i32, u8,)", self.types[7]),
            ("(u8,)", self.types[8]),
            ("( )", self.types[9]),
            ("!", self.types[10]),
            ("dyn Foo+Send+'static", self.types[11]),
            ("&str", self.types[12]),
            ("< Dog as Animal >::{vtable_type}", self.types[13]),
            ("core::{impl#0}::Foo", self.types[14]),
            ("(Point)", self.point),
        ):
            with self.subTest(name=name):
                self.assertFindType(name, expected)

    def test_primitive(self):
        for name, expected in (
            ("bool", self.prog.bool_type("bool", 1)),
            ("char", self.prog.int_type("char", 4, False)),
            ("i8", self.prog.int_type("i8", 1, True)),
            ("u128", self.prog.int_type("u128", 16, False)),
            ("isize", self.prog.int_type("isize", 8, True)),
            ("usize", self.prog.int_type("usize", 8, False)),
            ("f32", self.prog.float_type("f32", 4)),
            ("f64", self.prog.float_type("f64", 8)),
        ):
            with self.subTest(name=name):
                self.assertFindType(name, expected)

    def test_pointer(self):
        for name, canonical in (
            ("&Point", "&Point"),
            ("&'a Point", "&Point"),
            ("& mut Point", "&mut Point"),
            ("*const Point", "*const Point"),
            ("*mut Point", "*mut Point"),
        ):
            with self.subTest(name=name):
                self.assertFindType(
                    name, self.prog.pointer_type(self.point, name=canonical)
                )
        self.assertEqual(self.prog.type("&Point")._ptr, self.prog.type("&Point")._ptr)
        self.assertFindType(
            "&&str", self.prog.pointer_type(self.types[12], name="&&str")
        )

    def test_array(self):
        self.assertFindType("[Point; 4]", self.prog.array_type(self.point, 4))
        self.assertFindType("[Point; 0x10]", self.prog.array_type(self.point, 16))
        self.assertFindType("[Point]", self.prog.array_type(self.point))
        self.assertFindType(
            "[&Point; 2]",
            self.prog.array_type(self.prog.pointer_type(self.point, name="&Point"), 2),
        )

    def test_not_found(self):
        for name in (
            "Nope",
            "rtest::Point",
            "Vec<u8>",
            "str",
            "&[Point]",
            "&dyn Foo",
            "*const (dyn Foo + Send)",
            "&mut str",
        ):
            with self.subTest(name=name):
                self.assertRaisesRegex(
                    LookupError, "could not find", self.prog.type, name
                )

    def test_not_implemented(self):
        for name in ("fn(u8) -> u8", "unsafe fn()", 'extern "C" fn()'):
            with self.subTest(name=name):
                self.assertRaisesRegex(
                    NotImplementedError,
                    "function pointer types are not implemented",
                    self.prog.type,
                    name,
                )

    def test_syntax_error(self):
        for name, message in (
            ("", "expected type"),
            ("&", "expected type"),
            ("*Point", "expected 'const' or 'mut'"),
            ("[Point; x]", "expected array length"),
            ("[Point; 4", "expected ']'"),
            ("Vec<u8", "expected ',' or '>'"),
            ("(u8 u8)", "expected ',' or '\\)'"),
            ("Point Point", "expected end of type name"),
            ("<Dog Animal>::X", "expected 'as'"),
            ("a:b", "expected '::'"),
            ("Point$", "invalid character"),
        ):
            with self.subTest(name=name):
                self.assertRaisesRegex(SyntaxError, message, self.prog.type, name)
