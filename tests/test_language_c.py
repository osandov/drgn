# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import reduce
import operator
import unittest

from drgn import (
    Object,
    Qualifiers,
    Type,
    TypeEnumerator,
    TypeMember,
    TypeParameter,
    cast,
    container_of,
)
from tests import MockProgramTestCase
from tests.libdrgn import C_TOKEN, Lexer, drgn_lexer_c


class TestPrettyPrintTypeName(MockProgramTestCase):
    def assertTypeName(self, type, expected, same_as_definition=False):
        self.assertEqual(type.type_name(), expected)
        if same_as_definition:
            self.assertEqual(str(type), expected)

    def assertQualifiedTypeName(self, expected, same_as_definition, constructor, *args):
        self.assertEqual(constructor(*args).type_name(), expected)
        qualifiers = [
            (Qualifiers.CONST, "const"),
            (Qualifiers.VOLATILE, "volatile"),
            (Qualifiers.RESTRICT, "restrict"),
            (Qualifiers.ATOMIC, "_Atomic"),
        ]
        for qualifier in qualifiers:
            t = constructor(*args, qualifiers=qualifier[0])
            self.assertTypeName(t, qualifier[1] + " " + expected, same_as_definition)

        # All qualifiers.
        t = constructor(
            *args,
            qualifiers=reduce(operator.or_, (qualifier[0] for qualifier in qualifiers)),
        )
        self.assertTypeName(
            t,
            " ".join(qualifier[1] for qualifier in qualifiers) + " " + expected,
            same_as_definition,
        )

    def test_void(self):
        self.assertQualifiedTypeName("void", True, self.prog.void_type)

    def test_int(self):
        self.assertQualifiedTypeName("int", True, self.prog.int_type, "int", 4, True)

    def test_bool(self):
        self.assertQualifiedTypeName("_Bool", True, self.prog.bool_type, "_Bool", 1)

    def test_float(self):
        self.assertQualifiedTypeName("float", True, self.prog.float_type, "float", 4)

    def test_struct(self):
        self.assertQualifiedTypeName(
            "struct point", True, self.prog.struct_type, "point"
        )
        self.assertQualifiedTypeName(
            "struct <anonymous>", False, self.prog.struct_type, None
        )

    def test_union(self):
        self.assertQualifiedTypeName(
            "union option", True, self.prog.union_type, "option"
        ),
        self.assertQualifiedTypeName(
            "union <anonymous>", False, self.prog.union_type, None
        )

    def test_class(self):
        self.assertQualifiedTypeName("class coord", True, self.prog.class_type, "coord")
        self.assertQualifiedTypeName(
            "class <anonymous>", False, self.prog.class_type, None
        )

    def test_enum(self):
        self.assertQualifiedTypeName(
            "enum color", True, self.prog.enum_type, "color", None, None
        ),
        self.assertQualifiedTypeName(
            "enum <anonymous>", False, self.prog.enum_type, None, None, None
        )

    def test_typedef(self):
        self.assertQualifiedTypeName(
            "bool",
            False,
            self.prog.typedef_type,
            "bool",
            self.prog.bool_type("_Bool", 1),
        )

    def test_pointer(self):
        self.assertTypeName(
            self.prog.pointer_type(self.prog.void_type()), "void *", True
        )
        t = self.prog.pointer_type(self.prog.void_type(qualifiers=Qualifiers.VOLATILE))
        self.assertTypeName(t, "volatile void *", True)
        t = self.prog.pointer_type(
            self.prog.void_type(qualifiers=Qualifiers.VOLATILE),
            qualifiers=Qualifiers.CONST,
        )
        self.assertTypeName(t, "volatile void * const", True)
        t = self.prog.pointer_type(t)
        self.assertTypeName(t, "volatile void * const *", True)

    def test_array(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(self.prog.array_type(i), "int []", True)
        self.assertTypeName(self.prog.array_type(i, 2), "int [2]", True)
        self.assertTypeName(
            self.prog.array_type(self.prog.array_type(i, 3), 2), "int [2][3]", True
        )
        self.assertTypeName(
            self.prog.array_type(
                self.prog.array_type(self.prog.array_type(i, 4), 3), 2
            ),
            "int [2][3][4]",
            True,
        )

    def test_array_of_pointers(self):
        self.assertTypeName(
            self.prog.array_type(
                self.prog.array_type(
                    self.prog.pointer_type(self.prog.int_type("int", 4, True)), 3
                ),
                2,
            ),
            "int *[2][3]",
            True,
        )

    def test_pointer_to_array(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.array_type(self.prog.int_type("int", 4, True), 2)
            ),
            "int (*)[2]",
            True,
        )

    def test_pointer_to_pointer_to_array(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.pointer_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 2)
                )
            ),
            "int (**)[2]",
            True,
        )

    def test_pointer_to_array_of_pointers(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.array_type(
                    self.prog.pointer_type(self.prog.int_type("int", 4, True)), 2
                )
            ),
            "int *(*)[2]",
            True,
        )

    def test_array_of_pointers_to_array(self):
        self.assertTypeName(
            self.prog.array_type(
                self.prog.pointer_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 3)
                ),
                2,
            ),
            "int (*[2])[3]",
            True,
        )

    def test_pointer_to_function(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(i, (TypeParameter(i),), False)
            ),
            "int (*)(int)",
            True,
        )
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(i, (TypeParameter(i, "x"),), False)
            ),
            "int (*)(int x)",
            True,
        )
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    i,
                    (
                        TypeParameter(i),
                        TypeParameter(self.prog.float_type("float", 4)),
                    ),
                    False,
                ),
            ),
            "int (*)(int, float)",
            True,
        )

    def test_pointer_to_function_returning_pointer(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    self.prog.pointer_type(i), (TypeParameter(i),), False
                )
            ),
            "int *(*)(int)",
            True,
        )
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    self.prog.pointer_type(i),
                    (TypeParameter(self.prog.pointer_type(i)),),
                    False,
                ),
            ),
            "int *(*)(int *)",
            True,
        )

    def test_pointer_to_function_returning_pointer_to_const(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    self.prog.pointer_type(
                        self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST)
                    ),
                    (TypeParameter(i),),
                    False,
                ),
            ),
            "const int *(*)(int)",
            True,
        )

    def test_pointer_to_function_returning_const_pointer(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    self.prog.pointer_type(i, qualifiers=Qualifiers.CONST),
                    (TypeParameter(i),),
                    False,
                ),
            ),
            "int * const (*)(int)",
            True,
        )

    def test_const_pointer_to_function_returning_pointer(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(
                    self.prog.pointer_type(i), (TypeParameter(i),), False
                ),
                qualifiers=Qualifiers.CONST,
            ),
            "int *(* const)(int)",
            True,
        )

    def test_array_of_pointers_to_functions(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.array_type(
                self.prog.pointer_type(
                    self.prog.function_type(i, (TypeParameter(i),), False)
                ),
                4,
            ),
            "int (*[4])(int)",
            True,
        )

    def test_array_of_const_pointers_to_functions(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.array_type(
                self.prog.pointer_type(
                    self.prog.function_type(i, (TypeParameter(i),), False),
                    qualifiers=Qualifiers.CONST,
                ),
            ),
            "int (* const [])(int)",
            True,
        )

    def test_pointer_to_variadic_function(self):
        i = self.prog.int_type("int", 4, True)
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(i, (TypeParameter(i),), True)
            ),
            "int (*)(int, ...)",
            True,
        )

    def test_pointer_to_function_with_no_parameters(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(self.prog.int_type("int", 4, True), (), False)
            ),
            "int (*)(void)",
            True,
        )

    def test_pointer_to_function_with_no_parameter_specification(self):
        self.assertTypeName(
            self.prog.pointer_type(
                self.prog.function_type(self.prog.int_type("int", 4, True), (), True)
            ),
            "int (*)()",
            True,
        )

    def test_function(self):
        self.assertTypeName(
            self.prog.function_type(self.prog.int_type("int", 4, True), (), False),
            "int (void)",
        )


class TestPrettyPrintType(MockProgramTestCase):
    def assertPrettyPrint(self, type, expected):
        self.assertEqual(str(type), expected)

    def test_struct(self):
        self.assertPrettyPrint(
            self.point_type,
            """\
struct point {
	int x;
	int y;
}""",
        )

    def test_struct_member(self):
        self.assertPrettyPrint(
            self.line_segment_type,
            """\
struct line_segment {
	struct point a;
	struct point b;
}""",
        )

    def test_anonymous_struct(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                None,
                8,
                (
                    TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                    TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                ),
            ),
            """\
struct {
	int x;
	int y;
}""",
        )

    def test_anonymous_struct_member(self):
        # Member with anonymous struct type.
        anonymous_struct = self.prog.struct_type(
            None,
            8,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertPrettyPrint(
            self.prog.struct_type(
                "line_segment",
                16,
                (
                    TypeMember(anonymous_struct, "a", 0),
                    TypeMember(anonymous_struct, "b", 64),
                ),
            ),
            """\
struct line_segment {
	struct {
		int x;
		int y;
	} a;
	struct {
		int x;
		int y;
	} b;
}""",
        )

    def test_struct_unnamed_member(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "point3",
                0,
                (
                    TypeMember(
                        self.prog.struct_type(
                            None,
                            8,
                            (
                                TypeMember(self.prog.int_type("int", 4, True), "x"),
                                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                            ),
                        )
                    ),
                    TypeMember(self.prog.int_type("int", 4, True), "z", 64),
                ),
            ),
            """\
struct point3 {
	struct {
		int x;
		int y;
	};
	int z;
}""",
        )

    def test_bit_field(self):
        self.assertPrettyPrint(
            self.prog.struct_type(
                "point",
                4,
                (
                    TypeMember(
                        Object(
                            self.prog,
                            self.prog.int_type("int", 4, True),
                            bit_field_size=4,
                        ),
                        "x",
                        0,
                    ),
                    TypeMember(
                        Object(
                            self.prog,
                            self.prog.int_type("int", 4, True),
                            bit_field_size=8,
                        ),
                        "y",
                        4,
                    ),
                ),
            ),
            """\
struct point {
	int x : 4;
	int y : 8;
}""",
        )

    def test_union(self):
        self.assertPrettyPrint(
            self.prog.union_type(
                "foo",
                4,
                (
                    TypeMember(self.prog.int_type("int", 4, True), "i"),
                    TypeMember(
                        self.prog.array_type(
                            self.prog.int_type("unsigned char", 1, False), 4
                        ),
                        "a",
                    ),
                ),
            ),
            """\
union foo {
	int i;
	unsigned char a[4];
}""",
        )

    def test_union_qualified(self):
        self.assertPrettyPrint(
            self.prog.union_type(
                "foo",
                4,
                (
                    TypeMember(self.prog.int_type("int", 4, True), "i"),
                    TypeMember(
                        self.prog.array_type(
                            self.prog.int_type("unsigned char", 1, False), 4
                        ),
                        "a",
                    ),
                ),
                qualifiers=Qualifiers.CONST,
            ),
            """\
const union foo {
	int i;
	unsigned char a[4];
}""",
        )

    def test_class(self):
        self.assertPrettyPrint(
            self.coord_type,
            """\
class coord {
	int x;
	int y;
	int z;
}""",
        )

    def test_enum(self):
        self.assertPrettyPrint(
            self.color_type,
            """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""",
        )

    def test_enum_qualified(self):
        self.assertPrettyPrint(
            self.color_type.qualified(Qualifiers.CONST),
            """\
const enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""",
        )

    def test_enum_anonymous(self):
        self.assertPrettyPrint(
            self.prog.enum_type(
                None,
                self.prog.int_type("int", 4, True),
                (
                    TypeEnumerator("RED", 0),
                    TypeEnumerator("GREEN", -1),
                    TypeEnumerator("BLUE", -2),
                ),
            ),
            """\
enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
}""",
        )

    def test_typedef(self):
        self.assertPrettyPrint(
            self.prog.typedef_type("INT", self.prog.int_type("int", 4, True)),
            "typedef int INT",
        )

    def test_typedef_const(self):
        self.assertPrettyPrint(
            self.prog.typedef_type(
                "CINT", self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST)
            ),
            "typedef const int CINT",
        )

    def test_const_typedef(self):
        self.assertPrettyPrint(
            self.prog.typedef_type(
                "INT", self.prog.int_type("int", 4, True), qualifiers=Qualifiers.CONST
            ),
            "const typedef int INT",
        )

    def test_typedef_pointer(self):
        self.assertPrettyPrint(
            self.prog.typedef_type(
                "string", self.prog.pointer_type(self.prog.int_type("char", 1, True))
            ),
            "typedef char *string",
        )

    def test_typedef_struct(self):
        self.assertPrettyPrint(
            self.prog.typedef_type(
                "Point",
                self.prog.struct_type(
                    None,
                    8,
                    (
                        TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                        TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                    ),
                ),
            ),
            """\
typedef struct {
	int x;
	int y;
} Point""",
        )

    def test_typedef_function(self):
        self.assertPrettyPrint(
            self.prog.typedef_type(
                "fn",
                self.prog.function_type(self.prog.int_type("int", 4, True), (), False),
            ),
            "typedef int fn(void)",
        )

    def test_function_no_name(self):
        self.assertRaisesRegex(
            ValueError,
            "function must have name",
            str,
            self.prog.struct_type(
                "foo",
                8,
                (
                    TypeMember(
                        self.prog.function_type(
                            self.prog.int_type("int", 4, True), (), False
                        )
                    ),
                ),
            ),
        )


class TestLexer(unittest.TestCase):
    def lex(self, s):
        lexer = Lexer(drgn_lexer_c, s)
        while True:
            token = lexer.pop()
            if token.kind == C_TOKEN.EOF:
                break
            yield token

    def test_empty(self):
        lexer = Lexer(drgn_lexer_c, "")
        for i in range(64):
            self.assertEqual(lexer.pop().kind, C_TOKEN.EOF)

    def test_symbols(self):
        s = "()[]*."
        tokens = [
            C_TOKEN.LPAREN,
            C_TOKEN.RPAREN,
            C_TOKEN.LBRACKET,
            C_TOKEN.RBRACKET,
            C_TOKEN.ASTERISK,
            C_TOKEN.DOT,
        ]
        self.assertEqual([token.kind for token in self.lex(s)], tokens)

    def test_keywords(self):
        s = """void char short int long signed unsigned _Bool float double
        _Complex const restrict volatile _Atomic struct union enum"""
        tokens = [
            C_TOKEN.VOID,
            C_TOKEN.CHAR,
            C_TOKEN.SHORT,
            C_TOKEN.INT,
            C_TOKEN.LONG,
            C_TOKEN.SIGNED,
            C_TOKEN.UNSIGNED,
            C_TOKEN.BOOL,
            C_TOKEN.FLOAT,
            C_TOKEN.DOUBLE,
            C_TOKEN.COMPLEX,
            C_TOKEN.CONST,
            C_TOKEN.RESTRICT,
            C_TOKEN.VOLATILE,
            C_TOKEN.ATOMIC,
            C_TOKEN.STRUCT,
            C_TOKEN.UNION,
            C_TOKEN.ENUM,
        ]
        self.assertEqual([token.kind for token in self.lex(s)], tokens)

    def test_identifiers(self):
        s = "_ x foo _bar baz1"
        tokens = s.split()
        self.assertEqual(
            [(token.kind, token.value) for token in self.lex(s)],
            [(C_TOKEN.IDENTIFIER, value) for value in tokens],
        )

    def test_number(self):
        s = "0 1234 0xdeadbeef"
        tokens = s.split()
        self.assertEqual(
            [(token.kind, token.value) for token in self.lex(s)],
            [(C_TOKEN.NUMBER, value) for value in tokens],
        )

    def test_invalid_number(self):
        for s in ["0x", "1234y"]:
            self.assertRaisesRegex(SyntaxError, "invalid number", list, self.lex(s))

    def test_invalid_character(self):
        self.assertRaisesRegex(SyntaxError, "invalid character", list, self.lex("@"))


class TestLiteral(MockProgramTestCase):
    def test_int(self):
        self.assertIdentical(
            Object(self.prog, value=1), Object(self.prog, "int", value=1)
        )
        self.assertIdentical(
            Object(self.prog, value=-1), Object(self.prog, "int", value=-1)
        )
        self.assertIdentical(
            Object(self.prog, value=2 ** 31 - 1),
            Object(self.prog, "int", value=2 ** 31 - 1),
        )

        self.assertIdentical(
            Object(self.prog, value=2 ** 31), Object(self.prog, "long", value=2 ** 31)
        )
        # Not int, because this is treated as the negation operator applied to
        # 2**31.
        self.assertIdentical(
            Object(self.prog, value=-(2 ** 31)),
            Object(self.prog, "long", value=-(2 ** 31)),
        )

        self.assertIdentical(
            Object(self.prog, value=2 ** 63),
            Object(self.prog, "unsigned long long", value=2 ** 63),
        )
        self.assertIdentical(
            Object(self.prog, value=2 ** 64 - 1),
            Object(self.prog, "unsigned long long", value=2 ** 64 - 1),
        )
        self.assertIdentical(
            Object(self.prog, value=-(2 ** 64 - 1)),
            Object(self.prog, "unsigned long long", value=1),
        )

    def test_bool(self):
        self.assertIdentical(
            Object(self.prog, value=True), Object(self.prog, "int", value=1)
        )
        self.assertIdentical(
            Object(self.prog, value=False), Object(self.prog, "int", value=0)
        )

    def test_float(self):
        self.assertIdentical(
            Object(self.prog, value=3.14), Object(self.prog, "double", value=3.14)
        )

    def test_invalid(self):
        class Foo:
            pass

        self.assertRaisesRegex(
            TypeError, "cannot create Foo literal", Object, self.prog, value=Foo()
        )


class TestIntegerPromotion(MockProgramTestCase):
    def test_conversion_rank_less_than_int(self):
        self.assertIdentical(+self.bool(False), self.int(0))

        self.assertIdentical(
            +Object(self.prog, "char", value=1), Object(self.prog, "int", value=1)
        )
        self.assertIdentical(
            +Object(self.prog, "signed char", value=2),
            Object(self.prog, "int", value=2),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned char", value=3),
            Object(self.prog, "int", value=3),
        )

        self.assertIdentical(
            +Object(self.prog, "short", value=1), Object(self.prog, "int", value=1)
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned short", value=2),
            Object(self.prog, "int", value=2),
        )

        # If short is the same size as int, then int can't represent all of the
        # values of unsigned short.
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("short", 4, True), value=1),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("unsigned short", 4, False), value=2),
            Object(self.prog, "unsigned int", value=2),
        )

    def test_int(self):
        self.assertIdentical(
            +Object(self.prog, "int", value=-1), Object(self.prog, "int", value=-1)
        )

        self.assertIdentical(
            +Object(self.prog, "unsigned int", value=-1),
            Object(self.prog, "unsigned int", value=-1),
        )

    def test_conversion_rank_greater_than_int(self):
        self.assertIdentical(
            +Object(self.prog, "long", value=-1), Object(self.prog, "long", value=-1)
        )

        self.assertIdentical(
            +Object(self.prog, "unsigned long", value=-1),
            Object(self.prog, "unsigned long", value=-1),
        )

        self.assertIdentical(
            +Object(self.prog, "long long", value=-1),
            Object(self.prog, "long long", value=-1),
        )

        self.assertIdentical(
            +Object(self.prog, "unsigned long long", value=-1),
            Object(self.prog, "unsigned long long", value=-1),
        )

    def test_extended_integer(self):
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("byte", 1, True), value=1),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("ubyte", 1, False), value=-1),
            Object(self.prog, "int", value=0xFF),
        )
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("qword", 8, True), value=1),
            Object(self.prog, self.prog.int_type("qword", 8, True), value=1),
        )
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("qword", 8, False), value=1),
            Object(self.prog, self.prog.int_type("qword", 8, False), value=1),
        )

    def test_bit_field(self):
        # Bit fields which can be represented by int or unsigned int should be
        # promoted.
        self.assertIdentical(
            +Object(self.prog, "int", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "long", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "int", value=1, bit_field_size=32),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "long", value=1, bit_field_size=32),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned int", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned int", value=1, bit_field_size=32),
            Object(self.prog, "unsigned int", value=1),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=32),
            Object(self.prog, "unsigned int", value=1),
        )

        # Bit fields which cannot be represented by int or unsigned int should
        # be preserved.
        self.assertIdentical(
            +Object(self.prog, "long", value=1, bit_field_size=40),
            Object(self.prog, "long", value=1, bit_field_size=40),
        )
        self.assertIdentical(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=40),
            Object(self.prog, "unsigned long", value=1, bit_field_size=40),
        )

    def test_enum(self):
        # Enums should be converted to their compatible type and then promoted.
        self.assertIdentical(
            +Object(self.prog, self.color_type, value=1),
            Object(self.prog, "unsigned int", value=1),
        )

        type_ = self.prog.enum_type(
            "color",
            self.prog.type("unsigned long long"),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertIdentical(
            +Object(self.prog, type_, value=1),
            Object(self.prog, "unsigned long long", value=1),
        )

        type_ = self.prog.enum_type(
            "color",
            self.prog.type("char"),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertIdentical(
            +Object(self.prog, type_, value=1), Object(self.prog, "int", value=1)
        )

    def test_typedef(self):
        type_ = self.prog.typedef_type("SHORT", self.prog.type("short"))
        self.assertIdentical(
            +Object(self.prog, type_, value=5), Object(self.prog, "int", value=5)
        )

        # Typedef should be preserved if the type wasn't promoted.
        type_ = self.prog.typedef_type("CINT", self.prog.type("int"))
        self.assertIdentical(
            +Object(self.prog, type_, value=5), Object(self.prog, type_, value=5)
        )

    def test_non_integer(self):
        # Non-integer types should not be affected.
        self.assertIdentical(
            +Object(self.prog, "double", value=3.14),
            Object(self.prog, "double", value=3.14),
        )

    def test_byte_order(self):
        # Types in the opposite byte order should converted to the program's
        # byte order.
        self.assertIdentical(
            +Object(self.prog, self.prog.int_type("int", 4, True, "big"), value=5),
            Object(self.prog, self.prog.int_type("int", 4, True, "little"), value=5),
        )

    def test_byte_order_typedef(self):
        self.assertIdentical(
            +Object(
                self.prog,
                self.prog.typedef_type(
                    "CINT", self.prog.int_type("int", 4, True, "big")
                ),
                value=5,
            ),
            Object(
                self.prog,
                self.prog.typedef_type(
                    "CINT", self.prog.int_type("int", 4, True, "little")
                ),
                value=5,
            ),
        )

    def test_byte_order_enum(self):
        self.assertIdentical(
            +Object(
                self.prog,
                self.prog.enum_type(
                    "ENUM", self.prog.int_type("int", 4, True, "big"), ()
                ),
                value=5,
            ),
            Object(self.prog, self.prog.int_type("int", 4, True, "little"), value=5),
        )


class TestCommonRealType(MockProgramTestCase):
    def assertCommonRealType(self, lhs, rhs, expected, commutative=True):
        if isinstance(lhs, (str, Type)):
            obj1 = Object(self.prog, lhs, value=1)
        else:
            obj1 = Object(self.prog, lhs[0], value=1, bit_field_size=lhs[1])
        if isinstance(rhs, (str, Type)):
            obj2 = Object(self.prog, rhs, value=1)
        else:
            obj2 = Object(self.prog, rhs[0], value=1, bit_field_size=rhs[1])
        if isinstance(expected, (str, Type)):
            expected_obj = Object(self.prog, expected, value=1)
        else:
            expected_obj = Object(
                self.prog, expected[0], value=1, bit_field_size=expected[1]
            )
        self.assertIdentical(obj1 * obj2, expected_obj)
        if commutative:
            self.assertIdentical(obj2 * obj1, expected_obj)

    def test_float(self):
        self.assertCommonRealType("float", "long long", "float")
        self.assertCommonRealType("float", "float", "float")

        self.assertCommonRealType("double", "long long", "double")
        self.assertCommonRealType("double", "float", "double")
        self.assertCommonRealType("double", "double", "double")

        # Floating type not in the standard.
        float64 = self.prog.float_type("float64", 8)
        self.assertCommonRealType(float64, "long long", float64)
        self.assertCommonRealType(float64, "float", float64)
        self.assertCommonRealType(float64, "double", float64)
        self.assertCommonRealType(float64, float64, float64)

    def test_bit_field(self):
        # Same width and sign.
        self.assertCommonRealType(
            ("long long", 33), ("long long", 33), ("long long", 33)
        )
        self.assertCommonRealType(
            ("long long", 33), ("long", 33), ("long", 33), commutative=False
        )
        self.assertCommonRealType(
            ("long", 33), ("long long", 33), ("long long", 33), commutative=False
        )

        # Same width, different sign.
        self.assertCommonRealType(
            ("long long", 33), ("unsigned long long", 33), ("unsigned long long", 33)
        )

        # Different width, same sign.
        self.assertCommonRealType(
            ("long long", 34), ("long long", 33), ("long long", 34)
        )

        # Different width, different sign.
        self.assertCommonRealType(
            ("long long", 34), ("unsigned long long", 33), ("long long", 34)
        )

    def test_same(self):
        self.assertCommonRealType("_Bool", "_Bool", "int")
        self.assertCommonRealType("int", "int", "int")
        self.assertCommonRealType("long", "long", "long")

    def test_same_sign(self):
        self.assertCommonRealType("long", "int", "long")
        self.assertCommonRealType("long long", "int", "long long")
        self.assertCommonRealType("long long", "long", "long long")

        self.assertCommonRealType("unsigned long", "unsigned int", "unsigned long")
        self.assertCommonRealType(
            "unsigned long long", "unsigned int", "unsigned long long"
        )
        self.assertCommonRealType(
            "unsigned long long", "unsigned long", "unsigned long long"
        )

        int64 = self.prog.int_type("int64", 8, True)
        qword = self.prog.int_type("qword", 8, True)
        self.assertCommonRealType("long", int64, "long")
        self.assertCommonRealType(int64, qword, qword, commutative=False)
        self.assertCommonRealType(qword, int64, int64, commutative=False)
        self.assertCommonRealType("int", int64, int64)

    def test_unsigned_greater_rank(self):
        self.assertCommonRealType("unsigned long", "int", "unsigned long")
        self.assertCommonRealType("unsigned long long", "long", "unsigned long long")
        self.assertCommonRealType("unsigned long long", "int", "unsigned long long")

        int64 = self.prog.int_type("int64", 8, True)
        uint64 = self.prog.int_type("uint64", 8, False)
        self.assertCommonRealType(uint64, "int", uint64)
        self.assertCommonRealType("unsigned long", int64, "unsigned long")

    def test_signed_can_represent_unsigned(self):
        self.assertCommonRealType("long", "unsigned int", "long")
        self.assertCommonRealType("long long", "unsigned int", "long long")

        int64 = self.prog.int_type("int64", 8, True)
        weirduint = self.prog.int_type("weirduint", 6, False)
        self.assertCommonRealType(int64, "unsigned int", int64)
        self.assertCommonRealType("long", weirduint, "long")

    def test_corresponding_unsigned(self):
        self.assertCommonRealType("long", "unsigned long", "unsigned long")
        self.assertCommonRealType("long long", "unsigned long", "unsigned long long")

    def test_enum(self):
        self.assertCommonRealType(self.color_type, self.color_type, "unsigned int")

    def test_typedef(self):
        type_ = self.prog.typedef_type("INT", self.prog.type("int"))
        self.assertCommonRealType(type_, type_, type_)
        self.assertCommonRealType("int", type_, type_, commutative=False)
        self.assertCommonRealType(type_, "int", "int", commutative=False)

        type_ = self.prog.typedef_type("LONG", self.prog.type("long"))
        self.assertCommonRealType(type_, "int", type_)


class TestOperators(MockProgramTestCase):
    def test_cast_array(self):
        obj = Object(self.prog, "int []", address=0xFFFF0000)
        self.assertIdentical(
            cast("int *", obj), Object(self.prog, "int *", value=0xFFFF0000)
        )
        self.assertIdentical(
            cast("void *", obj), Object(self.prog, "void *", value=0xFFFF0000)
        )
        self.assertIdentical(
            cast("unsigned long", obj),
            Object(self.prog, "unsigned long", value=0xFFFF0000),
        )
        self.assertRaisesRegex(
            TypeError, r"cannot cast to 'int \[2]'", cast, "int [2]", obj
        )

    def test_cast_function(self):
        func = Object(
            self.prog,
            self.prog.function_type(self.prog.void_type(), (), False),
            address=0xFFFF0000,
        )
        self.assertIdentical(
            cast("void *", func), Object(self.prog, "void *", value=0xFFFF0000)
        )

    def _test_arithmetic(
        self, op, lhs, rhs, result, integral=True, floating_point=False
    ):
        if integral:
            self.assertIdentical(op(self.int(lhs), self.int(rhs)), self.int(result))
            self.assertIdentical(op(self.int(lhs), self.long(rhs)), self.long(result))
            self.assertIdentical(op(self.long(lhs), self.int(rhs)), self.long(result))
            self.assertIdentical(op(self.long(lhs), self.long(rhs)), self.long(result))
            self.assertIdentical(op(self.int(lhs), rhs), self.int(result))
            self.assertIdentical(op(self.long(lhs), rhs), self.long(result))
            self.assertIdentical(op(lhs, self.int(rhs)), self.int(result))
            self.assertIdentical(op(lhs, self.long(rhs)), self.long(result))

        if floating_point:
            self.assertIdentical(
                op(self.double(lhs), self.double(rhs)), self.double(result)
            )
            self.assertIdentical(
                op(self.double(lhs), self.int(rhs)), self.double(result)
            )
            self.assertIdentical(
                op(self.int(lhs), self.double(rhs)), self.double(result)
            )
            self.assertIdentical(op(self.double(lhs), float(rhs)), self.double(result))
            self.assertIdentical(op(float(lhs), self.double(rhs)), self.double(result))
            self.assertIdentical(op(float(lhs), self.int(rhs)), self.double(result))
            self.assertIdentical(op(self.int(lhs), float(rhs)), self.double(result))

    def _test_shift(self, op, lhs, rhs, result):
        self.assertIdentical(op(self.int(lhs), self.int(rhs)), self.int(result))
        self.assertIdentical(op(self.int(lhs), self.long(rhs)), self.int(result))
        self.assertIdentical(op(self.long(lhs), self.int(rhs)), self.long(result))
        self.assertIdentical(op(self.long(lhs), self.long(rhs)), self.long(result))
        self.assertIdentical(op(self.int(lhs), rhs), self.int(result))
        self.assertIdentical(op(self.long(lhs), rhs), self.long(result))
        self.assertIdentical(op(lhs, self.int(rhs)), self.int(result))
        self.assertIdentical(op(lhs, self.long(rhs)), self.int(result))

        self._test_pointer_type_errors(op)
        self._test_floating_type_errors(op)

    def _test_pointer_type_errors(self, op):
        def pointer(value):
            return Object(self.prog, "int *", value=value)

        self.assertRaisesRegex(
            TypeError, "invalid operands to binary", op, self.int(1), pointer(1)
        )
        self.assertRaisesRegex(
            TypeError, "invalid operands to binary", op, pointer(1), self.int(1)
        )
        self.assertRaisesRegex(
            TypeError, "invalid operands to binary", op, pointer(1), pointer(1)
        )

    def _test_floating_type_errors(self, op):
        self.assertRaises(TypeError, op, self.int(1), self.double(1))
        self.assertRaises(TypeError, op, self.double(1), self.int(1))
        self.assertRaises(TypeError, op, self.double(1), self.double(1))

    def test_relational(self):
        one = self.int(1)
        two = self.int(2)
        three = self.int(3)

        self.assertTrue(one < two)
        self.assertFalse(two < two)
        self.assertFalse(three < two)

        self.assertTrue(one <= two)
        self.assertTrue(two <= two)
        self.assertFalse(three <= two)

        self.assertTrue(one == one)
        self.assertFalse(one == two)

        self.assertFalse(one != one)
        self.assertTrue(one != two)

        self.assertFalse(one > two)
        self.assertFalse(two > two)
        self.assertTrue(three > two)

        self.assertFalse(one >= two)
        self.assertTrue(two >= two)
        self.assertTrue(three >= two)

        # The usual arithmetic conversions convert -1 to an unsigned int.
        self.assertFalse(self.int(-1) < self.unsigned_int(0))

        self.assertTrue(self.int(1) == self.bool(1))

    def test_ptr_relational(self):
        ptr0 = Object(self.prog, "int *", value=0xFFFF0000)
        ptr1 = Object(self.prog, "int *", value=0xFFFF0004)
        fptr1 = Object(self.prog, "float *", value=0xFFFF0004)

        self.assertTrue(ptr0 < ptr1)
        self.assertTrue(ptr0 < fptr1)
        self.assertFalse(ptr1 < fptr1)

        self.assertTrue(ptr0 <= ptr1)
        self.assertTrue(ptr0 <= fptr1)
        self.assertTrue(ptr1 <= fptr1)

        self.assertFalse(ptr0 == ptr1)
        self.assertFalse(ptr0 == fptr1)
        self.assertTrue(ptr1 == fptr1)

        self.assertTrue(ptr0 != ptr1)
        self.assertTrue(ptr0 != fptr1)
        self.assertFalse(ptr1 != fptr1)

        self.assertFalse(ptr0 > ptr1)
        self.assertFalse(ptr0 > fptr1)
        self.assertFalse(ptr1 > fptr1)

        self.assertFalse(ptr0 >= ptr1)
        self.assertFalse(ptr0 >= fptr1)
        self.assertTrue(ptr1 >= fptr1)

        self.assertRaises(TypeError, operator.lt, ptr0, self.int(1))

        func = Object(
            self.prog,
            self.prog.function_type(self.prog.void_type(), (), False),
            address=0xFFFF0000,
        )
        self.assertTrue(func == func)
        self.assertTrue(func == ptr0)

        array = Object(self.prog, "int [8]", address=0xFFFF0000)
        self.assertTrue(array == array)
        self.assertTrue(array != ptr1)

        incomplete = Object(self.prog, "int []", address=0xFFFF0000)
        self.assertTrue(incomplete == incomplete)
        self.assertTrue(incomplete == ptr0)

        self.assertRaises(
            TypeError,
            operator.eq,
            Object(
                self.prog, self.prog.struct_type("foo", None, None), address=0xFFFF0000
            ),
            ptr0,
        )

    def test_add(self):
        self._test_arithmetic(operator.add, 1, 2, 3, floating_point=True)

        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        arr = Object(self.prog, "int [2]", address=0xFFFF0000)
        ptr1 = Object(self.prog, "int *", value=0xFFFF0004)
        self.assertIdentical(ptr + self.int(1), ptr1)
        self.assertIdentical(self.unsigned_int(1) + ptr, ptr1)
        self.assertIdentical(arr + self.int(1), ptr1)
        self.assertIdentical(ptr1 + self.int(-1), ptr)
        self.assertIdentical(self.int(-1) + ptr1, ptr)

        self.assertIdentical(ptr + 1, ptr1)
        self.assertIdentical(1 + ptr, ptr1)
        self.assertRaises(TypeError, operator.add, ptr, ptr)
        self.assertRaises(TypeError, operator.add, ptr, 2.0)
        self.assertRaises(TypeError, operator.add, 2.0, ptr)

        void_ptr = Object(self.prog, "void *", value=0xFFFF0000)
        void_ptr1 = Object(self.prog, "void *", value=0xFFFF0001)
        self.assertIdentical(void_ptr + self.int(1), void_ptr1)
        self.assertIdentical(self.unsigned_int(1) + void_ptr, void_ptr1)
        self.assertIdentical(void_ptr + 1, void_ptr1)
        self.assertIdentical(1 + void_ptr, void_ptr1)

    def test_sub(self):
        self._test_arithmetic(operator.sub, 4, 2, 2, floating_point=True)

        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        arr = Object(self.prog, "int [2]", address=0xFFFF0004)
        ptr1 = Object(self.prog, "int *", value=0xFFFF0004)
        self.assertIdentical(ptr1 - ptr, Object(self.prog, "ptrdiff_t", value=1))
        self.assertIdentical(ptr - ptr1, Object(self.prog, "ptrdiff_t", value=-1))
        self.assertIdentical(ptr - self.int(0), ptr)
        self.assertIdentical(ptr1 - self.int(1), ptr)
        self.assertIdentical(arr - self.int(1), ptr)
        self.assertRaises(TypeError, operator.sub, self.int(1), ptr)
        self.assertRaises(TypeError, operator.sub, ptr, 1.0)

        void_ptr = Object(self.prog, "void *", value=0xFFFF0000)
        void_ptr1 = Object(self.prog, "void *", value=0xFFFF0001)
        self.assertIdentical(
            void_ptr1 - void_ptr, Object(self.prog, "ptrdiff_t", value=1)
        )
        self.assertIdentical(
            void_ptr - void_ptr1, Object(self.prog, "ptrdiff_t", value=-1)
        )
        self.assertIdentical(void_ptr - self.int(0), void_ptr)
        self.assertIdentical(void_ptr1 - self.int(1), void_ptr)

    def test_mul(self):
        self._test_arithmetic(operator.mul, 2, 3, 6, floating_point=True)
        self._test_pointer_type_errors(operator.mul)

        # Negative numbers.
        self.assertIdentical(self.int(2) * self.int(-3), self.int(-6))
        self.assertIdentical(self.int(-2) * self.int(3), self.int(-6))
        self.assertIdentical(self.int(-2) * self.int(-3), self.int(6))

        # Integer overflow.
        self.assertIdentical(self.int(0x8000) * self.int(0x10000), self.int(-(2 ** 31)))

        self.assertIdentical(
            self.unsigned_int(0x8000) * self.int(0x10000), self.unsigned_int(2 ** 31)
        )

        self.assertIdentical(
            self.unsigned_int(0xFFFFFFFF) * self.unsigned_int(0xFFFFFFFF),
            self.unsigned_int(1),
        )

        self.assertIdentical(
            self.unsigned_int(0xFFFFFFFF) * self.int(-1), self.unsigned_int(1)
        )

    def test_div(self):
        self._test_arithmetic(operator.truediv, 6, 3, 2, floating_point=True)

        # Make sure we do integer division for integer operands.
        self._test_arithmetic(operator.truediv, 3, 2, 1)

        # Make sure we truncate towards zero (Python truncates towards negative
        # infinity).
        self._test_arithmetic(operator.truediv, -1, 2, 0)
        self._test_arithmetic(operator.truediv, 1, -2, 0)

        self.assertRaises(ZeroDivisionError, operator.truediv, self.int(1), self.int(0))
        self.assertRaises(
            ZeroDivisionError,
            operator.truediv,
            self.unsigned_int(1),
            self.unsigned_int(0),
        )
        self.assertRaises(
            ZeroDivisionError, operator.truediv, self.double(1), self.double(0)
        )

        self._test_pointer_type_errors(operator.truediv)

    def test_mod(self):
        self._test_arithmetic(operator.mod, 4, 2, 0)

        # Make sure the modulo result has the sign of the dividend (Python uses
        # the sign of the divisor).
        self._test_arithmetic(operator.mod, 1, 26, 1)
        self._test_arithmetic(operator.mod, 1, -26, 1)
        self._test_arithmetic(operator.mod, -1, 26, -1)
        self._test_arithmetic(operator.mod, -1, -26, -1)

        self.assertRaises(ZeroDivisionError, operator.mod, self.int(1), self.int(0))
        self.assertRaises(
            ZeroDivisionError, operator.mod, self.unsigned_int(1), self.unsigned_int(0)
        )

        self._test_pointer_type_errors(operator.mod)
        self._test_floating_type_errors(operator.mod)

    def test_lshift(self):
        self._test_shift(operator.lshift, 2, 3, 16)
        self.assertIdentical(self.bool(True) << self.bool(True), self.int(2))
        self.assertIdentical(self.int(1) << self.int(32), self.int(0))

    def test_rshift(self):
        self._test_shift(operator.rshift, 16, 3, 2)
        self.assertIdentical(self.int(-2) >> self.int(1), self.int(-1))
        self.assertIdentical(self.int(1) >> self.int(32), self.int(0))
        self.assertIdentical(self.int(-1) >> self.int(32), self.int(-1))

    def test_and(self):
        self._test_arithmetic(operator.and_, 1, 3, 1)
        self.assertIdentical(self.int(-1) & self.int(2 ** 31), self.int(2 ** 31))
        self._test_pointer_type_errors(operator.and_)
        self._test_floating_type_errors(operator.and_)

    def test_xor(self):
        self._test_arithmetic(operator.xor, 1, 3, 2)
        self.assertIdentical(self.int(-1) ^ self.int(-(2 ** 31)), self.int(2 ** 31 - 1))
        self._test_pointer_type_errors(operator.xor)
        self._test_floating_type_errors(operator.xor)

    def test_or(self):
        self._test_arithmetic(operator.or_, 1, 3, 3)
        self.assertIdentical(self.int(-(2 ** 31)) | self.int(2 ** 31 - 1), self.int(-1))
        self._test_pointer_type_errors(operator.or_)
        self._test_floating_type_errors(operator.or_)

    def test_pos(self):
        # TestIntegerPromotion covers the other cases.
        self.assertRaisesRegex(
            TypeError,
            r"invalid operand to unary \+",
            operator.pos,
            Object(self.prog, "int *", value=0),
        )

    def test_neg(self):
        self.assertIdentical(-Object(self.prog, "unsigned char", value=1), self.int(-1))
        self.assertIdentical(-self.int(-1), self.int(1))
        self.assertIdentical(-self.unsigned_int(1), self.unsigned_int(0xFFFFFFFF))
        self.assertIdentical(
            -Object(self.prog, "long", value=-0x8000000000000000),
            Object(self.prog, "long", value=-0x8000000000000000),
        )
        self.assertIdentical(-self.double(2.0), self.double(-2.0))
        self.assertRaisesRegex(
            TypeError,
            "invalid operand to unary -",
            operator.neg,
            Object(self.prog, "int *", value=0),
        )

    def test_not(self):
        self.assertIdentical(~self.int(1), self.int(-2))
        self.assertIdentical(
            ~Object(self.prog, "unsigned long long", value=-1),
            Object(self.prog, "unsigned long long", value=0),
        )
        self.assertIdentical(
            ~Object(self.prog, "unsigned char", value=255), self.int(-256)
        )
        for type_ in ["int *", "double"]:
            self.assertRaisesRegex(
                TypeError,
                "invalid operand to unary ~",
                operator.invert,
                Object(self.prog, type_, value=0),
            )

    def test_container_of(self):
        obj = Object(self.prog, "int *", value=0xFFFF000C)
        container_of(obj, self.point_type, "x")
        self.assertIdentical(
            container_of(obj, self.point_type, "x"),
            Object(
                self.prog, self.prog.pointer_type(self.point_type), value=0xFFFF000C
            ),
        )
        self.assertIdentical(
            container_of(obj, self.point_type, "y"),
            Object(
                self.prog, self.prog.pointer_type(self.point_type), value=0xFFFF0008
            ),
        )

        self.assertIdentical(
            container_of(obj, self.line_segment_type, "a.x"),
            Object(
                self.prog,
                self.prog.pointer_type(self.line_segment_type),
                value=0xFFFF000C,
            ),
        )
        self.assertIdentical(
            container_of(obj, self.line_segment_type, "b.x"),
            Object(
                self.prog,
                self.prog.pointer_type(self.line_segment_type),
                value=0xFFFF0004,
            ),
        )

        self.assertRaisesRegex(
            LookupError,
            "'struct line_segment' has no member 'c'",
            container_of,
            obj,
            self.line_segment_type,
            "c.x",
        )

        polygon_type = self.prog.struct_type(
            "polygon", 0, (TypeMember(self.prog.array_type(self.point_type), "points"),)
        )
        self.assertIdentical(
            container_of(obj, polygon_type, "points[3].x"),
            Object(self.prog, self.prog.pointer_type(polygon_type), value=0xFFFEFFF4),
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
        self.assertRaisesRegex(
            ValueError,
            "member is not byte-aligned",
            container_of,
            obj,
            small_point_type,
            "y",
        )

        self.assertRaisesRegex(
            TypeError,
            r"container_of\(\) argument must be a pointer",
            container_of,
            obj[0],
            self.point_type,
            "x",
        )

        self.assertRaisesRegex(
            TypeError,
            "not a structure, union, or class",
            container_of,
            obj,
            obj.type_,
            "x",
        ),

        type_ = self.prog.struct_type(
            "foo",
            16,
            (
                TypeMember(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 8), "arr"
                ),
                TypeMember(self.point_type, "point", 256),
            ),
        )
        syntax_errors = [
            ("", r"^expected identifier$"),
            ("[1]", r"^expected identifier$"),
            ("point.", r"^expected identifier after '\.'$"),
            ("point(", r"^expected '\.' or '\[' after identifier$"),
            ("arr[1](", r"^expected '\.' or '\[' after ']'$"),
            ("arr[]", r"^expected number after '\['$"),
            ("arr[1)", r"^expected ']' after number$"),
        ]
        for member_designator, error in syntax_errors:
            self.assertRaisesRegex(
                SyntaxError, error, container_of, obj, type_, member_designator
            )


class TestPrettyPrintObject(MockProgramTestCase):
    def test_int(self):
        obj = Object(self.prog, "int", value=99)
        self.assertEqual(str(obj), "(int)99")
        self.assertEqual(obj.format_(type_name=False), "99")
        self.assertEqual(
            str(Object(self.prog, "const int", value=-99)), "(const int)-99"
        )

    def test_char(self):
        obj = Object(self.prog, "char", value=65)
        self.assertEqual(str(obj), "(char)65")
        self.assertEqual(obj.format_(char=True), "(char)'A'")
        self.assertEqual(
            Object(self.prog, "signed char", value=65).format_(char=True),
            "(signed char)'A'",
        )
        self.assertEqual(
            Object(self.prog, "unsigned char", value=65).format_(char=True),
            "(unsigned char)'A'",
        )
        self.assertEqual(
            Object(
                self.prog,
                self.prog.typedef_type("uint8_t", self.prog.type("unsigned char")),
                value=65,
            ).format_(char=True),
            "(uint8_t)65",
        )

    def test_bool(self):
        self.assertEqual(str(Object(self.prog, "_Bool", value=False)), "(_Bool)0")
        self.assertEqual(
            str(Object(self.prog, "const _Bool", value=True)), "(const _Bool)1"
        )

    def test_float(self):
        self.assertEqual(str(Object(self.prog, "double", value=2.0)), "(double)2.0")
        self.assertEqual(str(Object(self.prog, "float", value=0.5)), "(float)0.5")

    def test_typedef(self):
        type_ = self.prog.typedef_type("INT", self.prog.int_type("int", 4, True))
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(INT)99")

        type_ = self.prog.typedef_type(
            "INT", self.prog.int_type("int", 4, True), qualifiers=Qualifiers.CONST
        )
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(const INT)99")

        type_ = self.prog.typedef_type(
            "CINT", self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST)
        )
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(CINT)99")

    def test_struct(self):
        segment = (
            (99).to_bytes(4, "little")
            + (-1).to_bytes(4, "little", signed=True)
            + (12345).to_bytes(4, "little", signed=True)
            + (0).to_bytes(4, "little", signed=True)
        )
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        self.types.append(self.point_type)

        obj = Object(self.prog, "struct point", address=0xFFFF0000)
        self.assertEqual(
            str(obj),
            """\
(struct point){
	.x = (int)99,
	.y = (int)-1,
}""",
        )
        self.assertEqual(
            obj.format_(member_type_names=False),
            """\
(struct point){
	.x = 99,
	.y = -1,
}""",
        )
        self.assertEqual(
            obj.format_(members_same_line=True),
            "(struct point){ .x = (int)99, .y = (int)-1 }",
        )
        self.assertEqual(
            obj.format_(member_names=False),
            """\
(struct point){
	(int)99,
	(int)-1,
}""",
        )
        self.assertEqual(
            obj.format_(members_same_line=True, member_names=False),
            "(struct point){ (int)99, (int)-1 }",
        )

        type_ = self.prog.struct_type(
            "foo",
            16,
            (
                TypeMember(self.point_type, "point"),
                TypeMember(
                    self.prog.struct_type(
                        None,
                        8,
                        (
                            TypeMember(self.prog.int_type("int", 4, True), "bar"),
                            TypeMember(self.prog.int_type("int", 4, True), "baz", 32),
                        ),
                    ),
                    None,
                    64,
                ),
            ),
        )
        obj = Object(self.prog, type_, address=0xFFFF0000)
        expected = """\
(struct foo){
	.point = (struct point){
		.x = (int)99,
		.y = (int)-1,
	},
	.bar = (int)12345,
	.baz = (int)0,
}"""
        self.assertEqual(str(obj), expected)
        self.assertEqual(str(obj.read_()), expected)

        self.add_memory_segment(
            (
                (99).to_bytes(8, "little")
                + (-1).to_bytes(8, "little", signed=True)
                + (12345).to_bytes(8, "little", signed=True)
                + (0).to_bytes(8, "little", signed=True)
            ),
            virt_addr=0xFFFF8000,
        )

        type_ = self.prog.struct_type(
            "foo",
            32,
            (
                TypeMember(
                    self.prog.struct_type(
                        "long_point",
                        16,
                        (
                            TypeMember(self.prog.int_type("long", 8, True), "x"),
                            TypeMember(self.prog.int_type("long", 8, True), "y", 64),
                        ),
                    ),
                    "point",
                ),
                TypeMember(self.prog.int_type("long", 8, True), "bar", 128),
                TypeMember(self.prog.int_type("long", 8, True), "baz", 192),
            ),
        )
        obj = Object(self.prog, type_, address=0xFFFF8000)
        expected = """\
(struct foo){
	.point = (struct long_point){
		.x = (long)99,
		.y = (long)-1,
	},
	.bar = (long)12345,
	.baz = (long)0,
}"""
        self.assertEqual(str(obj), expected)
        self.assertEqual(str(obj.read_()), expected)

        type_ = self.prog.struct_type("foo", 0, ())
        self.assertEqual(str(Object(self.prog, type_, address=0)), "(struct foo){}")

        obj = Object(self.prog, self.point_type, value={"x": 1})
        self.assertEqual(
            obj.format_(implicit_members=False),
            """\
(struct point){
	.x = (int)1,
}""",
        )
        self.assertEqual(
            obj.format_(member_names=False, implicit_members=False),
            """\
(struct point){
	(int)1,
}""",
        )
        obj = Object(self.prog, self.point_type, value={"y": 1})
        self.assertEqual(
            obj.format_(implicit_members=False),
            """\
(struct point){
	.y = (int)1,
}""",
        )
        self.assertEqual(
            obj.format_(member_names=False, implicit_members=False),
            """\
(struct point){
	(int)0,
	(int)1,
}""",
        )

    def test_bit_field(self):
        self.add_memory_segment(b"\x07\x10\x5e\x5f\x1f\0\0\0", virt_addr=0xFFFF0000)
        type_ = self.prog.struct_type(
            "bits",
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
                        self.prog,
                        self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST),
                        bit_field_size=28,
                    ),
                    "y",
                    4,
                ),
                TypeMember(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True), bit_field_size=5
                    ),
                    "z",
                    32,
                ),
            ),
        )

        obj = Object(self.prog, type_, address=0xFFFF0000)
        self.assertEqual(
            str(obj),
            """\
(struct bits){
	.x = (int)7,
	.y = (const int)100000000,
	.z = (int)-1,
}""",
        )

        self.assertEqual(str(obj.x), "(int)7")
        self.assertEqual(str(obj.y), "(const int)100000000")
        self.assertEqual(str(obj.z), "(int)-1")

    def test_union(self):
        self.add_memory_segment(b"\0\0\x80?", virt_addr=0xFFFF0000)
        self.types.append(self.option_type)
        self.assertEqual(
            str(Object(self.prog, "union option", address=0xFFFF0000)),
            """\
(union option){
	.i = (int)1065353216,
	.f = (float)1.0,
}""",
        )

    def test_enum(self):
        self.assertEqual(
            str(Object(self.prog, self.color_type, value=0)), "(enum color)RED"
        )
        self.assertEqual(
            str(Object(self.prog, self.color_type, value=1)), "(enum color)GREEN"
        )
        self.assertEqual(
            str(Object(self.prog, self.color_type, value=4)), "(enum color)4"
        )
        obj = Object(self.prog, self.prog.enum_type("color"), address=0)
        self.assertRaisesRegex(TypeError, "cannot format incomplete enum", str, obj)

    def test_pointer(self):
        self.add_memory_segment((99).to_bytes(4, "little"), virt_addr=0xFFFF0000)
        obj = Object(self.prog, "int *", value=0xFFFF0000)
        self.assertEqual(str(obj), "*(int *)0xffff0000 = 99")
        self.assertEqual(obj.format_(dereference=False), "(int *)0xffff0000")
        self.assertEqual(
            str(Object(self.prog, "int *", value=0x7FFFFFFF)), "(int *)0x7fffffff"
        )

    def test_void_pointer(self):
        self.add_memory_segment((99).to_bytes(4, "little"), virt_addr=0xFFFF0000)
        self.assertEqual(
            str(Object(self.prog, "void *", value=0xFFFF0000)), "(void *)0xffff0000"
        )

    def test_pointer_typedef(self):
        self.add_memory_segment(
            (0xFFFF00F0).to_bytes(8, "little"), virt_addr=0xFFFF0000
        )
        type_ = self.prog.typedef_type(
            "HANDLE",
            self.prog.pointer_type(self.prog.pointer_type(self.prog.void_type())),
        )
        self.assertEqual(
            str(Object(self.prog, type_, value=0xFFFF0000)),
            "*(HANDLE)0xffff0000 = 0xffff00f0",
        )

    # TODO: test symbolize.

    def test_c_string(self):
        self.add_memory_segment(b"hello\0", virt_addr=0xFFFF0000)
        self.add_memory_segment(b"unterminated", virt_addr=0xFFFF0010)
        self.add_memory_segment(b'"escape\tme\\\0', virt_addr=0xFFFF0020)

        obj = Object(self.prog, "char *", value=0xFFFF0000)
        self.assertEqual(str(obj), '(char *)0xffff0000 = "hello"')
        self.assertEqual(obj.format_(string=False), "*(char *)0xffff0000 = 104")
        self.assertEqual(str(Object(self.prog, "char *", value=0x0)), "(char *)0x0")
        self.assertEqual(
            str(Object(self.prog, "char *", value=0xFFFF0010)), "(char *)0xffff0010"
        )
        self.assertEqual(
            str(Object(self.prog, "char *", value=0xFFFF0020)),
            r'(char *)0xffff0020 = "\"escape\tme\\"',
        )

    def test_basic_array(self):
        segment = bytearray()
        for i in range(5):
            segment.extend(i.to_bytes(4, "little"))
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        obj = Object(self.prog, "int [5]", address=0xFFFF0000)

        self.assertEqual(str(obj), "(int [5]){ 0, 1, 2, 3, 4 }")
        self.assertEqual(
            obj.format_(type_name=False, element_type_names=True),
            "{ (int)0, (int)1, (int)2, (int)3, (int)4 }",
        )
        self.assertEqual(
            obj.format_(element_indices=True),
            "(int [5]){ [1] = 1, [2] = 2, [3] = 3, [4] = 4 }",
        )
        self.assertEqual(
            obj.format_(element_indices=True, implicit_elements=True),
            "(int [5]){ [0] = 0, [1] = 1, [2] = 2, [3] = 3, [4] = 4 }",
        )
        self.assertEqual(obj.format_(columns=27), str(obj))

        for columns in range(22, 26):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [5]){
	0, 1, 2, 3, 4,
}""",
            )
        for columns in range(19, 22):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [5]){
	0, 1, 2, 3,
	4,
}""",
            )
        for columns in range(16, 19):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [5]){
	0, 1, 2,
	3, 4,
}""",
            )
        for columns in range(13, 16):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [5]){
	0, 1,
	2, 3,
	4,
}""",
            )
        for columns in range(13):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [5]){
	0,
	1,
	2,
	3,
	4,
}""",
            )
        self.assertEqual(
            obj.format_(elements_same_line=False),
            """\
(int [5]){
	0,
	1,
	2,
	3,
	4,
}""",
        )

    def test_nested_array(self):
        segment = bytearray()
        for i in range(10):
            segment.extend(i.to_bytes(4, "little"))
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        obj = Object(self.prog, "int [2][5]", address=0xFFFF0000)

        self.assertEqual(
            str(obj), "(int [2][5]){ { 0, 1, 2, 3, 4 }, { 5, 6, 7, 8, 9 } }"
        )
        self.assertEqual(obj.format_(columns=52), str(obj))
        for columns in range(45, 52):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [2][5]){
	{ 0, 1, 2, 3, 4 }, { 5, 6, 7, 8, 9 },
}""",
            )
        for columns in range(26, 45):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [2][5]){
	{ 0, 1, 2, 3, 4 },
	{ 5, 6, 7, 8, 9 },
}""",
            )
        for columns in range(24, 26):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [2][5]){
	{
		0, 1, 2,
		3, 4,
	},
	{
		5, 6, 7,
		8, 9,
	},
}""",
            )
        for columns in range(21, 24):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [2][5]){
	{
		0, 1,
		2, 3,
		4,
	},
	{
		5, 6,
		7, 8,
		9,
	},
}""",
            )
        for columns in range(21):
            self.assertEqual(
                obj.format_(columns=columns),
                """\
(int [2][5]){
	{
		0,
		1,
		2,
		3,
		4,
	},
	{
		5,
		6,
		7,
		8,
		9,
	},
}""",
            )

    def test_array_member(self):
        segment = bytearray()
        for i in range(5):
            segment.extend(i.to_bytes(4, "little"))
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)

        type_ = self.prog.struct_type(
            None,
            20,
            (
                TypeMember(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 5), "arr"
                ),
            ),
        )
        obj = Object(self.prog, type_, address=0xFFFF0000)

        self.assertEqual(
            str(obj),
            """\
(struct <anonymous>){
	.arr = (int [5]){ 0, 1, 2, 3, 4 },
}""",
        )
        self.assertEqual(obj.format_(columns=42), str(obj))

        self.assertEqual(
            obj.format_(columns=41),
            """\
(struct <anonymous>){
	.arr = (int [5]){
		0, 1, 2, 3, 4,
	},
}""",
        )

        self.assertEqual(
            obj.format_(columns=18),
            """\
(struct <anonymous>){
	.arr = (int [5]){
		0,
		1,
		2,
		3,
		4,
	},
}""",
        )

    def test_array_of_struct(self):
        segment = bytearray()
        for i in range(1, 5):
            segment.extend(i.to_bytes(4, "little"))
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        self.types.append(self.point_type)

        obj = Object(self.prog, "struct point [2]", address=0xFFFF0000)
        self.assertEqual(
            str(obj),
            """\
(struct point [2]){
	{
		.x = (int)1,
		.y = (int)2,
	},
	{
		.x = (int)3,
		.y = (int)4,
	},
}""",
        )

    def test_zero_length_array(self):
        self.assertEqual(str(Object(self.prog, "int []", address=0)), "(int []){}")
        self.assertEqual(str(Object(self.prog, "int [0]", address=0)), "(int [0]){}")

    def test_array_zeroes(self):
        segment = bytearray(16)
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        self.types.append(self.point_type)
        self.types.append(self.prog.struct_type("empty", 0, ()))

        obj = Object(self.prog, "int [2]", address=0xFFFF0000)
        self.assertEqual(str(obj), "(int [2]){}")
        self.assertEqual(obj.format_(implicit_elements=True), "(int [2]){ 0, 0 }")
        segment[:4] = (99).to_bytes(4, "little")
        self.assertEqual(str(obj), "(int [2]){ 99 }")
        segment[:4] = (0).to_bytes(4, "little")
        segment[4:8] = (99).to_bytes(4, "little")
        self.assertEqual(str(obj), "(int [2]){ 0, 99 }")

        obj = Object(self.prog, "struct point [2]", address=0xFFFF0000)
        self.assertEqual(
            str(obj),
            """\
(struct point [2]){
	{
		.x = (int)0,
		.y = (int)99,
	},
}""",
        )

        obj = Object(self.prog, "struct empty [2]", address=0)
        self.assertEqual(str(obj), "(struct empty [2]){}")

    def test_char_array(self):
        segment = bytearray(16)
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)

        obj = Object(self.prog, "char [4]", address=0xFFFF0000)
        segment[:16] = b"hello, world\0\0\0\0"
        self.assertEqual(str(obj), '(char [4])"hell"')
        self.assertEqual(obj.format_(string=False), "(char [4]){ 104, 101, 108, 108 }")
        self.assertEqual(str(obj.read_()), str(obj))
        segment[2] = 0
        self.assertEqual(str(obj), '(char [4])"he"')
        self.assertEqual(str(obj.read_()), str(obj))

        self.assertEqual(
            str(Object(self.prog, "char [0]", address=0xFFFF0000)), "(char [0]){}"
        )
        self.assertEqual(
            str(Object(self.prog, "char []", address=0xFFFF0000)), "(char []){}"
        )

    def test_function(self):
        obj = Object(
            self.prog,
            self.prog.function_type(self.prog.void_type(), (), False),
            address=0xFFFF0000,
        )
        self.assertEqual(str(obj), "(void (void))0xffff0000")

    def test_absent(self):
        self.assertRaises(TypeError, str, Object(self.prog, "void"))

        for type_ in [
            "int",
            "char",
            "_Bool",
            "double",
            self.point_type,
            self.option_type,
            self.coord_type,
            self.color_type,
            "size_t",
            "void *",
            "int [2]",
            self.prog.function_type(self.prog.void_type(), ()),
        ]:
            if isinstance(type_, Type):
                type_name = type_.type_name()
            else:
                type_name = type_
            self.assertEqual(str(Object(self.prog, type_)), f"({type_name})<absent>")
