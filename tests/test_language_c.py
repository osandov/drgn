# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

from functools import reduce
import operator
import unittest

from drgn import Qualifiers, TypeEnumerator, TypeMember, TypeParameter
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
            qualifiers=reduce(operator.or_, (qualifier[0] for qualifier in qualifiers))
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

    def test_complex(self):
        self.assertQualifiedTypeName(
            "double _Complex",
            True,
            self.prog.complex_type,
            "double _Complex",
            16,
            self.prog.float_type("double", 8),
        )

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
                    TypeMember(self.prog.int_type("int", 4, True), "x", 0, 4),
                    TypeMember(self.prog.int_type("int", 4, True), "y", 4, 8),
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
