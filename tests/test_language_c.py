# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

from functools import reduce
import operator
import unittest

from drgn import (
    Qualifiers,
    TypeEnumerator,
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
    struct_type,
    typedef_type,
    union_type,
    void_type,
)
from tests import coord_type, point_type
from tests.libdrgn import C_TOKEN, drgn_lexer_c, Lexer


class TestPrettyPrintTypeName(unittest.TestCase):
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
        self.assertQualifiedTypeName("void", True, void_type)

    def test_int(self):
        self.assertQualifiedTypeName("int", True, int_type, "int", 4, True)

    def test_bool(self):
        self.assertQualifiedTypeName("_Bool", True, bool_type, "_Bool", 1)

    def test_float(self):
        self.assertQualifiedTypeName("float", True, float_type, "float", 4)

    def test_complex(self):
        self.assertQualifiedTypeName(
            "double _Complex",
            True,
            complex_type,
            "double _Complex",
            16,
            float_type("double", 8),
        )

    def test_struct(self):
        self.assertQualifiedTypeName("struct point", True, struct_type, "point")
        self.assertQualifiedTypeName("struct <anonymous>", False, struct_type, None)

    def test_union(self):
        self.assertQualifiedTypeName("union option", True, union_type, "option"),
        self.assertQualifiedTypeName("union <anonymous>", False, union_type, None)

    def test_class(self):
        self.assertQualifiedTypeName("class coord", True, class_type, "coord")
        self.assertQualifiedTypeName("class <anonymous>", False, class_type, None)

    def test_enum(self):
        self.assertQualifiedTypeName(
            "enum color", True, enum_type, "color", None, None
        ),
        self.assertQualifiedTypeName(
            "enum <anonymous>", False, enum_type, None, None, None
        )

    def test_typedef(self):
        self.assertQualifiedTypeName(
            "bool", False, typedef_type, "bool", bool_type("_Bool", 1)
        )

    def test_pointer(self):
        self.assertTypeName(pointer_type(8, void_type()), "void *", True)
        t = pointer_type(8, void_type(Qualifiers.VOLATILE))
        self.assertTypeName(t, "volatile void *", True)
        t = pointer_type(8, void_type(Qualifiers.VOLATILE), Qualifiers.CONST)
        self.assertTypeName(t, "volatile void * const", True)
        t = pointer_type(8, t)
        self.assertTypeName(t, "volatile void * const *", True)

    def test_array(self):
        i = int_type("int", 4, True)
        self.assertTypeName(array_type(None, i), "int []", True)
        self.assertTypeName(array_type(2, i), "int [2]", True)
        self.assertTypeName(array_type(2, array_type(3, i)), "int [2][3]", True)
        self.assertTypeName(
            array_type(2, array_type(3, array_type(4, i))), "int [2][3][4]", True
        )

    def test_array_of_pointers(self):
        self.assertTypeName(
            array_type(2, array_type(3, pointer_type(8, int_type("int", 4, True)))),
            "int *[2][3]",
            True,
        )

    def test_pointer_to_array(self):
        self.assertTypeName(
            pointer_type(8, array_type(2, int_type("int", 4, True))), "int (*)[2]", True
        )

    def test_pointer_to_pointer_to_array(self):
        self.assertTypeName(
            pointer_type(8, pointer_type(8, array_type(2, int_type("int", 4, True)))),
            "int (**)[2]",
            True,
        )

    def test_pointer_to_array_of_pointers(self):
        self.assertTypeName(
            pointer_type(8, array_type(2, pointer_type(8, int_type("int", 4, True)))),
            "int *(*)[2]",
            True,
        )

    def test_array_of_pointers_to_array(self):
        self.assertTypeName(
            array_type(2, pointer_type(8, array_type(3, int_type("int", 4, True)))),
            "int (*[2])[3]",
            True,
        )

    def test_pointer_to_function(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(8, function_type(i, (TypeParameter(i),), False)),
            "int (*)(int)",
            True,
        )
        self.assertTypeName(
            pointer_type(8, function_type(i, (TypeParameter(i, "x"),), False)),
            "int (*)(int x)",
            True,
        )
        self.assertTypeName(
            pointer_type(
                8,
                function_type(
                    i, (TypeParameter(i), TypeParameter(float_type("float", 4),)), False
                ),
            ),
            "int (*)(int, float)",
            True,
        )

    def test_pointer_to_function_returning_pointer(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(
                8, function_type(pointer_type(8, i), (TypeParameter(i),), False)
            ),
            "int *(*)(int)",
            True,
        )
        self.assertTypeName(
            pointer_type(
                8,
                function_type(
                    pointer_type(8, i), (TypeParameter(pointer_type(8, i)),), False
                ),
            ),
            "int *(*)(int *)",
            True,
        )

    def test_pointer_to_function_returning_pointer_to_const(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(
                8,
                function_type(
                    pointer_type(8, int_type("int", 4, True, Qualifiers.CONST)),
                    (TypeParameter(i),),
                    False,
                ),
            ),
            "const int *(*)(int)",
            True,
        )

    def test_pointer_to_function_returning_const_pointer(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(
                8,
                function_type(
                    pointer_type(8, i, Qualifiers.CONST), (TypeParameter(i),), False
                ),
            ),
            "int * const (*)(int)",
            True,
        )

    def test_const_pointer_to_function_returning_pointer(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(
                8,
                function_type(pointer_type(8, i), (TypeParameter(i),), False),
                Qualifiers.CONST,
            ),
            "int *(* const)(int)",
            True,
        )

    def test_array_of_pointers_to_functions(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            array_type(
                4, pointer_type(8, function_type(i, (TypeParameter(i),), False))
            ),
            "int (*[4])(int)",
            True,
        )

    def test_array_of_const_pointers_to_functions(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            array_type(
                None,
                pointer_type(
                    8, function_type(i, (TypeParameter(i),), False), Qualifiers.CONST
                ),
            ),
            "int (* const [])(int)",
            True,
        )

    def test_pointer_to_variadic_function(self):
        i = int_type("int", 4, True)
        self.assertTypeName(
            pointer_type(8, function_type(i, (TypeParameter(i),), True)),
            "int (*)(int, ...)",
            True,
        )

    def test_pointer_to_function_with_no_parameters(self):
        self.assertTypeName(
            pointer_type(8, function_type(int_type("int", 4, True), (), False)),
            "int (*)(void)",
            True,
        )

    def test_pointer_to_function_with_no_parameter_specification(self):
        self.assertTypeName(
            pointer_type(8, function_type(int_type("int", 4, True), (), True)),
            "int (*)()",
            True,
        )

    def test_function(self):
        self.assertTypeName(
            function_type(int_type("int", 4, True), (), False), "int (void)"
        )


class TestPrettyPrintType(unittest.TestCase):
    def assertPrettyPrint(self, type, expected):
        self.assertEqual(str(type), expected)

    def test_struct(self):
        self.assertPrettyPrint(
            point_type,
            """\
struct point {
	int x;
	int y;
}""",
        )

        line_segment = struct_type(
            "line_segment",
            16,
            (TypeMember(point_type, "a", 0), TypeMember(point_type, "b", 8)),
        )
        self.assertPrettyPrint(
            line_segment,
            """\
struct line_segment {
	struct point a;
	struct point b;
}""",
        )

        anonymous_point = struct_type(
            None,
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0),
                TypeMember(int_type("int", 4, True), "y", 4),
            ),
        )
        self.assertPrettyPrint(
            anonymous_point,
            """\
struct {
	int x;
	int y;
}""",
        )

        # Member with anonymous struct type.
        line_segment = struct_type(
            "line_segment",
            16,
            (TypeMember(anonymous_point, "a", 0), TypeMember(anonymous_point, "b", 8),),
        )

        self.assertPrettyPrint(
            line_segment,
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

        # Unnamed member.
        point3 = struct_type(
            "point3",
            0,
            (
                TypeMember(anonymous_point, None, 0),
                TypeMember(int_type("int", 4, True), "z", 8),
            ),
        )
        self.assertPrettyPrint(
            point3,
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
        point = struct_type(
            "point",
            4,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 4, 8),
            ),
        )
        self.assertPrettyPrint(
            point,
            """\
struct point {
	int x : 4;
	int y : 8;
}""",
        )

    def test_union(self):
        t = union_type(
            "foo",
            4,
            (
                TypeMember(int_type("int", 4, True), "i"),
                TypeMember(array_type(4, int_type("unsigned char", 1, False)), "a"),
            ),
        )
        self.assertPrettyPrint(
            t,
            """\
union foo {
	int i;
	unsigned char a[4];
}""",
        )

        t = union_type(
            "foo",
            4,
            (
                TypeMember(int_type("int", 4, True), "i"),
                TypeMember(array_type(4, int_type("unsigned char", 1, False)), "a"),
            ),
            Qualifiers.CONST,
        )
        self.assertPrettyPrint(
            t,
            """\
const union foo {
	int i;
	unsigned char a[4];
}""",
        )

    def test_class(self):
        self.assertPrettyPrint(
            coord_type,
            """\
class coord {
	int x;
	int y;
	int z;
}""",
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
        self.assertPrettyPrint(
            t,
            """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""",
        )

        t = enum_type(
            "color",
            int_type("unsigned int", 4, False),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
            Qualifiers.CONST,
        )
        self.assertPrettyPrint(
            t,
            """\
const enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""",
        )

        t = enum_type(
            None,
            int_type("int", 4, True),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", -1),
                TypeEnumerator("BLUE", -2),
            ),
        )
        self.assertPrettyPrint(
            t,
            """\
enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
}""",
        )

    def test_typedef(self):
        self.assertPrettyPrint(
            typedef_type("INT", int_type("int", 4, True)), "typedef int INT"
        )
        self.assertPrettyPrint(
            typedef_type("CINT", int_type("int", 4, True, Qualifiers.CONST)),
            "typedef const int CINT",
        )
        self.assertPrettyPrint(
            typedef_type("INT", int_type("int", 4, True), Qualifiers.CONST),
            "const typedef int INT",
        )
        self.assertPrettyPrint(
            typedef_type("string", pointer_type(8, int_type("char", 1, True))),
            "typedef char *string",
        )

        t = typedef_type(
            "Point",
            struct_type(
                None,
                8,
                (
                    TypeMember(int_type("int", 4, True), "x", 0),
                    TypeMember(int_type("int", 4, True), "y", 4),
                ),
            ),
        )
        self.assertPrettyPrint(
            t,
            """\
typedef struct {
	int x;
	int y;
} Point""",
        )

    def test_function_typedef(self):
        self.assertPrettyPrint(
            typedef_type("fn", function_type(int_type("int", 4, True), (), False)),
            "typedef int fn(void)",
        )

    def test_function_no_name(self):
        self.assertRaisesRegex(
            ValueError,
            "function must have name",
            str,
            struct_type(
                "foo",
                8,
                (TypeMember(function_type(int_type("int", 4, True), (), False), None),),
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
