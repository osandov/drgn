# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from drgn import TypeMember
from drgn.helpers.common.type import member_at_offset
from tests import TestCase, mock_program


class TestMemberAtOffset(TestCase):
    def test_simple(self):
        prog = mock_program()
        point_type = prog.struct_type(
            "point",
            8,
            (
                TypeMember(prog.int_type("int", 4, True), "x", 0),
                TypeMember(prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(member_at_offset(point_type, 0), "x")
        self.assertEqual(member_at_offset(point_type, 4), "y")

    def test_unnamed_member(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            8,
            (
                TypeMember(
                    prog.struct_type(
                        None,
                        8,
                        (
                            TypeMember(prog.int_type("int", 4, True), "x", 0),
                            TypeMember(prog.int_type("int", 4, True), "y", 32),
                        ),
                    ),
                    None,
                ),
            ),
        )
        self.assertEqual(member_at_offset(type, 0), "x")
        self.assertEqual(member_at_offset(type, 4), "y")

    def test_end(self):
        prog = mock_program()
        point_type = prog.struct_type(
            "point",
            8,
            (
                TypeMember(prog.int_type("int", 4, True), "x", 0),
                TypeMember(prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(member_at_offset(point_type, 8), "<end>")
        self.assertEqual(member_at_offset(point_type, 9), "<past end>")

    def test_padding_between_members(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.int_type("int", 4, True), "i", 0),
                TypeMember(prog.int_type("long", 8, True), "l", 64),
            ),
        )
        self.assertEqual(member_at_offset(type, 4), "<padding between i and l>")

    def test_padding_between_unnamed_members(self):
        prog = mock_program()

        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.int_type("int", 4, True), "i"),
                TypeMember(
                    prog.struct_type(
                        None, 8, (TypeMember(prog.int_type("long", 8, True), "l"),)
                    ),
                    None,
                    64,
                ),
            ),
        )
        self.assertEqual(member_at_offset(type, 4), "<padding between i and <unnamed>>")

        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(
                    prog.struct_type(
                        None, 4, (TypeMember(prog.int_type("int", 4, True), "i"),)
                    ),
                    None,
                ),
                TypeMember(prog.int_type("long", 8, True), "l", 64),
            ),
        )
        self.assertEqual(member_at_offset(type, 4), "<padding between <unnamed> and l>")

        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(
                    prog.struct_type(
                        None, 4, (TypeMember(prog.int_type("int", 4, True), "i"),)
                    ),
                    None,
                ),
                TypeMember(
                    prog.struct_type(
                        None, 8, (TypeMember(prog.int_type("long", 8, True), "l"),)
                    ),
                    None,
                    64,
                ),
            ),
        )
        self.assertEqual(
            member_at_offset(type, 4), "<padding between <unnamed> and <unnamed>>"
        )

    def test_padding_at_end(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.int_type("long", 8, True), "l", 0),
                TypeMember(prog.int_type("int", 4, True), "i", 64),
            ),
        )
        self.assertEqual(member_at_offset(type, 12), "<padding at end>")

    def test_padding_at_beginning(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (TypeMember(prog.int_type("int", 4, True), "i", 32),),
        )
        self.assertEqual(member_at_offset(type, 0), "<padding at beginning>")

    def test_offset(self):
        prog = mock_program()
        point_type = prog.struct_type(
            "point",
            8,
            (
                TypeMember(prog.int_type("int", 4, True), "x", 0),
                TypeMember(prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.assertEqual(member_at_offset(point_type, 2), "x+0x2")
        self.assertEqual(member_at_offset(point_type, 6), "y+0x2")

    def test_nested(self):
        prog = mock_program()
        point_type = prog.struct_type(
            "point",
            8,
            (
                TypeMember(prog.int_type("int", 4, True), "x", 0),
                TypeMember(prog.int_type("int", 4, True), "y", 32),
            ),
        )
        line_segment_type = prog.struct_type(
            "line_segment",
            16,
            (TypeMember(point_type, "a"), TypeMember(point_type, "b", 64)),
        )
        self.assertEqual(member_at_offset(line_segment_type, 0), "a.x")
        self.assertEqual(member_at_offset(line_segment_type, 4), "a.y")
        self.assertEqual(member_at_offset(line_segment_type, 8), "b.x")
        self.assertEqual(member_at_offset(line_segment_type, 12), "b.y")

    def test_padding_in_nested(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(
                    prog.struct_type(
                        None,
                        16,
                        (
                            TypeMember(prog.int_type("int", 4, True), "i", 0),
                            TypeMember(prog.int_type("long", 8, True), "l", 64),
                        ),
                    ),
                    "x",
                ),
            ),
        )
        self.assertEqual(member_at_offset(type, 4), "x.<padding between i and l>")

    def test_array(self):
        prog = mock_program()
        type = prog.array_type(prog.int_type("int", 4, True), 2)
        self.assertEqual(member_at_offset(type, 0), "[0]")
        self.assertEqual(member_at_offset(type, 4), "[1]")

    def test_array_end(self):
        prog = mock_program()
        type = prog.array_type(prog.int_type("int", 4, True), 2)
        self.assertEqual(member_at_offset(type, 8), "<end>")
        self.assertEqual(member_at_offset(type, 9), "<past end>")

    def test_array_padding_at_end_of_element(self):
        prog = mock_program()
        type = prog.array_type(
            prog.struct_type(
                None,
                16,
                (
                    TypeMember(prog.int_type("long", 8, True), "l", 0),
                    TypeMember(prog.int_type("int", 4, True), "i", 64),
                ),
            ),
            2,
        )
        self.assertEqual(member_at_offset(type, 12), "[0].<padding at end>")

    def test_array_offset(self):
        prog = mock_program()
        type = prog.array_type(prog.int_type("int", 4, True), 2)
        self.assertEqual(member_at_offset(type, 1), "[0]+0x1")
        self.assertEqual(member_at_offset(type, 7), "[1]+0x3")

    def test_array_of_structs(self):
        prog = mock_program()
        type = prog.array_type(
            prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
            2,
        )
        self.assertEqual(member_at_offset(type, 0), "[0].x")
        self.assertEqual(member_at_offset(type, 4), "[0].y")
        self.assertEqual(member_at_offset(type, 8), "[1].x")
        self.assertEqual(member_at_offset(type, 12), "[1].y")

    def test_array_of_structs_end(self):
        prog = mock_program()
        type = prog.array_type(
            prog.struct_type(
                "point",
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
            2,
        )
        self.assertEqual(member_at_offset(type, 16), "<end>")
        self.assertEqual(member_at_offset(type, 17), "<past end>")

    def test_array_of_structs_padding(self):
        prog = mock_program()
        type = prog.array_type(
            prog.struct_type(
                None,
                16,
                (
                    TypeMember(prog.int_type("int", 4, True), "i", 0),
                    TypeMember(prog.int_type("long", 8, True), "l", 64),
                ),
            ),
            2,
        )
        self.assertEqual(member_at_offset(type, 4), "[0].<padding between i and l>")
        self.assertEqual(member_at_offset(type, 20), "[1].<padding between i and l>")

    def test_array_member(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.array_type(prog.int_type("int", 4, True), 3), "a", 0),
                TypeMember(prog.array_type(prog.int_type("int", 4, True), 1), "b", 96),
            ),
        )
        self.assertEqual(member_at_offset(type, 0), "a[0]")
        self.assertEqual(member_at_offset(type, 4), "a[1]")
        self.assertEqual(member_at_offset(type, 8), "a[2]")
        self.assertEqual(member_at_offset(type, 12), "b[0]")

    def test_array_member_end(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.array_type(prog.int_type("int", 4, True), 3), "a", 0),
                TypeMember(prog.array_type(prog.int_type("int", 4, True), 1), "b", 96),
            ),
        )
        self.assertEqual(member_at_offset(type, 16), "<end>")
        self.assertEqual(member_at_offset(type, 17), "<past end>")

    def test_incomplete_array(self):
        prog = mock_program()
        type = prog.array_type(prog.int_type("int", 4, True), None)
        self.assertEqual(member_at_offset(type, 0), "[0]")
        self.assertEqual(member_at_offset(type, 8), "[2]")

    def test_incomplete_array_offset(self):
        prog = mock_program()
        type = prog.array_type(prog.int_type("int", 4, True), None)
        self.assertEqual(member_at_offset(type, 3), "[0]+0x3")
        self.assertEqual(member_at_offset(type, 10), "[2]+0x2")

    def test_incomplete_array_member(self):
        prog = mock_program()
        type = prog.struct_type(
            None,
            16,
            (
                TypeMember(prog.int_type("int", 4, True), "n", 0),
                TypeMember(
                    prog.array_type(prog.int_type("int", 4, True), None), "a", 32
                ),
            ),
        )
        self.assertEqual(member_at_offset(type, 0), "n")
        self.assertEqual(member_at_offset(type, 4), "a[0]")
        self.assertEqual(member_at_offset(type, 8), "a[1]")

    def test_union(self):
        prog = mock_program()
        option_type = prog.union_type(
            "option",
            4,
            (
                TypeMember(prog.int_type("int", 4, True), "i"),
                TypeMember(prog.float_type("float", 4), "f"),
            ),
        )
        self.assertEqual(member_at_offset(option_type, 0), "i or f")

    def test_union_end(self):
        prog = mock_program()
        option_type = prog.union_type(
            "option",
            4,
            (
                TypeMember(prog.int_type("int", 4, True), "i"),
                TypeMember(prog.float_type("float", 4), "f"),
            ),
        )
        self.assertEqual(member_at_offset(option_type, 4), "<end>")

    def test_union_of_structs(self):
        prog = mock_program()
        type = prog.union_type(
            None,
            8,
            (
                TypeMember(
                    prog.struct_type(
                        None,
                        8,
                        (
                            TypeMember(prog.int_type("int", 4, True), "x", 0),
                            TypeMember(prog.int_type("int", 4, True), "y", 32),
                        ),
                    ),
                    "point",
                ),
                TypeMember(prog.float_type("int", 4), "i"),
            ),
        )
        self.assertEqual(member_at_offset(type, 0), "point.x or i")
        self.assertEqual(member_at_offset(type, 4), "point.y")

    def test_unions_nested(self):
        prog = mock_program()
        type = prog.union_type(
            None,
            8,
            (
                TypeMember(
                    prog.union_type(
                        None,
                        8,
                        (
                            TypeMember(prog.int_type("long", 8, True), "l"),
                            TypeMember(prog.float_type("double", 8), "d"),
                        ),
                    ),
                    "big",
                ),
                TypeMember(
                    prog.union_type(
                        None,
                        4,
                        (
                            TypeMember(prog.int_type("int", 4, True), "i"),
                            TypeMember(prog.float_type("float", 4), "f"),
                        ),
                    ),
                    "small",
                ),
            ),
        )
        self.assertEqual(
            member_at_offset(type, 0), "big.l or big.d or small.i or small.f"
        )
        self.assertEqual(member_at_offset(type, 4), "big.l+0x4 or big.d+0x4")

    def test_type_error(self):
        prog = mock_program()
        self.assertRaises(TypeError, member_at_offset, prog.int_type("int", 4, True), 0)

    def test_typedefs(self):
        prog = mock_program()
        point_type = prog.typedef_type(
            "Point",
            prog.struct_type(
                None,
                8,
                (
                    TypeMember(prog.int_type("int", 4, True), "x", 0),
                    TypeMember(prog.int_type("int", 4, True), "y", 32),
                ),
            ),
        )
        line_segment_type = prog.typedef_type(
            "LineSegment",
            prog.struct_type(
                None,
                16,
                (TypeMember(point_type, "a"), TypeMember(point_type, "b", 64)),
            ),
        )
        self.assertEqual(member_at_offset(line_segment_type, 0), "a.x")
        self.assertEqual(member_at_offset(line_segment_type, 4), "a.y")
        self.assertEqual(member_at_offset(line_segment_type, 8), "b.x")
        self.assertEqual(member_at_offset(line_segment_type, 12), "b.y")
