# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import math
import operator
import struct

from drgn import (
    FaultError,
    Object,
    ObjectAbsentError,
    OutOfBoundsError,
    Qualifiers,
    Type,
    TypeMember,
    cast,
    reinterpret,
    sizeof,
)
from tests import MockMemorySegment, MockProgramTestCase, mock_program


class TestInit(MockProgramTestCase):
    def test_type_stays_alive(self):
        obj = Object(self.prog, self.prog.int_type("int", 4, True), value=0)
        self.assertIdentical(obj.type_, self.prog.int_type("int", 4, True))
        type_ = obj.type_
        del obj
        self.assertIdentical(type_, self.prog.int_type("int", 4, True))

    def test_type(self):
        self.assertRaisesRegex(
            TypeError, "type must be Type, str, or None", Object, self.prog, 1, value=0
        )
        self.assertRaisesRegex(
            ValueError, "reference must have type", Object, self.prog, address=0
        )
        self.assertRaisesRegex(
            ValueError, "absent object must have type", Object, self.prog
        )

    def test_address_nand_value(self):
        self.assertRaisesRegex(
            ValueError,
            "object cannot have address and value",
            Object,
            self.prog,
            "int",
            0,
            address=0,
        )
        self.assertRaisesRegex(
            ValueError,
            "object cannot have address and value",
            Object,
            self.prog,
            "int",
            value=0,
            address=0,
        )

    def test_integer_address(self):
        self.assertRaises(TypeError, Object, self.prog, "int", address="NULL")

    def test_bit_field_size(self):
        self.assertRaises(
            TypeError, Object, self.prog, "int", address=0, bit_field_size="1"
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field size cannot be zero",
            Object,
            self.prog,
            "int",
            address=0,
            bit_field_size=0,
        )

    def test_bit_offset(self):
        self.assertRaisesRegex(
            ValueError,
            "value cannot have bit offset",
            Object,
            self.prog,
            "int",
            value=0,
            bit_offset=4,
        )
        self.assertRaisesRegex(
            ValueError,
            "value cannot have bit offset",
            Object,
            self.prog,
            self.point_type,
            value={},
            bit_offset=4,
        )
        self.assertRaisesRegex(
            ValueError,
            "absent object cannot have bit offset",
            Object,
            self.prog,
            "int",
            bit_offset=4,
        )

    def test_integer_size(self):
        self.assertRaisesRegex(
            ValueError,
            "unsupported integer bit size",
            Object,
            self.prog,
            self.prog.int_type("ZERO", 0, True),
        )
        self.assertRaisesRegex(
            ValueError,
            "unsupported integer bit size",
            Object,
            self.prog,
            self.prog.int_type("BIG", 16, True),
        )

    def test_float_size(self):
        for i in range(10):
            if i == 4 or i == 8:
                continue
            self.assertRaisesRegex(
                ValueError,
                "unsupported floating-point bit size",
                Object,
                self.prog,
                self.prog.float_type("FLOAT", i),
            )


class TestReference(MockProgramTestCase):
    def test_basic(self):
        self.add_memory_segment((1000).to_bytes(4, "little"), virt_addr=0xFFFF0000)

        obj = Object(self.prog, "int", address=0xFFFF0000)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("int"))
        self.assertFalse(obj.absent_)
        self.assertEqual(obj.address_, 0xFFFF0000)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 1000)
        self.assertEqual(repr(obj), "Object(prog, 'int', address=0xffff0000)")

        self.assertIdentical(obj.read_(), Object(self.prog, "int", value=1000))

        obj = Object(
            self.prog, self.prog.int_type("sbe32", 4, True, "big"), address=0xFFFF0000
        )
        self.assertEqual(obj.value_(), -402456576)

        obj = Object(self.prog, "unsigned int", address=0xFFFF0000, bit_field_size=4)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertEqual(obj.bit_field_size_, 4)
        self.assertEqual(obj.value_(), 8)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned int', address=0xffff0000, bit_field_size=4)",
        )
        self.assertRaises(TypeError, sizeof, obj)

        obj = Object(
            self.prog,
            "unsigned int",
            address=0xFFFF0000,
            bit_field_size=4,
            bit_offset=4,
        )
        self.assertEqual(obj.bit_offset_, 4)
        self.assertEqual(obj.bit_field_size_, 4)
        self.assertEqual(obj.value_(), 14)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned int', address=0xffff0000, bit_offset=4, bit_field_size=4)",
        )

    def test_overflow(self):
        Object(self.prog, "char", address=0xFFFFFFFFFFFFFFFF)
        Object(
            self.prog,
            "char",
            address=0xFFFFFFFFFFFFFFFF,
            bit_field_size=1,
            bit_offset=7,
        )

    def test_read_unsigned(self):
        value = 12345678912345678989
        for bit_size in range(1, 65):
            for bit_offset in range(8):
                size = (bit_size + bit_offset + 7) // 8
                size_mask = (1 << (8 * size)) - 1
                for byteorder in ["little", "big"]:
                    if byteorder == "little":
                        tmp = value << bit_offset
                    else:
                        tmp = value << (8 - bit_size - bit_offset) % 8
                    tmp &= size_mask
                    buf = tmp.to_bytes(size, byteorder)
                    prog = mock_program(segments=[MockMemorySegment(buf, 0)])
                    obj = Object(
                        prog,
                        prog.int_type("unsigned long long", 8, False, byteorder),
                        address=0,
                        bit_field_size=bit_size,
                        bit_offset=bit_offset,
                    )
                    self.assertEqual(obj.value_(), value & ((1 << bit_size) - 1))

    def test_read_float(self):
        pi32 = struct.unpack("f", struct.pack("f", math.pi))[0]
        for bit_size in [32, 64]:
            for bit_offset in range(8):
                for byteorder in ["little", "big"]:
                    if bit_size == 64:
                        fmt = "<d"
                        expected = math.pi
                    else:
                        fmt = "<f"
                        expected = pi32
                    tmp = int.from_bytes(struct.pack(fmt, math.pi), "little")
                    if byteorder == "little":
                        tmp <<= bit_offset
                    else:
                        tmp <<= (8 - bit_size - bit_offset) % 8
                    buf = tmp.to_bytes((bit_size + bit_offset + 7) // 8, byteorder)
                    prog = mock_program(segments=[MockMemorySegment(buf, 0)])
                    obj = Object(
                        prog,
                        prog.float_type(
                            "double" if bit_size == 64 else "float",
                            bit_size // 8,
                            byteorder,
                        ),
                        address=0,
                        bit_offset=bit_offset,
                    )
                    self.assertEqual(obj.value_(), expected)

    def test_struct(self):
        self.add_memory_segment(
            (
                (99).to_bytes(4, "little")
                + (-1).to_bytes(4, "little", signed=True)
                + (12345).to_bytes(4, "little")
                + (0).to_bytes(4, "little")
            ),
            virt_addr=0xFFFF0000,
        )
        self.types.append(self.point_type)
        obj = Object(self.prog, "struct point", address=0xFFFF0000)
        self.assertEqual(obj.value_(), {"x": 99, "y": -1})
        self.assertEqual(sizeof(obj), 8)

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
        self.assertEqual(
            obj.value_(), {"point": {"x": 99, "y": -1}, "bar": 12345, "baz": 0}
        )

    def test_read_struct_bit_offset(self):
        value = 12345678912345678989
        for bit_size in range(1, 65):
            for bit_offset in range(8):
                size = (bit_size + bit_offset + 7) // 8
                size_mask = (1 << (8 * size)) - 1
                for byteorder in ["little", "big"]:
                    if byteorder == "little":
                        tmp = value << bit_offset
                    else:
                        tmp = value << (8 - bit_size - bit_offset) % 8
                    tmp &= size_mask
                    buf = tmp.to_bytes(size, byteorder) + b"\0"
                    prog = mock_program(segments=[MockMemorySegment(buf, 0)])
                    obj = Object(
                        prog,
                        prog.struct_type(
                            None,
                            (bit_offset + bit_size + 7) // 8,
                            (
                                TypeMember(
                                    Object(
                                        prog,
                                        prog.int_type(
                                            "unsigned long long",
                                            8,
                                            False,
                                            byteorder,
                                        ),
                                        bit_field_size=bit_size,
                                    ),
                                    "x",
                                    bit_offset=bit_offset,
                                ),
                            ),
                        ),
                        address=0,
                    )
                    self.assertEqual(obj.x.value_(), value & ((1 << bit_size) - 1))
                    self.assertEqual(
                        obj.x.read_().value_(), value & ((1 << bit_size) - 1)
                    )
                    self.assertEqual(
                        obj.read_().x.value_(), value & ((1 << bit_size) - 1)
                    )

    def test_array(self):
        segment = bytearray()
        for i in range(10):
            segment.extend(i.to_bytes(4, "little"))
        self.add_memory_segment(segment, virt_addr=0xFFFF0000)
        obj = Object(self.prog, "int [5]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [0, 1, 2, 3, 4])
        self.assertEqual(sizeof(obj), 20)

        obj = Object(self.prog, "int [2][5]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]])

        obj = Object(self.prog, "int [2][2][2]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [[[0, 1], [2, 3]], [[4, 5], [6, 7]]])

    def test_void(self):
        obj = Object(self.prog, self.prog.void_type(), address=0)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.void_type())
        self.assertEqual(obj.address_, 0)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertRaisesRegex(
            TypeError, "cannot read object with void type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with void type", obj.read_
        )
        self.assertRaises(TypeError, sizeof, obj)

    def test_function(self):
        obj = Object(
            self.prog,
            self.prog.function_type(self.prog.void_type(), (), False),
            address=0,
        )
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(
            obj.type_, self.prog.function_type(self.prog.void_type(), (), False)
        )
        self.assertEqual(obj.address_, 0)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertRaisesRegex(
            TypeError, "cannot read object with function type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with function type", obj.read_
        )
        self.assertRaises(TypeError, sizeof, obj)

    def test_incomplete(self):
        # It's valid to create references with incomplete type, but not to read
        # from them.
        obj = Object(self.prog, self.prog.struct_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete structure type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete structure type", obj.read_
        )
        self.assertRaises(TypeError, sizeof, obj)

        obj = Object(self.prog, self.prog.union_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete union type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete union type", obj.read_
        )

        obj = Object(self.prog, self.prog.enum_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete enumerated type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete enumerated type", obj.read_
        )

        obj = Object(
            self.prog,
            self.prog.array_type(self.prog.int_type("int", 4, True)),
            address=0,
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete array type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete array type", obj.read_
        )

    def test_non_scalar_bit_offset(self):
        obj = Object(
            self.prog,
            self.prog.struct_type(
                "weird", 9, (TypeMember(self.point_type, "point", bit_offset=1),)
            ),
            address=0xFFFF0000,
        )
        self.assertRaisesRegex(
            ValueError, "non-scalar must be byte-aligned", obj.member_, "point"
        )
        self.assertRaisesRegex(
            ValueError,
            "non-scalar must be byte-aligned",
            Object,
            self.prog,
            self.point_type,
            address=0xFFFF0000,
            bit_offset=1,
        )
        self.assertIdentical(
            Object(self.prog, self.point_type, address=0xFFFF0000, bit_offset=32),
            Object(self.prog, self.point_type, address=0xFFFF0004),
        )


class TestValue(MockProgramTestCase):
    def test_positional(self):
        self.assertIdentical(
            Object(self.prog, "int", 1), Object(self.prog, "int", value=1)
        )

    def test_signed(self):
        obj = Object(self.prog, "int", value=-4)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("int"))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), -4)
        self.assertEqual(repr(obj), "Object(prog, 'int', value=-4)")

        self.assertIdentical(obj.read_(), obj)

        self.assertIdentical(Object(self.prog, "int", value=2 ** 32 - 4), obj)
        self.assertIdentical(Object(self.prog, "int", value=2 ** 64 - 4), obj)
        self.assertIdentical(Object(self.prog, "int", value=2 ** 128 - 4), obj)
        self.assertIdentical(Object(self.prog, "int", value=-4.6), obj)

        self.assertRaisesRegex(
            TypeError,
            "'int' value must be number",
            Object,
            self.prog,
            "int",
            value=b"asdf",
        )

        obj = Object(self.prog, "int", value=8, bit_field_size=4)
        self.assertIsNone(obj.bit_offset_)
        self.assertEqual(obj.bit_field_size_, 4)
        self.assertEqual(obj.value_(), -8)
        self.assertEqual(repr(obj), "Object(prog, 'int', value=-8, bit_field_size=4)")

        value = 12345678912345678989
        for bit_size in range(1, 65):
            tmp = value & ((1 << bit_size) - 1)
            mask = 1 << (bit_size - 1)
            tmp = (tmp ^ mask) - mask
            self.assertEqual(
                Object(
                    self.prog, "long", value=value, bit_field_size=bit_size
                ).value_(),
                tmp,
            )

    def test_unsigned(self):
        obj = Object(self.prog, "unsigned int", value=2 ** 32 - 1)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("unsigned int"))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 2 ** 32 - 1)
        self.assertEqual(repr(obj), "Object(prog, 'unsigned int', value=4294967295)")

        self.assertIdentical(Object(self.prog, "unsigned int", value=-1), obj)
        self.assertIdentical(Object(self.prog, "unsigned int", value=2 ** 64 - 1), obj)
        self.assertIdentical(Object(self.prog, "unsigned int", value=2 ** 65 - 1), obj)
        self.assertIdentical(
            Object(self.prog, "unsigned int", value=2 ** 32 - 1 + 0.9), obj
        )

        self.assertRaisesRegex(
            TypeError,
            "'unsigned int' value must be number",
            Object,
            self.prog,
            "unsigned int",
            value="foo",
        )

        obj = Object(self.prog, "unsigned int", value=24, bit_field_size=4)
        self.assertIsNone(obj.bit_offset_)
        self.assertEqual(obj.bit_field_size_, 4)
        self.assertEqual(obj.value_(), 8)
        self.assertEqual(
            repr(obj), "Object(prog, 'unsigned int', value=8, bit_field_size=4)"
        )

        value = 12345678912345678989
        for bit_size in range(1, 65):
            self.assertEqual(
                Object(
                    self.prog,
                    "unsigned long long",
                    value=value,
                    bit_field_size=bit_size,
                ).value_(),
                value & ((1 << bit_size) - 1),
            )

    def test_float(self):
        obj = Object(self.prog, "double", value=3.14)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("double"))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 3.14)
        self.assertEqual(repr(obj), "Object(prog, 'double', value=3.14)")

        obj = Object(self.prog, "double", value=-100.0)
        self.assertIdentical(Object(self.prog, "double", value=-100), obj)

        self.assertRaisesRegex(
            TypeError,
            "'double' value must be number",
            Object,
            self.prog,
            "double",
            value={},
        )

        self.assertEqual(Object(self.prog, "double", value=math.e).value_(), math.e)
        self.assertEqual(
            Object(self.prog, "float", value=math.e).value_(),
            struct.unpack("f", struct.pack("f", math.e))[0],
        )

    def test_enum(self):
        self.assertEqual(Object(self.prog, self.color_type, value=0).value_(), 0)

    def test_incomplete_struct(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create value with incomplete structure type",
            Object,
            self.prog,
            self.prog.struct_type("foo"),
            value={},
        )

    def test_incomplete_union(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create value with incomplete union type",
            Object,
            self.prog,
            self.prog.union_type("foo"),
            value={},
        )

    def test_incomplete_class(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create value with incomplete class type",
            Object,
            self.prog,
            self.prog.class_type("foo"),
            value={},
        )

    def test_incomplete_enum(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create value with incomplete enumerated type",
            Object,
            self.prog,
            self.prog.enum_type("foo"),
            value=0,
        )

    def test_incomplete_array(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create value with incomplete array type",
            Object,
            self.prog,
            self.prog.array_type(self.prog.int_type("int", 4, True)),
            value=[],
        )

    def test_compound(self):
        obj = Object(self.prog, self.point_type, value={"x": 100, "y": -5})
        self.assertIdentical(obj.x, Object(self.prog, "int", value=100))
        self.assertIdentical(obj.y, Object(self.prog, "int", value=-5))

        self.assertIdentical(
            Object(self.prog, self.point_type, value={}),
            Object(self.prog, self.point_type, value={"x": 0, "y": 0}),
        )

        value = {
            "a": {"x": 1, "y": 2},
            "b": {"x": 3, "y": 4},
        }
        obj = Object(self.prog, self.line_segment_type, value=value)
        self.assertIdentical(
            obj.a, Object(self.prog, self.point_type, value={"x": 1, "y": 2})
        )
        self.assertIdentical(
            obj.b, Object(self.prog, self.point_type, value={"x": 3, "y": 4})
        )
        self.assertEqual(obj.value_(), value)

        invalid_struct = self.prog.struct_type(
            "foo",
            4,
            (
                TypeMember(self.prog.int_type("short", 2, True), "a"),
                # Straddles the end of the structure.
                TypeMember(self.prog.int_type("int", 4, True), "b", 16),
                # Beyond the end of the structure.
                TypeMember(self.prog.int_type("int", 4, True), "c", 32),
            ),
        )

        Object(self.prog, invalid_struct, value={"a": 0})
        self.assertRaisesRegex(
            OutOfBoundsError,
            "out of bounds of value",
            Object,
            self.prog,
            invalid_struct,
            value={"a": 0, "b": 4},
        )
        self.assertRaisesRegex(
            OutOfBoundsError,
            "out of bounds of value",
            Object,
            self.prog,
            invalid_struct,
            value={"a": 0, "c": 4},
        )

        self.assertRaisesRegex(
            TypeError,
            "must be dictionary or mapping",
            Object,
            self.prog,
            self.point_type,
            value=1,
        )
        self.assertRaisesRegex(
            TypeError,
            "member key must be string",
            Object,
            self.prog,
            self.point_type,
            value={0: 0},
        )
        self.assertRaisesRegex(
            TypeError,
            "must be number",
            Object,
            self.prog,
            self.point_type,
            value={"x": []},
        )
        self.assertRaisesRegex(
            LookupError,
            "has no member 'z'",
            Object,
            self.prog,
            self.point_type,
            value={"z": 999},
        )

    def test_compound_offset(self):
        value = {"n": 23, "x": 100, "y": -5}
        obj = Object(
            self.prog,
            self.prog.struct_type(
                None,
                12,
                (
                    TypeMember(self.prog.int_type("int", 4, True), "n"),
                    TypeMember(self.point_type, None, 32),
                ),
            ),
            value,
        )
        self.assertEqual(obj.value_(), value)
        self.assertIdentical(obj.x, Object(self.prog, "int", value=100))
        self.assertIdentical(obj.y, Object(self.prog, "int", value=-5))

    def test_pointer(self):
        obj = Object(self.prog, "int *", value=0xFFFF0000)
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 0xFFFF0000)
        self.assertEqual(repr(obj), "Object(prog, 'int *', value=0xffff0000)")

    def test_pointer_typedef(self):
        obj = Object(
            self.prog,
            self.prog.typedef_type("INTP", self.prog.type("int *")),
            value=0xFFFF0000,
        )
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 0xFFFF0000)
        self.assertEqual(repr(obj), "Object(prog, 'INTP', value=0xffff0000)")

    def test_array(self):
        obj = Object(self.prog, "int [2]", value=[1, 2])
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.address_)

        self.assertIdentical(obj[0], Object(self.prog, "int", value=1))
        self.assertIdentical(obj[1], Object(self.prog, "int", value=2))

        self.assertIdentical(
            Object(self.prog, "int [2]", value=[]),
            Object(self.prog, "int [2]", value=[0, 0]),
        )

        self.assertRaisesRegex(
            TypeError, "must be iterable", Object, self.prog, "int [1]", value=1
        )
        self.assertRaisesRegex(
            ValueError,
            "too many items in array value",
            Object,
            self.prog,
            "int [1]",
            value=[1, 2],
        )

    def test_non_scalar_bit_offset(self):
        obj = Object(
            self.prog,
            self.prog.struct_type(
                "weird", 9, (TypeMember(self.point_type, "point", bit_offset=1),)
            ),
            value={},
        )
        self.assertRaisesRegex(
            ValueError, "non-scalar must be byte-aligned", obj.member_, "point"
        )


class TestAbsent(MockProgramTestCase):
    def test_basic(self):
        for obj in [
            Object(self.prog, "int"),
            Object(self.prog, "int", value=None, address=None),
        ]:
            self.assertIs(obj.prog_, self.prog)
            self.assertIdentical(obj.type_, self.prog.type("int"))
            self.assertTrue(obj.absent_)
            self.assertIsNone(obj.address_)
            self.assertIsNone(obj.bit_offset_)
            self.assertIsNone(obj.bit_field_size_)
            self.assertRaises(ObjectAbsentError, obj.value_)
            self.assertEqual(repr(obj), "Object(prog, 'int')")

            self.assertRaises(ObjectAbsentError, obj.read_)

    def test_bit_field(self):
        obj = Object(self.prog, "int", bit_field_size=1)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("int"))
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertEqual(obj.bit_field_size_, 1)
        self.assertEqual(repr(obj), "Object(prog, 'int', bit_field_size=1)")

    def test_operators(self):
        absent = Object(self.prog, "int")
        obj = Object(self.prog, "int", 1)
        for op in [
            operator.lt,
            operator.le,
            operator.eq,
            operator.ge,
            operator.gt,
            operator.add,
            operator.and_,
            operator.lshift,
            operator.mod,
            operator.mul,
            operator.or_,
            operator.rshift,
            operator.sub,
            operator.truediv,
            operator.xor,
        ]:
            self.assertRaises(ObjectAbsentError, op, absent, obj)
            self.assertRaises(ObjectAbsentError, op, obj, absent)

        for op in [
            operator.not_,
            operator.truth,
            operator.index,
            operator.inv,
            operator.neg,
            operator.pos,
            round,
            math.trunc,
            math.floor,
            math.ceil,
        ]:
            self.assertRaises(ObjectAbsentError, op, absent)

        self.assertRaises(ObjectAbsentError, absent.address_of_)

        self.assertRaises(
            ObjectAbsentError,
            operator.getitem,
            Object(self.prog, "int [2]"),
            0,
        )

        self.assertRaises(ObjectAbsentError, Object(self.prog, "char [16]").string_)
        self.assertRaises(ObjectAbsentError, Object(self.prog, "char *").string_)


class TestConversions(MockProgramTestCase):
    def test_bool(self):
        self.assertTrue(Object(self.prog, "int", value=-1))
        self.assertFalse(Object(self.prog, "int", value=0))

        self.assertTrue(Object(self.prog, "unsigned int", value=1))
        self.assertFalse(Object(self.prog, "unsigned int", value=0))

        self.assertTrue(Object(self.prog, "double", value=3.14))
        self.assertFalse(Object(self.prog, "double", value=0.0))

        self.assertTrue(Object(self.prog, "int *", value=0xFFFF0000))
        self.assertFalse(Object(self.prog, "int *", value=0x0))

        self.assertTrue(Object(self.prog, "int []", address=0))

        self.assertRaisesRegex(
            TypeError,
            "cannot convert 'struct point' to bool",
            bool,
            Object(self.prog, self.point_type, address=0),
        )

    def test_int(self):
        self.assertEqual(int(Object(self.prog, "int", value=-1)), -1)
        self.assertEqual(int(Object(self.prog, "unsigned int", value=1)), 1)
        self.assertEqual(int(Object(self.prog, "double", value=9.99)), 9)
        self.assertEqual(int(Object(self.prog, "int *", value=0)), 0)

        self.assertRaisesRegex(
            TypeError,
            r"cannot convert 'int \[\]' to int",
            int,
            Object(self.prog, "int []", address=0),
        )

    def test_float(self):
        self.assertEqual(float(Object(self.prog, "int", value=-1)), -1.0)
        self.assertEqual(float(Object(self.prog, "unsigned int", value=1)), 1.0)
        self.assertEqual(float(Object(self.prog, "double", value=9.99)), 9.99)

        self.assertRaisesRegex(
            TypeError,
            r"cannot convert 'int \*' to float",
            float,
            Object(self.prog, "int *", value=0xFFFF0000),
        )
        self.assertRaisesRegex(
            TypeError,
            r"cannot convert 'int \[\]' to float",
            float,
            Object(self.prog, "int []", address=0),
        )

    def test_index(self):
        self.assertEqual(operator.index(Object(self.prog, "int", value=-1)), -1)
        self.assertEqual(operator.index(Object(self.prog, "unsigned int", value=1)), 1)
        self.assertEqual(operator.index(Object(self.prog, "int *", value=0)), 0)

        self.assertRaisesRegex(
            TypeError,
            "'double' object cannot be interpreted as an integer",
            operator.index,
            Object(self.prog, "double", value=9.99),
        )
        self.assertRaisesRegex(
            TypeError,
            r"'int \[\]' object cannot be interpreted as an integer",
            operator.index,
            Object(self.prog, "int []", address=0),
        )


class TestInvalidBitField(MockProgramTestCase):
    def test_integer(self):
        self.assertRaisesRegex(
            ValueError,
            "bit field size is larger than type size",
            Object,
            self.prog,
            "int",
            value=0,
            bit_field_size=64,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field size is larger than type size",
            Object,
            self.prog,
            "int",
            address=0,
            bit_field_size=64,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field size is larger than type size",
            Object,
            self.prog,
            "unsigned int",
            value=0,
            bit_field_size=64,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field size is larger than type size",
            Object,
            self.prog,
            "unsigned int",
            address=0,
            bit_field_size=64,
        )

    def test_float(self):
        self.assertRaisesRegex(
            ValueError,
            "bit field must be integer",
            Object,
            self.prog,
            "float",
            value=0,
            bit_field_size=16,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field must be integer",
            Object,
            self.prog,
            "float",
            address=0,
            bit_field_size=16,
        )

    def test_reference(self):
        self.assertRaisesRegex(
            ValueError,
            "bit field must be integer",
            Object,
            self.prog,
            self.point_type,
            address=0,
            bit_field_size=4,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field must be integer",
            Object,
            self.prog,
            self.point_type,
            value={},
            bit_field_size=4,
        )


class TestGenericOperators(MockProgramTestCase):
    def setUp(self):
        super().setUp()
        self.add_memory_segment(
            b"".join(i.to_bytes(4, "little") for i in range(4)), virt_addr=0xFFFF0000
        )

    def test_len(self):
        self.assertEqual(len(Object(self.prog, "int [0]", address=0)), 0)
        self.assertEqual(len(Object(self.prog, "int [10]", address=0)), 10)
        self.assertRaisesRegex(
            TypeError, "'int' has no len()", len, Object(self.prog, "int", address=0)
        )
        self.assertRaisesRegex(
            TypeError,
            r"'int \[\]' has no len()",
            len,
            Object(self.prog, "int []", address=0),
        )

    def test_address_of(self):
        obj = Object(self.prog, "int", address=0xFFFF0000)
        self.assertIdentical(
            obj.address_of_(), Object(self.prog, "int *", value=0xFFFF0000)
        )
        obj = obj.read_()
        self.assertRaisesRegex(
            ValueError, "cannot take address of value", obj.address_of_
        )
        obj = Object(self.prog, "int", address=0xFFFF0000, bit_field_size=4)
        self.assertRaisesRegex(
            ValueError, "cannot take address of bit field", obj.address_of_
        )
        obj = Object(self.prog, "int", address=0xFFFF0000, bit_offset=4)
        self.assertRaisesRegex(
            ValueError, "cannot take address of bit field", obj.address_of_
        )

    def test_subscript(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            for i in range(5):
                self.assertIdentical(
                    obj[i], Object(self.prog, "int", address=0xFFFF0000 + 4 * i)
                )
                if i < 4:
                    self.assertIdentical(
                        obj[i].read_(), Object(self.prog, "int", value=i)
                    )
                else:
                    self.assertRaises(FaultError, obj[i].read_)

        obj = arr.read_()
        for i in range(4):
            self.assertIdentical(obj[i], Object(self.prog, "int", value=i))
        self.assertRaisesRegex(OutOfBoundsError, "out of bounds", obj.__getitem__, 4)
        obj = Object(self.prog, "int", value=0)
        self.assertRaises(TypeError, obj.__getitem__, 0)

    def test_cast_primitive_value(self):
        obj = Object(self.prog, "long", value=2 ** 32 + 1)
        self.assertIdentical(cast("int", obj), Object(self.prog, "int", value=1))
        self.assertIdentical(
            cast("int", obj.read_()), Object(self.prog, "int", value=1)
        )
        self.assertIdentical(
            cast("const int", Object(self.prog, "int", value=1)),
            Object(self.prog, "const int", value=1),
        )
        self.assertRaisesRegex(
            TypeError,
            "cannot cast to 'struct point'",
            cast,
            self.point_type,
            Object(self.prog, "int", value=1),
        )

    def test_cast_compound_value(self):
        obj = Object(self.prog, self.point_type, address=0xFFFF0000).read_()
        self.assertRaisesRegex(
            TypeError,
            "cannot cast to 'struct point'",
            cast,
            self.point_type,
            obj,
        )
        self.assertRaisesRegex(
            TypeError,
            "cannot convert 'struct point' to 'enum color'",
            cast,
            self.color_type,
            obj,
        )

    def test_cast_invalid(self):
        obj = Object(self.prog, "int", value=1)
        self.assertRaisesRegex(TypeError, "cannot cast to void type", cast, "void", obj)

    def test_reinterpret_reference(self):
        obj = Object(self.prog, "int", address=0xFFFF0000)
        self.assertIdentical(reinterpret("int", obj), obj)
        self.assertIdentical(
            reinterpret(self.prog.int_type("int", 4, True, "big"), obj),
            Object(
                self.prog, self.prog.int_type("int", 4, True, "big"), address=0xFFFF0000
            ),
        )

        obj = Object(self.prog, "int []", address=0xFFFF0000)
        self.assertIdentical(
            reinterpret("int [4]", obj),
            Object(self.prog, "int [4]", address=0xFFFF0000),
        )

    def test_reinterpret_value(self):
        self.types.append(self.point_type)
        self.types.append(
            self.prog.struct_type(
                "foo", 8, (TypeMember(self.prog.int_type("long", 8, True), "counter"),)
            ),
        )
        obj = Object(self.prog, "struct point", address=0xFFFF0008).read_()
        self.assertIdentical(
            reinterpret("struct foo", obj),
            Object(self.prog, "struct foo", address=0xFFFF0008).read_(),
        )
        self.assertIdentical(reinterpret("int", obj), Object(self.prog, "int", value=2))
        self.assertIdentical(
            reinterpret(self.prog.int_type("int", 4, True, "big"), obj),
            Object(
                self.prog, self.prog.int_type("int", 4, True, "big"), value=33554432
            ),
        )

    def test_member(self):
        reference = Object(self.prog, self.point_type, address=0xFFFF0000)
        unnamed_reference = Object(
            self.prog,
            self.prog.struct_type(
                "point",
                8,
                (
                    TypeMember(
                        self.prog.struct_type(None, 8, self.point_type.members), None
                    ),
                ),
            ),
            address=0xFFFF0000,
        )
        ptr = Object(
            self.prog, self.prog.pointer_type(self.point_type), value=0xFFFF0000
        )
        for obj in [reference, unnamed_reference, ptr]:
            self.assertIdentical(
                obj.member_("x"), Object(self.prog, "int", address=0xFFFF0000)
            )
            self.assertIdentical(obj.member_("x"), obj.x)
            self.assertIdentical(
                obj.member_("y"), Object(self.prog, "int", address=0xFFFF0004)
            )
            self.assertIdentical(obj.member_("y"), obj.y)

            self.assertRaisesRegex(
                LookupError, "'struct point' has no member 'z'", obj.member_, "z"
            )
            self.assertRaisesRegex(
                AttributeError, "'struct point' has no member 'z'", getattr, obj, "z"
            )

        obj = reference.read_()
        self.assertIdentical(obj.x, Object(self.prog, "int", value=0))
        self.assertIdentical(obj.y, Object(self.prog, "int", value=1))

        obj = Object(self.prog, "int", value=1)
        self.assertRaisesRegex(
            TypeError, "'int' is not a structure, union, or class", obj.member_, "x"
        )
        self.assertRaisesRegex(AttributeError, "no attribute", getattr, obj, "x")

    def test_bit_field_member(self):
        self.add_memory_segment(b"\x07\x10\x5e\x5f\x1f\0\0\0", virt_addr=0xFFFF8000)
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

        obj = Object(self.prog, type_, address=0xFFFF8000)
        self.assertIdentical(
            obj.x,
            Object(
                self.prog,
                self.prog.int_type("int", 4, True),
                address=0xFFFF8000,
                bit_field_size=4,
            ),
        )
        self.assertIdentical(
            obj.y,
            Object(
                self.prog,
                self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST),
                address=0xFFFF8000,
                bit_field_size=28,
                bit_offset=4,
            ),
        )
        self.assertIdentical(
            obj.z,
            Object(
                self.prog,
                self.prog.int_type("int", 4, True),
                address=0xFFFF8004,
                bit_field_size=5,
            ),
        )

    def test_member_out_of_bounds(self):
        obj = Object(
            self.prog,
            self.prog.struct_type("foo", 4, self.point_type.members),
            address=0xFFFF0000,
        ).read_()
        self.assertRaisesRegex(OutOfBoundsError, "out of bounds", getattr, obj, "y")

    def test_string(self):
        self.add_memory_segment(
            b"\x00\x00\xff\xff\x00\x00\x00\x00", virt_addr=0xFFFEFFF8
        )
        self.add_memory_segment(b"hello\0world\0", virt_addr=0xFFFF0000)
        strings = [
            (Object(self.prog, "char *", address=0xFFFEFFF8), b"hello"),
            (Object(self.prog, "char [2]", address=0xFFFF0000), b"he"),
            (Object(self.prog, "char [8]", address=0xFFFF0000), b"hello"),
        ]
        for obj, expected in strings:
            with self.subTest(obj=obj):
                self.assertEqual(obj.string_(), expected)
                self.assertEqual(obj.read_().string_(), expected)

        strings = [
            Object(self.prog, "char []", address=0xFFFF0000),
            Object(self.prog, "int []", address=0xFFFF0000),
            Object(self.prog, "int [2]", address=0xFFFF0000),
            Object(self.prog, "int *", value=0xFFFF0000),
        ]
        for obj in strings:
            self.assertEqual(obj.string_(), b"hello")

        self.assertRaisesRegex(
            TypeError,
            "must be an array or pointer",
            Object(self.prog, "int", value=1).string_,
        )


class TestSpecialMethods(MockProgramTestCase):
    def test_dir(self):
        obj = Object(self.prog, "int", value=0)
        self.assertEqual(dir(obj), sorted(object.__dir__(obj)))

        obj = Object(self.prog, self.point_type, address=0xFFFF0000)
        self.assertEqual(dir(obj), sorted(object.__dir__(obj) + ["x", "y"]))
        self.assertEqual(dir(obj.address_of_()), dir(obj))

    def test_round(self):
        for func in [round, math.trunc, math.floor, math.ceil]:
            for value in [0.0, -0.0, -0.4, 0.4, 0.5, -0.5, 0.6, -0.6, 1.0, -1.0]:
                self.assertEqual(
                    func(Object(self.prog, "double", value=value)), func(value)
                )
                self.assertEqual(
                    func(Object(self.prog, "int", value=value)), func(int(value))
                )
        self.assertIdentical(
            round(Object(self.prog, "int", value=1), 2),
            Object(self.prog, "int", value=1),
        )
        self.assertIdentical(
            round(Object(self.prog, "double", value=0.123), 2),
            Object(self.prog, "double", value=0.12),
        )

    def test_iter(self):
        obj = Object(self.prog, "int [4]", value=[0, 1, 2, 3])
        for i, element in enumerate(obj):
            self.assertIdentical(element, Object(self.prog, "int", value=i))
        self.assertEqual(operator.length_hint(iter(obj)), 4)
        self.assertRaisesRegex(
            TypeError, "'int' is not iterable", iter, Object(self.prog, "int", value=0)
        )
        self.assertRaisesRegex(
            TypeError,
            r"'int \[\]' is not iterable",
            iter,
            Object(self.prog, "int []", address=0),
        )
