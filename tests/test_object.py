# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import math
import operator
import struct

from drgn import (
    FaultError,
    Object,
    OutOfBoundsError,
    Qualifiers,
    Type,
    TypeEnumerator,
    TypeMember,
    array_type,
    cast,
    container_of,
    enum_type,
    float_type,
    function_type,
    int_type,
    pointer_type,
    reinterpret,
    sizeof,
    struct_type,
    typedef_type,
    union_type,
    void_type,
)
from tests import (
    MockMemorySegment,
    ObjectTestCase,
    color_type,
    coord_type,
    line_segment_type,
    mock_program,
    option_type,
    pid_type,
    point_type,
)


class TestInit(ObjectTestCase):
    def test_type_stays_alive(self):
        obj = Object(self.prog, int_type("int", 4, True), value=0)
        self.assertEqual(obj.type_, int_type("int", 4, True))
        type_ = obj.type_
        del obj
        self.assertEqual(type_, int_type("int", 4, True))
        del self.prog
        self.assertEqual(type_, int_type("int", 4, True))

    def test_type(self):
        self.assertRaisesRegex(
            TypeError, "type must be Type, str, or None", Object, self.prog, 1, value=0
        )
        self.assertRaisesRegex(
            ValueError, "reference must have type", Object, self.prog, address=0
        )

    def test_address_xor_value(self):
        self.assertRaisesRegex(
            ValueError, "object must have either address or value", Object, self.prog
        )
        self.assertRaisesRegex(
            ValueError,
            "object must have either address or value",
            Object,
            self.prog,
            "int",
        )
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

    def test_byteorder(self):
        self.assertRaises(
            ValueError, Object, self.prog, "int", address=0, byteorder="middle"
        )
        self.assertRaisesRegex(
            ValueError,
            "primitive value cannot have byteorder",
            Object,
            self.prog,
            "int",
            value=0,
            byteorder="little",
        )

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
            "primitive value cannot have bit offset",
            Object,
            self.prog,
            "int",
            value=0,
            bit_offset=4,
        )


class TestReference(ObjectTestCase):
    def test_basic(self):
        prog = mock_program(
            segments=[
                MockMemorySegment((1000).to_bytes(4, "little"), virt_addr=0xFFFF0000),
            ]
        )
        obj = Object(prog, "int", address=0xFFFF0000)
        self.assertIs(obj.prog_, prog)
        self.assertEqual(obj.type_, prog.type("int"))
        self.assertEqual(obj.address_, 0xFFFF0000)
        self.assertEqual(obj.byteorder_, "little")
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 1000)
        self.assertEqual(repr(obj), "Object(prog, 'int', address=0xffff0000)")

        self.assertEqual(obj.read_(), Object(prog, "int", value=1000))

        obj = Object(prog, "int", address=0xFFFF0000, byteorder="big")
        self.assertEqual(obj.byteorder_, "big")
        self.assertEqual(obj.value_(), -402456576)
        self.assertEqual(
            repr(obj), "Object(prog, 'int', address=0xffff0000, byteorder='big')"
        )
        self.assertEqual(sizeof(obj), 4)

        obj = Object(prog, "unsigned int", address=0xFFFF0000, bit_field_size=4)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertEqual(obj.bit_field_size_, 4)
        self.assertEqual(obj.value_(), 8)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned int', address=0xffff0000, bit_field_size=4)",
        )
        self.assertRaises(TypeError, sizeof, obj)

        obj = Object(
            prog, "unsigned int", address=0xFFFF0000, bit_field_size=4, bit_offset=4
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
        Object(self.prog, f"char [{(2**64 - 1) // 8}]", address=0, bit_offset=7)

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
                        "unsigned long long",
                        address=0,
                        bit_field_size=bit_size,
                        bit_offset=bit_offset,
                        byteorder=byteorder,
                    )
                    self.assertEqual(obj.value_(), value & ((1 << bit_size) - 1))

    def test_read_float(self):
        pi32 = struct.unpack("f", struct.pack("f", math.pi))[0]
        for bit_size in [32, 64]:
            for bit_offset in range(8):
                for byteorder in ["little", "big"]:
                    if bit_size == 64:
                        fmt = "<d"
                        type_ = "double"
                        expected = math.pi
                    else:
                        fmt = "<f"
                        type_ = "float"
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
                        type_,
                        address=0,
                        bit_offset=bit_offset,
                        byteorder=byteorder,
                    )
                    self.assertEqual(obj.value_(), expected)

    def test_struct(self):
        segment = (
            (99).to_bytes(4, "little")
            + (-1).to_bytes(4, "little", signed=True)
            + (12345).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[point_type],
        )

        obj = Object(prog, "struct point", address=0xFFFF0000)
        self.assertEqual(obj.value_(), {"x": 99, "y": -1})
        self.assertEqual(sizeof(obj), 8)

        type_ = struct_type(
            "foo",
            16,
            (
                TypeMember(point_type, "point"),
                TypeMember(
                    struct_type(
                        None,
                        8,
                        (
                            TypeMember(int_type("int", 4, True), "bar"),
                            TypeMember(int_type("int", 4, True), "baz", 32),
                        ),
                    ),
                    None,
                    64,
                ),
            ),
        )
        obj = Object(prog, type_, address=0xFFFF0000)
        self.assertEqual(
            obj.value_(), {"point": {"x": 99, "y": -1}, "bar": 12345, "baz": 0}
        )

    def test_array(self):
        segment = bytearray()
        for i in range(10):
            segment.extend(i.to_bytes(4, "little"))
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        obj = Object(prog, "int [5]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [0, 1, 2, 3, 4])
        self.assertEqual(sizeof(obj), 20)

        obj = Object(prog, "int [2][5]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]])

        obj = Object(prog, "int [2][2][2]", address=0xFFFF0000)
        self.assertEqual(obj.value_(), [[[0, 1], [2, 3]], [[4, 5], [6, 7]]])

    def test_void(self):
        obj = Object(self.prog, void_type(), address=0)
        self.assertIs(obj.prog_, self.prog)
        self.assertEqual(obj.type_, void_type())
        self.assertEqual(obj.address_, 0)
        self.assertEqual(obj.byteorder_, "little")
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
        obj = Object(self.prog, function_type(void_type(), (), False), address=0)
        self.assertIs(obj.prog_, self.prog)
        self.assertEqual(obj.type_, function_type(void_type(), (), False))
        self.assertEqual(obj.address_, 0)
        self.assertEqual(obj.byteorder_, "little")
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
        obj = Object(self.prog, struct_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete structure type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete structure type", obj.read_
        )
        self.assertRaises(TypeError, sizeof, obj)

        obj = Object(self.prog, union_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete union type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete union type", obj.read_
        )

        obj = Object(self.prog, enum_type("foo"), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete enumerated type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete enumerated type", obj.read_
        )

        obj = Object(self.prog, array_type(None, int_type("int", 4, True)), address=0)
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete array type", obj.value_
        )
        self.assertRaisesRegex(
            TypeError, "cannot read object with incomplete array type", obj.read_
        )


class TestValue(ObjectTestCase):
    def test_positional(self):
        self.assertEqual(Object(self.prog, "int", 1), Object(self.prog, "int", value=1))

    def test_signed(self):
        obj = Object(self.prog, "int", value=-4)
        self.assertIs(obj.prog_, self.prog)
        self.assertEqual(obj.type_, self.prog.type("int"))
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.byteorder_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), -4)
        self.assertEqual(repr(obj), "Object(prog, 'int', value=-4)")

        self.assertEqual(obj.read_(), obj)

        self.assertEqual(Object(self.prog, "int", value=2 ** 32 - 4), obj)
        self.assertEqual(Object(self.prog, "int", value=2 ** 64 - 4), obj)
        self.assertEqual(Object(self.prog, "int", value=2 ** 128 - 4), obj)
        self.assertEqual(Object(self.prog, "int", value=-4.6), obj)

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
        self.assertEqual(obj.type_, self.prog.type("unsigned int"))
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.byteorder_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 2 ** 32 - 1)
        self.assertEqual(repr(obj), "Object(prog, 'unsigned int', value=4294967295)")

        self.assertEqual(Object(self.prog, "unsigned int", value=-1), obj)
        self.assertEqual(Object(self.prog, "unsigned int", value=2 ** 64 - 1), obj)
        self.assertEqual(Object(self.prog, "unsigned int", value=2 ** 65 - 1), obj)
        self.assertEqual(
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
        self.assertEqual(obj.type_, self.prog.type("double"))
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.byteorder_)
        self.assertEqual(obj.value_(), 3.14)
        self.assertEqual(repr(obj), "Object(prog, 'double', value=3.14)")

        obj = Object(self.prog, "double", value=-100.0)
        self.assertEqual(Object(self.prog, "double", value=-100), obj)

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
        self.assertEqual(Object(self.prog, color_type, value=0).value_(), 0)

    def test_incomplete(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create object with incomplete structure type",
            Object,
            self.prog,
            struct_type("foo"),
            value={},
        )

        self.assertRaisesRegex(
            TypeError,
            "cannot create object with incomplete union type",
            Object,
            self.prog,
            union_type("foo"),
            value={},
        )

        self.assertRaisesRegex(
            TypeError,
            "cannot create object with incomplete enumerated type",
            Object,
            self.prog,
            enum_type("foo"),
            value=0,
        )

        self.assertRaisesRegex(
            TypeError,
            "cannot create object with incomplete array type",
            Object,
            self.prog,
            array_type(None, int_type("int", 4, True)),
            value=[],
        )

    def test_compound(self):
        obj = Object(self.prog, point_type, value={"x": 100, "y": -5})
        self.assertEqual(obj.x, Object(self.prog, "int", value=100))
        self.assertEqual(obj.y, Object(self.prog, "int", value=-5))

        self.assertEqual(
            Object(self.prog, point_type, value={}),
            Object(self.prog, point_type, value={"x": 0, "y": 0}),
        )

        value = {
            "a": {"x": 1, "y": 2},
            "b": {"x": 3, "y": 4},
        }
        obj = Object(self.prog, line_segment_type, value=value)
        self.assertEqual(obj.a, Object(self.prog, point_type, value={"x": 1, "y": 2}))
        self.assertEqual(obj.b, Object(self.prog, point_type, value={"x": 3, "y": 4}))
        self.assertEqual(obj.value_(), value)

        invalid_struct = struct_type(
            "foo",
            4,
            (
                TypeMember(int_type("short", 2, True), "a"),
                # Straddles the end of the structure.
                TypeMember(int_type("int", 4, True), "b", 16),
                # Beyond the end of the structure.
                TypeMember(int_type("int", 4, True), "c", 32),
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
            point_type,
            value=1,
        )
        self.assertRaisesRegex(
            TypeError,
            "member key must be string",
            Object,
            self.prog,
            point_type,
            value={0: 0},
        )
        self.assertRaisesRegex(
            TypeError, "must be number", Object, self.prog, point_type, value={"x": []}
        )
        self.assertRaisesRegex(
            LookupError,
            "has no member 'z'",
            Object,
            self.prog,
            point_type,
            value={"z": 999},
        )

    def test_pointer(self):
        obj = Object(self.prog, "int *", value=0xFFFF0000)
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 0xFFFF0000)
        self.assertEqual(repr(obj), "Object(prog, 'int *', value=0xffff0000)")

        obj = Object(
            self.prog, typedef_type("INTP", self.prog.type("int *")), value=0xFFFF0000
        )
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 0xFFFF0000)
        self.assertEqual(repr(obj), "Object(prog, 'INTP', value=0xffff0000)")

    def test_array(self):
        obj = Object(self.prog, "int [2]", value=[1, 2])
        self.assertEqual(obj[0], Object(self.prog, "int", value=1))
        self.assertEqual(obj[1], Object(self.prog, "int", value=2))

        self.assertEqual(
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


class TestConversions(ObjectTestCase):
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
            Object(self.prog, point_type, address=0),
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


class TestInvalidBitField(ObjectTestCase):
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
            point_type,
            address=0,
            bit_field_size=4,
        )
        self.assertRaisesRegex(
            ValueError,
            "bit field must be integer",
            Object,
            self.prog,
            point_type,
            value={},
            bit_field_size=4,
        )

    def test_member(self):
        type_ = struct_type("foo", 8, (TypeMember(point_type, "p", 0, 4),))
        obj = Object(self.prog, type_, address=0)
        self.assertRaisesRegex(
            ValueError, "bit field must be integer", obj.member_, "p"
        )


class TestCLiteral(ObjectTestCase):
    def test_int(self):
        self.assertEqual(Object(self.prog, value=1), Object(self.prog, "int", value=1))
        self.assertEqual(
            Object(self.prog, value=-1), Object(self.prog, "int", value=-1)
        )
        self.assertEqual(
            Object(self.prog, value=2 ** 31 - 1),
            Object(self.prog, "int", value=2 ** 31 - 1),
        )

        self.assertEqual(
            Object(self.prog, value=2 ** 31), Object(self.prog, "long", value=2 ** 31)
        )
        # Not int, because this is treated as the negation operator applied to
        # 2**31.
        self.assertEqual(
            Object(self.prog, value=-(2 ** 31)),
            Object(self.prog, "long", value=-(2 ** 31)),
        )

        self.assertEqual(
            Object(self.prog, value=2 ** 63),
            Object(self.prog, "unsigned long long", value=2 ** 63),
        )
        self.assertEqual(
            Object(self.prog, value=2 ** 64 - 1),
            Object(self.prog, "unsigned long long", value=2 ** 64 - 1),
        )
        self.assertEqual(
            Object(self.prog, value=-(2 ** 64 - 1)),
            Object(self.prog, "unsigned long long", value=1),
        )

    def test_bool(self):
        self.assertEqual(
            Object(self.prog, value=True), Object(self.prog, "int", value=1)
        )
        self.assertEqual(
            Object(self.prog, value=False), Object(self.prog, "int", value=0)
        )

    def test_float(self):
        self.assertEqual(
            Object(self.prog, value=3.14), Object(self.prog, "double", value=3.14)
        )

    def test_invalid(self):
        class Foo:
            pass

        self.assertRaisesRegex(
            TypeError, "cannot create Foo literal", Object, self.prog, value=Foo()
        )


class TestCIntegerPromotion(ObjectTestCase):
    def test_conversion_rank_less_than_int(self):
        self.assertEqual(+self.bool(False), self.int(0))

        self.assertEqual(
            +Object(self.prog, "char", value=1), Object(self.prog, "int", value=1)
        )
        self.assertEqual(
            +Object(self.prog, "signed char", value=2),
            Object(self.prog, "int", value=2),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned char", value=3),
            Object(self.prog, "int", value=3),
        )

        self.assertEqual(
            +Object(self.prog, "short", value=1), Object(self.prog, "int", value=1)
        )
        self.assertEqual(
            +Object(self.prog, "unsigned short", value=2),
            Object(self.prog, "int", value=2),
        )

        # If short is the same size as int, then int can't represent all of the
        # values of unsigned short.
        self.assertEqual(
            +Object(self.prog, int_type("short", 4, True), value=1),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, int_type("unsigned short", 4, False), value=2),
            Object(self.prog, "unsigned int", value=2),
        )

    def test_int(self):
        self.assertEqual(
            +Object(self.prog, "int", value=-1), Object(self.prog, "int", value=-1)
        )

        self.assertEqual(
            +Object(self.prog, "unsigned int", value=-1),
            Object(self.prog, "unsigned int", value=-1),
        )

    def test_conversion_rank_greater_than_int(self):
        self.assertEqual(
            +Object(self.prog, "long", value=-1), Object(self.prog, "long", value=-1)
        )

        self.assertEqual(
            +Object(self.prog, "unsigned long", value=-1),
            Object(self.prog, "unsigned long", value=-1),
        )

        self.assertEqual(
            +Object(self.prog, "long long", value=-1),
            Object(self.prog, "long long", value=-1),
        )

        self.assertEqual(
            +Object(self.prog, "unsigned long long", value=-1),
            Object(self.prog, "unsigned long long", value=-1),
        )

    def test_extended_integer(self):
        self.assertEqual(
            +Object(self.prog, int_type("byte", 1, True), value=1),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, int_type("ubyte", 1, False), value=-1),
            Object(self.prog, "int", value=0xFF),
        )
        self.assertEqual(
            +Object(self.prog, int_type("qword", 8, True), value=1),
            Object(self.prog, int_type("qword", 8, True), value=1),
        )
        self.assertEqual(
            +Object(self.prog, int_type("qword", 8, False), value=1),
            Object(self.prog, int_type("qword", 8, False), value=1),
        )

    def test_bit_field(self):
        # Bit fields which can be represented by int or unsigned int should be
        # promoted.
        self.assertEqual(
            +Object(self.prog, "int", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "long", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "int", value=1, bit_field_size=32),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "long", value=1, bit_field_size=32),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned int", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=4),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned int", value=1, bit_field_size=32),
            Object(self.prog, "unsigned int", value=1),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=32),
            Object(self.prog, "unsigned int", value=1),
        )

        # Bit fields which cannot be represented by int or unsigned int should
        # be preserved.
        self.assertEqual(
            +Object(self.prog, "long", value=1, bit_field_size=40),
            Object(self.prog, "long", value=1, bit_field_size=40),
        )
        self.assertEqual(
            +Object(self.prog, "unsigned long", value=1, bit_field_size=40),
            Object(self.prog, "unsigned long", value=1, bit_field_size=40),
        )

    def test_enum(self):
        # Enums should be converted to their compatible type and then promoted.
        self.assertEqual(
            +Object(self.prog, color_type, value=1),
            Object(self.prog, "unsigned int", value=1),
        )

        type_ = enum_type(
            "color",
            self.prog.type("unsigned long long"),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertEqual(
            +Object(self.prog, type_, value=1),
            Object(self.prog, "unsigned long long", value=1),
        )

        type_ = enum_type(
            "color",
            self.prog.type("char"),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.assertEqual(
            +Object(self.prog, type_, value=1), Object(self.prog, "int", value=1)
        )

    def test_typedef(self):
        type_ = typedef_type("SHORT", self.prog.type("short"))
        self.assertEqual(
            +Object(self.prog, type_, value=5), Object(self.prog, "int", value=5)
        )

        # Typedef should be preserved if the type wasn't promoted.
        type_ = typedef_type("self.int", self.prog.type("int"))
        self.assertEqual(
            +Object(self.prog, type_, value=5), Object(self.prog, type_, value=5)
        )

    def test_non_integer(self):
        # Non-integer types should not be affected.
        self.assertEqual(
            +Object(self.prog, "double", value=3.14),
            Object(self.prog, "double", value=3.14),
        )


class TestCCommonRealType(ObjectTestCase):
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
        self.assertEqual(obj1 * obj2, expected_obj)
        if commutative:
            self.assertEqual(obj2 * obj1, expected_obj)

    def test_float(self):
        self.assertCommonRealType("float", "long long", "float")
        self.assertCommonRealType("float", "float", "float")

        self.assertCommonRealType("double", "long long", "double")
        self.assertCommonRealType("double", "float", "double")
        self.assertCommonRealType("double", "double", "double")

        # Floating type not in the standard.
        float64 = float_type("float64", 8)
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

        int64 = int_type("int64", 8, True)
        qword = int_type("qword", 8, True)
        self.assertCommonRealType("long", int64, "long")
        self.assertCommonRealType(int64, qword, qword, commutative=False)
        self.assertCommonRealType(qword, int64, int64, commutative=False)
        self.assertCommonRealType("int", int64, int64)

    def test_unsigned_greater_rank(self):
        self.assertCommonRealType("unsigned long", "int", "unsigned long")
        self.assertCommonRealType("unsigned long long", "long", "unsigned long long")
        self.assertCommonRealType("unsigned long long", "int", "unsigned long long")

        int64 = int_type("int64", 8, True)
        uint64 = int_type("uint64", 8, False)
        self.assertCommonRealType(uint64, "int", uint64)
        self.assertCommonRealType("unsigned long", int64, "unsigned long")

    def test_signed_can_represent_unsigned(self):
        self.assertCommonRealType("long", "unsigned int", "long")
        self.assertCommonRealType("long long", "unsigned int", "long long")

        int64 = int_type("int64", 8, True)
        weirduint = int_type("weirduint", 6, False)
        self.assertCommonRealType(int64, "unsigned int", int64)
        self.assertCommonRealType("long", weirduint, "long")

    def test_corresponding_unsigned(self):
        self.assertCommonRealType("long", "unsigned long", "unsigned long")
        self.assertCommonRealType("long long", "unsigned long", "unsigned long long")

    def test_enum(self):
        self.assertCommonRealType(color_type, color_type, "unsigned int")

    def test_typedef(self):
        type_ = typedef_type("INT", self.prog.type("int"))
        self.assertCommonRealType(type_, type_, type_)
        self.assertCommonRealType("int", type_, type_, commutative=False)
        self.assertCommonRealType(type_, "int", "int", commutative=False)

        type_ = typedef_type("LONG", self.prog.type("long"))
        self.assertCommonRealType(type_, "int", type_)


class TestCOperators(ObjectTestCase):
    def test_cast_array(self):
        obj = Object(self.prog, "int []", address=0xFFFF0000)
        self.assertEqual(
            cast("int *", obj), Object(self.prog, "int *", value=0xFFFF0000)
        )
        self.assertEqual(
            cast("void *", obj), Object(self.prog, "void *", value=0xFFFF0000)
        )
        self.assertEqual(
            cast("unsigned long", obj),
            Object(self.prog, "unsigned long", value=0xFFFF0000),
        )
        self.assertRaisesRegex(
            TypeError, r"cannot convert 'int \*' to 'int \[2]'", cast, "int [2]", obj
        )

    def test_cast_function(self):
        func = Object(
            self.prog, function_type(void_type(), (), False), address=0xFFFF0000
        )
        self.assertEqual(
            cast("void *", func), Object(self.prog, "void *", value=0xFFFF0000)
        )

    def _test_arithmetic(
        self, op, lhs, rhs, result, integral=True, floating_point=False
    ):
        if integral:
            self.assertEqual(op(self.int(lhs), self.int(rhs)), self.int(result))
            self.assertEqual(op(self.int(lhs), self.long(rhs)), self.long(result))
            self.assertEqual(op(self.long(lhs), self.int(rhs)), self.long(result))
            self.assertEqual(op(self.long(lhs), self.long(rhs)), self.long(result))
            self.assertEqual(op(self.int(lhs), rhs), self.int(result))
            self.assertEqual(op(self.long(lhs), rhs), self.long(result))
            self.assertEqual(op(lhs, self.int(rhs)), self.int(result))
            self.assertEqual(op(lhs, self.long(rhs)), self.long(result))

        if floating_point:
            self.assertEqual(
                op(self.double(lhs), self.double(rhs)), self.double(result)
            )
            self.assertEqual(op(self.double(lhs), self.int(rhs)), self.double(result))
            self.assertEqual(op(self.int(lhs), self.double(rhs)), self.double(result))
            self.assertEqual(op(self.double(lhs), float(rhs)), self.double(result))
            self.assertEqual(op(float(lhs), self.double(rhs)), self.double(result))
            self.assertEqual(op(float(lhs), self.int(rhs)), self.double(result))
            self.assertEqual(op(self.int(lhs), float(rhs)), self.double(result))

    def _test_shift(self, op, lhs, rhs, result):
        self.assertEqual(op(self.int(lhs), self.int(rhs)), self.int(result))
        self.assertEqual(op(self.int(lhs), self.long(rhs)), self.int(result))
        self.assertEqual(op(self.long(lhs), self.int(rhs)), self.long(result))
        self.assertEqual(op(self.long(lhs), self.long(rhs)), self.long(result))
        self.assertEqual(op(self.int(lhs), rhs), self.int(result))
        self.assertEqual(op(self.long(lhs), rhs), self.long(result))
        self.assertEqual(op(lhs, self.int(rhs)), self.int(result))
        self.assertEqual(op(lhs, self.long(rhs)), self.int(result))

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
            self.prog, function_type(void_type(), (), False), address=0xFFFF0000
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
            Object(self.prog, struct_type("foo", None, None), address=0xFFFF0000),
            ptr0,
        )

    def test_add(self):
        self._test_arithmetic(operator.add, 1, 2, 3, floating_point=True)

        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        arr = Object(self.prog, "int [2]", address=0xFFFF0000)
        ptr1 = Object(self.prog, "int *", value=0xFFFF0004)
        self.assertEqual(ptr + self.int(1), ptr1)
        self.assertEqual(self.unsigned_int(1) + ptr, ptr1)
        self.assertEqual(arr + self.int(1), ptr1)
        self.assertEqual(ptr1 + self.int(-1), ptr)
        self.assertEqual(self.int(-1) + ptr1, ptr)

        self.assertEqual(ptr + 1, ptr1)
        self.assertEqual(1 + ptr, ptr1)
        self.assertRaises(TypeError, operator.add, ptr, ptr)
        self.assertRaises(TypeError, operator.add, ptr, 2.0)
        self.assertRaises(TypeError, operator.add, 2.0, ptr)

        void_ptr = Object(self.prog, "void *", value=0xFFFF0000)
        void_ptr1 = Object(self.prog, "void *", value=0xFFFF0001)
        self.assertEqual(void_ptr + self.int(1), void_ptr1)
        self.assertEqual(self.unsigned_int(1) + void_ptr, void_ptr1)
        self.assertEqual(void_ptr + 1, void_ptr1)
        self.assertEqual(1 + void_ptr, void_ptr1)

    def test_sub(self):
        self._test_arithmetic(operator.sub, 4, 2, 2, floating_point=True)

        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        arr = Object(self.prog, "int [2]", address=0xFFFF0004)
        ptr1 = Object(self.prog, "int *", value=0xFFFF0004)
        self.assertEqual(ptr1 - ptr, Object(self.prog, "ptrdiff_t", value=1))
        self.assertEqual(ptr - ptr1, Object(self.prog, "ptrdiff_t", value=-1))
        self.assertEqual(ptr - self.int(0), ptr)
        self.assertEqual(ptr1 - self.int(1), ptr)
        self.assertEqual(arr - self.int(1), ptr)
        self.assertRaises(TypeError, operator.sub, self.int(1), ptr)
        self.assertRaises(TypeError, operator.sub, ptr, 1.0)

        void_ptr = Object(self.prog, "void *", value=0xFFFF0000)
        void_ptr1 = Object(self.prog, "void *", value=0xFFFF0001)
        self.assertEqual(void_ptr1 - void_ptr, Object(self.prog, "ptrdiff_t", value=1))
        self.assertEqual(void_ptr - void_ptr1, Object(self.prog, "ptrdiff_t", value=-1))
        self.assertEqual(void_ptr - self.int(0), void_ptr)
        self.assertEqual(void_ptr1 - self.int(1), void_ptr)

    def test_mul(self):
        self._test_arithmetic(operator.mul, 2, 3, 6, floating_point=True)
        self._test_pointer_type_errors(operator.mul)

        # Negative numbers.
        self.assertEqual(self.int(2) * self.int(-3), self.int(-6))
        self.assertEqual(self.int(-2) * self.int(3), self.int(-6))
        self.assertEqual(self.int(-2) * self.int(-3), self.int(6))

        # Integer overflow.
        self.assertEqual(self.int(0x8000) * self.int(0x10000), self.int(-(2 ** 31)))

        self.assertEqual(
            self.unsigned_int(0x8000) * self.int(0x10000), self.unsigned_int(2 ** 31)
        )

        self.assertEqual(
            self.unsigned_int(0xFFFFFFFF) * self.unsigned_int(0xFFFFFFFF),
            self.unsigned_int(1),
        )

        self.assertEqual(
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
        self.assertEqual(self.bool(True) << self.bool(True), self.int(2))
        self.assertEqual(self.int(1) << self.int(32), self.int(0))

    def test_rshift(self):
        self._test_shift(operator.rshift, 16, 3, 2)
        self.assertEqual(self.int(-2) >> self.int(1), self.int(-1))
        self.assertEqual(self.int(1) >> self.int(32), self.int(0))
        self.assertEqual(self.int(-1) >> self.int(32), self.int(-1))

    def test_and(self):
        self._test_arithmetic(operator.and_, 1, 3, 1)
        self.assertEqual(self.int(-1) & self.int(2 ** 31), self.int(2 ** 31))
        self._test_pointer_type_errors(operator.and_)
        self._test_floating_type_errors(operator.and_)

    def test_xor(self):
        self._test_arithmetic(operator.xor, 1, 3, 2)
        self.assertEqual(self.int(-1) ^ self.int(-(2 ** 31)), self.int(2 ** 31 - 1))
        self._test_pointer_type_errors(operator.xor)
        self._test_floating_type_errors(operator.xor)

    def test_or(self):
        self._test_arithmetic(operator.or_, 1, 3, 3)
        self.assertEqual(self.int(-(2 ** 31)) | self.int(2 ** 31 - 1), self.int(-1))
        self._test_pointer_type_errors(operator.or_)
        self._test_floating_type_errors(operator.or_)

    def test_pos(self):
        # TestCIntegerPromotion covers the other cases.
        self.assertRaisesRegex(
            TypeError,
            r"invalid operand to unary \+",
            operator.pos,
            Object(self.prog, "int *", value=0),
        )

    def test_neg(self):
        self.assertEqual(-Object(self.prog, "unsigned char", value=1), self.int(-1))
        self.assertEqual(-self.int(-1), self.int(1))
        self.assertEqual(-self.unsigned_int(1), self.unsigned_int(0xFFFFFFFF))
        self.assertEqual(
            -Object(self.prog, "long", value=-0x8000000000000000),
            Object(self.prog, "long", value=-0x8000000000000000),
        )
        self.assertEqual(-self.double(2.0), self.double(-2.0))
        self.assertRaisesRegex(
            TypeError,
            "invalid operand to unary -",
            operator.neg,
            Object(self.prog, "int *", value=0),
        )

    def test_not(self):
        self.assertEqual(~self.int(1), self.int(-2))
        self.assertEqual(
            ~Object(self.prog, "unsigned long long", value=-1),
            Object(self.prog, "unsigned long long", value=0),
        )
        self.assertEqual(~Object(self.prog, "unsigned char", value=255), self.int(-256))
        for type_ in ["int *", "double"]:
            self.assertRaisesRegex(
                TypeError,
                "invalid operand to unary ~",
                operator.invert,
                Object(self.prog, type_, value=0),
            )

    def test_container_of(self):
        obj = Object(self.prog, "int *", value=0xFFFF000C)
        container_of(obj, point_type, "x")
        self.assertEqual(
            container_of(obj, point_type, "x"),
            Object(self.prog, pointer_type(8, point_type), value=0xFFFF000C),
        )
        self.assertEqual(
            container_of(obj, point_type, "y"),
            Object(self.prog, pointer_type(8, point_type), value=0xFFFF0008),
        )

        self.assertEqual(
            container_of(obj, line_segment_type, "a.x"),
            Object(self.prog, pointer_type(8, line_segment_type), value=0xFFFF000C),
        )
        self.assertEqual(
            container_of(obj, line_segment_type, "b.x"),
            Object(self.prog, pointer_type(8, line_segment_type), value=0xFFFF0004),
        )

        polygon_type = struct_type(
            "polygon", 0, (TypeMember(array_type(None, point_type), "points"),)
        )
        self.assertEqual(
            container_of(obj, polygon_type, "points[3].x"),
            Object(self.prog, pointer_type(8, polygon_type), value=0xFFFEFFF4),
        )

        small_point_type = struct_type(
            "small_point",
            1,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True), "y", 4, 4),
            ),
        )
        self.assertRaisesRegex(
            ValueError,
            r"container_of\(\) member is not byte-aligned",
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
            point_type,
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

        type_ = struct_type(
            "foo",
            16,
            (
                TypeMember(array_type(8, int_type("int", 4, True)), "arr"),
                TypeMember(point_type, "point", 256),
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


class TestCPretty(ObjectTestCase):
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
                typedef_type("uint8_t", self.prog.type("unsigned char")),
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
        type_ = typedef_type("INT", int_type("int", 4, True))
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(INT)99")

        type_ = typedef_type("INT", int_type("int", 4, True), Qualifiers.CONST)
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(const INT)99")

        type_ = typedef_type("CINT", int_type("int", 4, True, Qualifiers.CONST))
        self.assertEqual(str(Object(self.prog, type_, value=99)), "(CINT)99")

    def test_struct(self):
        segment = (
            (99).to_bytes(4, "little")
            + (-1).to_bytes(4, "little", signed=True)
            + (12345).to_bytes(4, "little", signed=True)
            + (0).to_bytes(4, "little", signed=True)
        )
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[point_type],
        )

        obj = Object(prog, "struct point", address=0xFFFF0000)
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

        type_ = struct_type(
            "foo",
            16,
            (
                TypeMember(point_type, "point"),
                TypeMember(
                    struct_type(
                        None,
                        8,
                        (
                            TypeMember(int_type("int", 4, True), "bar"),
                            TypeMember(int_type("int", 4, True), "baz", 32),
                        ),
                    ),
                    None,
                    64,
                ),
            ),
        )
        obj = Object(prog, type_, address=0xFFFF0000)
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

        segment = (
            (99).to_bytes(8, "little")
            + (-1).to_bytes(8, "little", signed=True)
            + (12345).to_bytes(8, "little", signed=True)
            + (0).to_bytes(8, "little", signed=True)
        )
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        type_ = struct_type(
            "foo",
            32,
            (
                TypeMember(
                    struct_type(
                        "long_point",
                        16,
                        (
                            TypeMember(int_type("long", 8, True), "x"),
                            TypeMember(int_type("long", 8, True), "y", 64),
                        ),
                    ),
                    "point",
                ),
                TypeMember(int_type("long", 8, True), "bar", 128),
                TypeMember(int_type("long", 8, True), "baz", 192),
            ),
        )
        obj = Object(prog, type_, address=0xFFFF0000)
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

        type_ = struct_type("foo", 0, ())
        self.assertEqual(str(Object(prog, type_, address=0)), "(struct foo){}")

        obj = Object(prog, point_type, value={"x": 1})
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
        obj = Object(prog, point_type, value={"y": 1})
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
        segment = b"\x07\x10\x5e\x5f\x1f\0\0\0"
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        type_ = struct_type(
            "bits",
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True, Qualifiers.CONST), "y", 4, 28),
                TypeMember(int_type("int", 4, True), "z", 32, 5),
            ),
        )

        obj = Object(prog, type_, address=0xFFFF0000)
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
        segment = b"\0\0\x80?"
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[option_type],
        )
        self.assertEqual(
            str(Object(prog, "union option", address=0xFFFF0000)),
            """\
(union option){
	.i = (int)1065353216,
	.f = (float)1.0,
}""",
        )

    def test_enum(self):
        self.assertEqual(str(Object(self.prog, color_type, value=0)), "(enum color)RED")
        self.assertEqual(
            str(Object(self.prog, color_type, value=1)), "(enum color)GREEN"
        )
        self.assertEqual(str(Object(self.prog, color_type, value=4)), "(enum color)4")
        obj = Object(self.prog, enum_type("color"), address=0)
        self.assertRaisesRegex(TypeError, "cannot format incomplete enum", str, obj)

    def test_pointer(self):
        prog = mock_program(
            segments=[
                MockMemorySegment((99).to_bytes(4, "little"), virt_addr=0xFFFF0000),
            ]
        )
        obj = Object(prog, "int *", value=0xFFFF0000)
        self.assertEqual(str(obj), "*(int *)0xffff0000 = 99")
        self.assertEqual(obj.format_(dereference=False), "(int *)0xffff0000")
        self.assertEqual(
            str(Object(prog, "int *", value=0x7FFFFFFF)), "(int *)0x7fffffff"
        )

    def test_void_pointer(self):
        prog = mock_program(
            segments=[
                MockMemorySegment((99).to_bytes(8, "little"), virt_addr=0xFFFF0000),
            ]
        )
        self.assertEqual(
            str(Object(prog, "void *", value=0xFFFF0000)), "(void *)0xffff0000"
        )

    def test_pointer_typedef(self):
        prog = mock_program(
            segments=[
                MockMemorySegment(
                    (0xFFFF00F0).to_bytes(8, "little"), virt_addr=0xFFFF0000
                ),
            ]
        )
        type_ = typedef_type("HANDLE", pointer_type(8, pointer_type(8, void_type())))
        self.assertEqual(
            str(Object(prog, type_, value=0xFFFF0000)),
            "*(HANDLE)0xffff0000 = 0xffff00f0",
        )

    # TODO: test symbolize.

    def test_c_string(self):
        prog = mock_program(
            segments=[
                MockMemorySegment(b"hello\0", virt_addr=0xFFFF0000),
                MockMemorySegment(b"unterminated", virt_addr=0xFFFF0010),
                MockMemorySegment(b'"escape\tme\\\0', virt_addr=0xFFFF0020),
            ]
        )

        obj = Object(prog, "char *", value=0xFFFF0000)
        self.assertEqual(str(obj), '(char *)0xffff0000 = "hello"')
        self.assertEqual(obj.format_(string=False), "*(char *)0xffff0000 = 104")
        self.assertEqual(str(Object(prog, "char *", value=0x0)), "(char *)0x0")
        self.assertEqual(
            str(Object(prog, "char *", value=0xFFFF0010)), "(char *)0xffff0010"
        )
        self.assertEqual(
            str(Object(prog, "char *", value=0xFFFF0020)),
            r'(char *)0xffff0020 = "\"escape\tme\\"',
        )

    def test_basic_array(self):
        segment = bytearray()
        for i in range(5):
            segment.extend(i.to_bytes(4, "little"))
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )
        obj = Object(prog, "int [5]", address=0xFFFF0000)

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
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )
        obj = Object(prog, "int [2][5]", address=0xFFFF0000)

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
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        type_ = struct_type(
            None, 20, (TypeMember(array_type(5, int_type("int", 4, True)), "arr"),)
        )
        obj = Object(prog, type_, address=0xFFFF0000)

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
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[point_type],
        )

        obj = Object(prog, "struct point [2]", address=0xFFFF0000)
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
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[point_type, struct_type("empty", 0, ()),],
        )

        obj = Object(prog, "int [2]", address=0xFFFF0000)
        self.assertEqual(str(obj), "(int [2]){}")
        self.assertEqual(obj.format_(implicit_elements=True), "(int [2]){ 0, 0 }")
        segment[:4] = (99).to_bytes(4, "little")
        self.assertEqual(str(obj), "(int [2]){ 99 }")
        segment[:4] = (0).to_bytes(4, "little")
        segment[4:8] = (99).to_bytes(4, "little")
        self.assertEqual(str(obj), "(int [2]){ 0, 99 }")

        obj = Object(prog, "struct point [2]", address=0xFFFF0000)
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

        obj = Object(prog, "struct empty [2]", address=0)
        self.assertEqual(str(obj), "(struct empty [2]){}")

    def test_char_array(self):
        segment = bytearray(16)
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        obj = Object(prog, "char [4]", address=0xFFFF0000)
        segment[:16] = b"hello, world\0\0\0\0"
        self.assertEqual(str(obj), '(char [4])"hell"')
        self.assertEqual(obj.format_(string=False), "(char [4]){ 104, 101, 108, 108 }")
        self.assertEqual(str(obj.read_()), str(obj))
        segment[2] = 0
        self.assertEqual(str(obj), '(char [4])"he"')
        self.assertEqual(str(obj.read_()), str(obj))

        self.assertEqual(
            str(Object(prog, "char [0]", address=0xFFFF0000)), "(char [0]){}"
        )
        self.assertEqual(
            str(Object(prog, "char []", address=0xFFFF0000)), "(char []){}"
        )

    def test_function(self):
        obj = Object(
            self.prog, function_type(void_type(), (), False), address=0xFFFF0000
        )
        self.assertEqual(str(obj), "(void (void))0xffff0000")


class TestGenericOperators(ObjectTestCase):
    def setUp(self):
        super().setUp()
        self.prog = mock_program(
            segments=[
                MockMemorySegment(
                    b"".join(i.to_bytes(4, "little") for i in range(4)),
                    virt_addr=0xFFFF0000,
                ),
            ]
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
        self.assertEqual(
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
                self.assertEqual(
                    obj[i], Object(self.prog, "int", address=0xFFFF0000 + 4 * i)
                )
                if i < 4:
                    self.assertEqual(obj[i].read_(), Object(self.prog, "int", value=i))
                else:
                    self.assertRaises(FaultError, obj[i].read_)

        obj = arr.read_()
        for i in range(4):
            self.assertEqual(obj[i], Object(self.prog, "int", value=i))
        self.assertRaisesRegex(OutOfBoundsError, "out of bounds", obj.__getitem__, 4)
        obj = Object(self.prog, "int", value=0)
        self.assertRaises(TypeError, obj.__getitem__, 0)

    def test_cast_primitive_value(self):
        obj = Object(self.prog, "long", value=2 ** 32 + 1)
        self.assertEqual(cast("int", obj), Object(self.prog, "int", value=1))
        self.assertEqual(cast("int", obj.read_()), Object(self.prog, "int", value=1))
        self.assertEqual(
            cast("const int", Object(self.prog, "int", value=1)),
            Object(self.prog, "const int", value=1),
        )
        self.assertRaisesRegex(
            TypeError,
            "cannot convert 'int' to 'struct point'",
            cast,
            point_type,
            Object(self.prog, "int", value=1),
        )

    def test_cast_compound_value(self):
        obj = Object(self.prog, point_type, address=0xFFFF0000).read_()
        self.assertEqual(cast(point_type, obj), obj)
        const_point_type = point_type.qualified(Qualifiers.CONST)
        self.assertEqual(
            cast(const_point_type, obj),
            Object(self.prog, const_point_type, address=0xFFFF0000).read_(),
        )
        self.assertRaisesRegex(
            TypeError,
            "cannot convert 'struct point' to 'enum color'",
            cast,
            color_type,
            obj,
        )

    def test_cast_invalid(self):
        obj = Object(self.prog, "int", value=1)
        self.assertRaisesRegex(TypeError, "cannot cast to void type", cast, "void", obj)

    def test_reinterpret_reference(self):
        obj = Object(self.prog, "int", address=0xFFFF0000)
        self.assertEqual(reinterpret("int", obj), obj)
        self.assertEqual(
            reinterpret("int", obj, byteorder="big"),
            Object(self.prog, "int", address=0xFFFF0000, byteorder="big"),
        )

        obj = Object(self.prog, "int []", address=0xFFFF0000)
        self.assertEqual(
            reinterpret("int [4]", obj),
            Object(self.prog, "int [4]", address=0xFFFF0000),
        )

    def test_reinterpret_value(self):
        segment = (1).to_bytes(4, "little") + (2).to_bytes(4, "little")
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),],
            types=[
                point_type,
                struct_type(
                    "foo", 8, (TypeMember(int_type("long", 8, True), "counter"),)
                ),
            ],
        )
        obj = Object(prog, "struct point", address=0xFFFF0000).read_()
        self.assertEqual(
            reinterpret("struct foo", obj),
            Object(prog, "struct foo", address=0xFFFF0000).read_(),
        )
        self.assertEqual(
            reinterpret(obj.type_, obj, byteorder="big"),
            Object(prog, "struct point", address=0xFFFF0000, byteorder="big").read_(),
        )
        self.assertEqual(reinterpret("int", obj), Object(prog, "int", value=1))

    def test_member(self):
        reference = Object(self.prog, point_type, address=0xFFFF0000)
        unnamed_reference = Object(
            self.prog,
            struct_type(
                "point",
                8,
                (TypeMember(struct_type(None, 8, point_type.members), None),),
            ),
            address=0xFFFF0000,
        )
        ptr = Object(self.prog, pointer_type(8, point_type), value=0xFFFF0000)
        for obj in [reference, unnamed_reference, ptr]:
            self.assertEqual(
                obj.member_("x"), Object(self.prog, "int", address=0xFFFF0000)
            )
            self.assertEqual(obj.member_("x"), obj.x)
            self.assertEqual(
                obj.member_("y"), Object(self.prog, "int", address=0xFFFF0004)
            )
            self.assertEqual(obj.member_("y"), obj.y)

            self.assertRaisesRegex(
                LookupError, "'struct point' has no member 'z'", obj.member_, "z"
            )
            self.assertRaisesRegex(
                AttributeError, "'struct point' has no member 'z'", getattr, obj, "z"
            )

        obj = reference.read_()
        self.assertEqual(obj.x, Object(self.prog, "int", value=0))
        self.assertEqual(obj.y, Object(self.prog, "int", value=1))

        obj = Object(self.prog, "int", value=1)
        self.assertRaisesRegex(
            TypeError, "'int' is not a structure, union, or class", obj.member_, "x"
        )
        self.assertRaisesRegex(AttributeError, "no attribute", getattr, obj, "x")

    def test_bit_field_member(self):
        segment = b"\x07\x10\x5e\x5f\x1f\0\0\0"
        prog = mock_program(
            segments=[MockMemorySegment(segment, virt_addr=0xFFFF0000),]
        )

        type_ = struct_type(
            "bits",
            8,
            (
                TypeMember(int_type("int", 4, True), "x", 0, 4),
                TypeMember(int_type("int", 4, True, Qualifiers.CONST), "y", 4, 28),
                TypeMember(int_type("int", 4, True), "z", 32, 5),
            ),
        )

        obj = Object(prog, type_, address=0xFFFF0000)
        self.assertEqual(
            obj.x,
            Object(
                prog, int_type("int", 4, True), address=0xFFFF0000, bit_field_size=4
            ),
        )
        self.assertEqual(
            obj.y,
            Object(
                prog,
                int_type("int", 4, True, Qualifiers.CONST),
                address=0xFFFF0000,
                bit_field_size=28,
                bit_offset=4,
            ),
        )
        self.assertEqual(
            obj.z,
            Object(
                prog, int_type("int", 4, True), address=0xFFFF0004, bit_field_size=5
            ),
        )

    def test_member_out_of_bounds(self):
        obj = Object(
            self.prog, struct_type("foo", 4, point_type.members), address=0xFFFF0000
        ).read_()
        self.assertRaisesRegex(OutOfBoundsError, "out of bounds", getattr, obj, "y")

    def test_string(self):
        prog = mock_program(
            segments=[
                MockMemorySegment(
                    b"\x00\x00\xff\xff\x00\x00\x00\x00", virt_addr=0xFFFEFFF8
                ),
                MockMemorySegment(b"hello\0world\0", virt_addr=0xFFFF0000),
            ]
        )
        strings = [
            (Object(prog, "char *", address=0xFFFEFFF8), b"hello"),
            (Object(prog, "char [2]", address=0xFFFF0000), b"he"),
            (Object(prog, "char [8]", address=0xFFFF0000), b"hello"),
        ]
        for obj, expected in strings:
            with self.subTest(obj=obj):
                self.assertEqual(obj.string_(), expected)
                self.assertEqual(obj.read_().string_(), expected)

        strings = [
            Object(prog, "char []", address=0xFFFF0000),
            Object(prog, "int []", address=0xFFFF0000),
            Object(prog, "int [2]", address=0xFFFF0000),
            Object(prog, "int *", value=0xFFFF0000),
        ]
        for obj in strings:
            self.assertEqual(obj.string_(), b"hello")

        self.assertRaisesRegex(
            TypeError,
            "must be an array or pointer",
            Object(prog, "int", value=1).string_,
        )


class TestSpecialMethods(ObjectTestCase):
    def test_dir(self):
        obj = Object(self.prog, "int", value=0)
        self.assertEqual(dir(obj), sorted(object.__dir__(obj)))

        obj = Object(self.prog, point_type, address=0xFFFF0000)
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
        self.assertEqual(
            round(Object(self.prog, "int", value=1), 2),
            Object(self.prog, "int", value=1),
        )
        self.assertEqual(
            round(Object(self.prog, "double", value=0.123), 2),
            Object(self.prog, "double", value=0.12),
        )

    def test_iter(self):
        obj = Object(self.prog, "int [4]", value=[0, 1, 2, 3])
        for i, element in enumerate(obj):
            self.assertEqual(element, Object(self.prog, "int", value=i))
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
