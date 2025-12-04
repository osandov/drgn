# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import math
import operator
import struct

from drgn import (
    AbsenceReason,
    FaultError,
    NoDefaultProgramError,
    Object,
    ObjectAbsentError,
    OutOfBoundsError,
    Qualifiers,
    TypeMember,
    cast,
    reinterpret,
    sizeof,
)
from tests import (
    MockMemorySegment,
    MockObject,
    MockProgramTestCase,
    assertReprPrettyEqualsStr,
    mock_program,
    with_default_prog,
)


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

    def test_address_value_absence_reason_nand(self):
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
        self.assertRaisesRegex(
            ValueError,
            "object cannot have address and absence reason",
            Object,
            self.prog,
            "int",
            address=0,
            absence_reason=AbsenceReason.OTHER,
        )
        self.assertRaisesRegex(
            ValueError,
            "object cannot have value and absence reason",
            Object,
            self.prog,
            "int",
            value=0,
            absence_reason=AbsenceReason.OTHER,
        )
        self.assertRaisesRegex(
            ValueError,
            "object cannot have address, value, and absence reason",
            Object,
            self.prog,
            "int",
            value=0,
            address=0,
            absence_reason=AbsenceReason.OTHER,
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
            self.prog.int_type("BIGGEST", 1024**3, True),
        )

    def test_float_size(self):
        self.assertRaisesRegex(
            ValueError,
            "unsupported floating-point bit size",
            Object,
            self.prog,
            self.prog.float_type("ZERO", 0),
        )
        self.assertRaisesRegex(
            ValueError,
            "unsupported floating-point bit size",
            Object,
            self.prog,
            self.prog.float_type("BIGGEST", 32 + 1),
        )


def _int_bits_cases(prog):
    for signed in (True, False):
        for byteorder in ("little", "big"):
            for bit_size in range(1, 129):
                if bit_size <= 8:
                    size = 1
                else:
                    size = 1 << ((bit_size - 1).bit_length() - 3)
                type = prog.int_type(
                    "" if signed else "u" + f"int{size}", size, signed, byteorder
                )
                if signed:
                    values = (
                        0xF8935CF44C45202748DE66B49BA0CBAC % (1 << (bit_size - 1)),
                        ~0xF8935CF44C45202748DE66B49BA0CBAC % (1 << (bit_size - 1)),
                        -0xC256D5AAFFDC3179A6AC84E7154A215D % -(1 << (bit_size - 1)),
                        ~-0xC256D5AAFFDC3179A6AC84E7154A215D % -(1 << (bit_size - 1)),
                    )
                else:
                    values = (
                        0xF8935CF44C45202748DE66B49BA0CBAC % (1 << bit_size),
                        ~0xF8935CF44C45202748DE66B49BA0CBAC % (1 << bit_size),
                    )
                for value in values:
                    # value_bytes is the value converted to bytes.
                    if byteorder == "little":
                        value_bytes = (value & ((1 << bit_size) - 1)).to_bytes(
                            (bit_size + 7) // 8, byteorder
                        )
                    else:
                        value_bytes = (value << (-bit_size % 8)).to_bytes(
                            (bit_size + 7) // 8, byteorder, signed=signed
                        )
                    for bit_offset in range(8):
                        # source_bytes is a buffer containing the value at the
                        # given bit offset, with extra bits that should be
                        # ignored.
                        if byteorder == "little":
                            source_bytes = bytearray(
                                (value << bit_offset).to_bytes(
                                    (bit_offset + bit_size + 7) // 8,
                                    byteorder,
                                    signed=signed,
                                )
                            )
                            source_bytes[0] |= (1 << bit_offset) - 1
                            if (bit_offset + bit_size) % 8 != 0:
                                source_bytes[-1] ^= (
                                    0xFF << ((bit_offset + bit_size) % 8)
                                ) & 0xFF
                        else:
                            source_bytes = bytearray(
                                (value << (-(bit_offset + bit_size) % 8)).to_bytes(
                                    (bit_offset + bit_size + 7) // 8,
                                    byteorder,
                                    signed=signed,
                                )
                            )
                            source_bytes[0] ^= (0xFF00 >> bit_offset) & 0xFF
                            if (bit_offset + bit_size) % 8 != 0:
                                source_bytes[-1] |= (
                                    1 << (-(bit_offset + bit_size) % 8)
                                ) - 1
                        yield signed, byteorder, bit_size, type, bit_offset, value, value_bytes, source_bytes


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

    def test_signed_big(self):
        buffer = (-4).to_bytes(16, "little", signed=True)
        self.add_memory_segment(buffer, virt_addr=0xFFFF0000)
        obj = Object(
            self.prog,
            self.prog.int_type("__int128", 16, True),
            address=0xFFFF0000,
        )
        self.assertIs(obj.prog_, self.prog)
        self.assertFalse(obj.absent_)
        self.assertEqual(obj.address_, 0xFFFF0000)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.type_.size, 16)
        self.assertEqual(obj.value_(), -4)
        self.assertEqual(obj.to_bytes_(), buffer)
        self.assertEqual(repr(obj), "Object(prog, '__int128', address=0xffff0000)")

        self.assertIdentical(
            obj.read_(),
            Object(self.prog, self.prog.int_type("__int128", 16, True), value=-4),
        )

    def test_unsigned_big(self):
        buffer = (1000).to_bytes(16, "little")
        self.add_memory_segment(buffer, virt_addr=0xFFFF0000)
        obj = Object(
            self.prog,
            self.prog.int_type("unsigned __int128", 16, False),
            address=0xFFFF0000,
        )
        self.assertIs(obj.prog_, self.prog)
        self.assertFalse(obj.absent_)
        self.assertEqual(obj.address_, 0xFFFF0000)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.type_.size, 16)
        self.assertEqual(obj.value_(), 1000)
        self.assertEqual(obj.to_bytes_(), buffer)
        self.assertEqual(
            repr(obj), "Object(prog, 'unsigned __int128', address=0xffff0000)"
        )

        self.assertIdentical(
            obj.read_(),
            Object(
                self.prog,
                self.prog.int_type("unsigned __int128", 16, False),
                value=1000,
            ),
        )

    def test_int_bits(self):
        buffer = bytearray(17)
        self.add_memory_segment(buffer, virt_addr=0xFFFF0000)
        for (
            signed,
            byteorder,
            bit_size,
            type,
            bit_offset,
            value,
            value_bytes,
            source_bytes,
        ) in _int_bits_cases(self.prog):
            with self.subTest(
                signed=signed,
                byteorder=byteorder,
                bit_size=bit_size,
                bit_offset=bit_offset,
                value=value,
            ):
                buffer[: len(source_bytes)] = source_bytes
                obj = Object(
                    self.prog,
                    type,
                    address=0xFFFF0000,
                    bit_offset=bit_offset,
                    bit_field_size=bit_size,
                )
                self.assertEqual(obj.value_(), value)
                self.assertEqual(obj.to_bytes_(), value_bytes)

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

    def test_bit_field_of_big_int(self):
        buffer = (1000).to_bytes(4, "little")
        self.add_memory_segment(buffer, virt_addr=0xFFFF0000)
        obj = Object(
            self.prog,
            self.prog.int_type("unsigned __int128", 16, False),
            address=0xFFFF0000,
            bit_field_size=32,
        )
        self.assertIs(obj.prog_, self.prog)
        self.assertFalse(obj.absent_)
        self.assertEqual(obj.address_, 0xFFFF0000)
        self.assertEqual(obj.bit_offset_, 0)
        self.assertEqual(obj.bit_field_size_, 32)
        self.assertEqual(obj.value_(), 1000)
        self.assertIdentical(
            obj.read_(),
            Object(
                self.prog,
                self.prog.int_type("unsigned __int128", 16, False),
                bit_field_size=32,
                value=1000,
            ),
        )
        self.assertEqual(obj.to_bytes_(), buffer)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned __int128', address=0xffff0000, bit_field_size=32)",
        )

    def test_non_standard_float(self):
        for size in (2, 10, 16, 32):
            buffer = (1000).to_bytes(size, "little")
            self.add_memory_segment(buffer, virt_addr=0xFFFF0000)
            obj = Object(
                self.prog,
                self.prog.float_type("CUSTOM_FLOAT", size),
                address=0xFFFF0000,
            )
            self.assertIs(obj.prog_, self.prog)
            self.assertFalse(obj.absent_)
            self.assertEqual(obj.address_, 0xFFFF0000)
            self.assertEqual(obj.bit_offset_, 0)
            self.assertIsNone(obj.bit_field_size_)
            self.assertEqual(obj.type_.size, size)
            self.assertRaisesRegex(
                NotImplementedError,
                "float values which are not 32 or 64 bits are not yet supported",
                obj.value_,
            )
            self.assertEqual(obj.to_bytes_(), buffer)
            self.assertEqual(
                repr(obj), "Object(prog, 'CUSTOM_FLOAT', address=0xffff0000)"
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
        self.assertIsNone(obj.absence_reason_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), -4)
        self.assertEqual(repr(obj), "Object(prog, 'int', value=-4)")

        self.assertIdentical(obj.read_(), obj)

        self.assertIdentical(Object(self.prog, "int", value=2**32 - 4), obj)
        self.assertIdentical(Object(self.prog, "int", value=2**64 - 4), obj)
        self.assertIdentical(Object(self.prog, "int", value=2**128 - 4), obj)
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

    def test_unsigned(self):
        obj = Object(self.prog, "unsigned int", value=2**32 - 1)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("unsigned int"))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 2**32 - 1)
        self.assertEqual(repr(obj), "Object(prog, 'unsigned int', value=4294967295)")

        self.assertIdentical(Object(self.prog, "unsigned int", value=-1), obj)
        self.assertIdentical(Object(self.prog, "unsigned int", value=2**64 - 1), obj)
        self.assertIdentical(Object(self.prog, "unsigned int", value=2**65 - 1), obj)
        self.assertIdentical(
            Object(self.prog, "unsigned int", value=2**32 - 1 + 0.9), obj
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

    def _test_big_int_operators(self, type):
        big_obj = Object(self.prog, type, 1000)
        obj = Object(self.prog, "int", 0)
        for op in (
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
        ):
            self.assertRaises(NotImplementedError, op, big_obj, obj)
            self.assertRaises(NotImplementedError, op, obj, big_obj)

        for op in (
            operator.inv,
            operator.neg,
            operator.pos,
        ):
            self.assertRaises(NotImplementedError, op, big_obj)

        self.assertFalse(not big_obj)
        self.assertTrue(bool(big_obj))
        for op in (
            operator.index,
            round,
            math.trunc,
            math.floor,
            math.ceil,
        ):
            self.assertEqual(op(big_obj), 1000)

    def test_signed_big(self):
        type = self.prog.int_type("__int128", 16, True)
        obj = Object(self.prog, type, -4)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.int_type("__int128", 16, True))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), -4)
        self.assertEqual(repr(obj), "Object(prog, '__int128', value=-4)")

        self.assertIdentical(Object(self.prog, type, value=2**128 - 4), obj)
        self.assertIdentical(Object(self.prog, type, value=-4.6), obj)

        self.assertIdentical(
            Object(self.prog, type, value=2**128 + 4),
            Object(self.prog, type, value=4),
        )

        self.assertRaisesRegex(
            TypeError,
            "'__int128' value must be number",
            Object,
            self.prog,
            type,
            value=b"asdf",
        )

        self._test_big_int_operators(type)

    def test_unsigned_big(self):
        type = self.prog.int_type("unsigned __int128", 16, False)
        obj = Object(self.prog, type, 2**128 - 1)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(
            obj.type_, self.prog.int_type("unsigned __int128", 16, False)
        )
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(obj.value_(), 2**128 - 1)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned __int128', value=340282366920938463463374607431768211455)",
        )

        self.assertIdentical(Object(self.prog, type, value=-1), obj)
        self.assertIdentical(Object(self.prog, type, value=2**128 - 1), obj)
        self.assertIdentical(Object(self.prog, type, value=2**129 - 1), obj)
        self.assertIdentical(
            Object(self.prog, type, value=0.1), Object(self.prog, type, value=0)
        )

        self.assertRaisesRegex(
            TypeError,
            "'unsigned __int128' value must be number",
            Object,
            self.prog,
            type,
            value="foo",
        )

        self._test_big_int_operators(type)

    def test_int_bits(self):
        for (
            signed,
            byteorder,
            bit_size,
            type,
            bit_offset,
            value,
            value_bytes,
            source_bytes,
        ) in _int_bits_cases(self.prog):
            with self.subTest(
                signed=signed,
                byteorder=byteorder,
                bit_size=bit_size,
                bit_offset=bit_offset,
                value=value,
            ):
                obj = Object(self.prog, type, value, bit_field_size=bit_size)
                self.assertEqual(obj.value_(), value)
                self.assertEqual(obj.to_bytes_(), value_bytes)
                self.assertIdentical(
                    Object.from_bytes_(
                        self.prog,
                        obj.type_,
                        source_bytes,
                        bit_offset=bit_offset,
                        bit_field_size=bit_size,
                    ),
                    obj,
                )

    def test_float(self):
        obj = Object(self.prog, "double", value=3.14)
        self.assertIs(obj.prog_, self.prog)
        self.assertIdentical(obj.type_, self.prog.type("double"))
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
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

    def test_compound_float(self):
        for byteorder in ("little", "big"):
            for type in (
                self.prog.float_type("double", 8, byteorder),
                self.prog.float_type("float", 4, byteorder),
            ):
                with self.subTest(byteorder=byteorder, type=type.name):
                    obj = Object(
                        self.prog,
                        self.prog.struct_type(
                            None,
                            type.size * 2,
                            (
                                TypeMember(type, "a"),
                                TypeMember(type, "b", type.size * 8),
                            ),
                        ),
                        value={"a": 1234, "b": -3.125},
                    )
                    self.assertEqual(obj.a.value_(), 1234.0)
                    self.assertEqual(obj.b.value_(), -3.125)

    def test_compound_bit_fields(self):
        a = 0xF8935CF44C45202748DE66B49BA0CBAC
        b = -0xC256D5AAFFDC3179A6AC84E7154A215D
        for signed in (True, False):
            if signed:

                def truncate(x, bit_size):
                    sign = 1 << (bit_size - 1)
                    return (x & (sign - 1)) - (x & sign)

            else:

                def truncate(x, bit_size):
                    return x & ((1 << bit_size) - 1)

            for byteorder in ("little", "big"):
                for bit_size in range(1, 128):
                    with self.subTest(
                        signed=signed, byteorder=byteorder, bit_size=bit_size
                    ):
                        type = self.prog.int_type(
                            ("" if signed else "unsigned ") + "__int128", 16, signed
                        )
                        obj = Object(
                            self.prog,
                            self.prog.struct_type(
                                None,
                                type.size * 2,
                                (
                                    TypeMember(
                                        Object(
                                            self.prog, type, bit_field_size=bit_size
                                        ),
                                        "a",
                                    ),
                                    TypeMember(
                                        Object(
                                            self.prog,
                                            type,
                                            bit_field_size=128 - bit_size,
                                        ),
                                        "b",
                                        bit_size,
                                    ),
                                ),
                            ),
                            value={"a": a, "b": b},
                        )
                        self.assertEqual(obj.a.value_(), truncate(a, bit_size))
                        self.assertEqual(obj.b.value_(), truncate(b, 128 - bit_size))

    def test_pointer(self):
        obj = Object(self.prog, "int *", value=0xFFFF0000)
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
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
        self.assertIsNone(obj.absence_reason_)
        self.assertIsNone(obj.address_)
        self.assertEqual(obj.value_(), 0xFFFF0000)
        self.assertEqual(repr(obj), "Object(prog, 'INTP', value=0xffff0000)")

    def test_array(self):
        obj = Object(self.prog, "int [2]", value=[1, 2])
        self.assertFalse(obj.absent_)
        self.assertIsNone(obj.absence_reason_)
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

    def test_small_bit_field_of_big_int(self):
        obj = Object(
            self.prog,
            self.prog.int_type("unsigned __int128", 16, False),
            value=1000,
            bit_field_size=32,
        )
        self.assertIsNone(obj.bit_offset_)
        self.assertEqual(obj.bit_field_size_, 32)
        self.assertEqual(obj.value_(), 1000)
        self.assertEqual(
            repr(obj),
            "Object(prog, 'unsigned __int128', value=1000, bit_field_size=32)",
        )

    def test_non_standard_float(self):
        for size in (2, 10, 16, 32):
            type = self.prog.float_type("CUSTOM_FLOAT", size)
            self.assertRaisesRegex(
                NotImplementedError,
                "float values which are not 32 or 64 bits are not yet supported",
                Object,
                self.prog,
                type,
                0,
            )
            self.assertRaisesRegex(
                NotImplementedError,
                "float values which are not 32 or 64 bits are not yet supported",
                Object.from_bytes_,
                self.prog,
                type,
                (0).to_bytes(size, "little"),
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
            self.assertEqual(
                Object(self.prog, "int").absence_reason_, AbsenceReason.OTHER
            )
            self.assertIsNone(obj.address_)
            self.assertIsNone(obj.bit_offset_)
            self.assertIsNone(obj.bit_field_size_)
            self.assertRaises(ObjectAbsentError, obj.value_)
            self.assertEqual(repr(obj), "Object(prog, 'int')")

            self.assertRaises(ObjectAbsentError, obj.read_)

    def test_reason(self):
        obj = Object(self.prog, "int", absence_reason=AbsenceReason.OPTIMIZED_OUT)
        self.assertEqual(obj.absence_reason_, AbsenceReason.OPTIMIZED_OUT)
        self.assertEqual(
            repr(obj), "Object(prog, 'int', absence_reason=AbsenceReason.OPTIMIZED_OUT)"
        )

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

    def test_big_int(self):
        obj = Object(self.prog, self.prog.int_type("BIG", 16, True))
        self.assertIs(obj.prog_, self.prog)
        self.assertEqual(obj.type_.size, 16)
        self.assertIsNone(obj.address_)
        self.assertIsNone(obj.bit_offset_)
        self.assertIsNone(obj.bit_field_size_)
        self.assertEqual(repr(obj), "Object(prog, 'BIG')")

    def test_non_standard_float(self):
        for size in (2, 10, 16, 32):
            obj = Object(self.prog, self.prog.float_type("CUSTOM_FLOAT", size))
            self.assertIs(obj.prog_, self.prog)
            self.assertEqual(obj.type_.size, size)
            self.assertIsNone(obj.address_)
            self.assertIsNone(obj.bit_offset_)
            self.assertIsNone(obj.bit_field_size_)
            self.assertEqual(repr(obj), "Object(prog, 'CUSTOM_FLOAT')")


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

    def test_signed_int_value_to_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertEqual(
                    Object(
                        self.prog, self.prog.int_type("int", 4, True, byteorder), -100
                    ).to_bytes_(),
                    (-100).to_bytes(4, byteorder, signed=True),
                )
                self.assertEqual(
                    Object(
                        self.prog,
                        self.prog.int_type("long", 8, True, byteorder),
                        -(2**32),
                    ).to_bytes_(),
                    (-(2**32)).to_bytes(8, byteorder, signed=True),
                )

    def test_unsigned_int_value_to_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertEqual(
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned int", 4, False, byteorder),
                        2**31,
                    ).to_bytes_(),
                    (2**31).to_bytes(4, byteorder),
                )
                self.assertEqual(
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long", 8, False, byteorder),
                        2**60,
                    ).to_bytes_(),
                    (2**60).to_bytes(8, byteorder),
                )

    def test_float64_value_to_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertEqual(
                    Object(
                        self.prog, self.prog.float_type("double", 8, byteorder), math.e
                    ).to_bytes_(),
                    struct.pack(("<" if byteorder == "little" else ">") + "d", math.e),
                )

    def test_float32_value_to_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertEqual(
                    Object(
                        self.prog, self.prog.float_type("float", 4, byteorder), math.e
                    ).to_bytes_(),
                    struct.pack(("<" if byteorder == "little" else ">") + "f", math.e),
                )

    def test_struct_value_to_bytes(self):
        self.assertEqual(
            Object(self.prog, self.point_type, {"x": 1, "y": 2}).to_bytes_(),
            b"\x01\x00\x00\x00\x02\x00\x00\x00",
        )

    def test_int_reference_to_bytes(self):
        self.add_memory_segment(b"\x78\x56\x34\x12", virt_addr=0xFFFF0000)
        self.assertEqual(
            Object(self.prog, "int", address=0xFFFF0000).to_bytes_(),
            b"\x78\x56\x34\x12",
        )

    def test_int_reference_bit_offset_to_bytes(self):
        self.add_memory_segment(b"\xe0Y\xd1H\x00", virt_addr=0xFFFF0000)
        self.assertEqual(
            Object(self.prog, "int", address=0xFFFF0000, bit_offset=2).to_bytes_(),
            b"\x78\x56\x34\x12",
        )

    def test_int_reference_big_endian_bit_offset_to_bytes(self):
        self.add_memory_segment(b"\x04\x8d\x15\x9e\x00", virt_addr=0xFFFF0000)
        self.assertEqual(
            Object(
                self.prog,
                self.prog.int_type("int", 4, True, "big"),
                address=0xFFFF0000,
                bit_offset=2,
            ).to_bytes_(),
            b"\x12\x34\x56\x78",
        )

    def test_struct_reference_to_bytes(self):
        self.add_memory_segment(
            b"\x01\x00\x00\x00\x02\x00\x00\x00", virt_addr=0xFFFF0000
        )
        self.assertEqual(
            Object(self.prog, self.point_type, address=0xFFFF0000).to_bytes_(),
            b"\x01\x00\x00\x00\x02\x00\x00\x00",
        )

    def test_int_from_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                type_ = self.prog.int_type("int", 4, True, byteorder)
                self.assertIdentical(
                    Object.from_bytes_(
                        self.prog, type_, (0x12345678).to_bytes(4, byteorder)
                    ),
                    Object(self.prog, type_, 0x12345678),
                )

    def test_int_from_bytes_bit_offset(self):
        self.assertIdentical(
            Object.from_bytes_(self.prog, "int", b"\xe0Y\xd1H\x00", bit_offset=2),
            Object(self.prog, "int", 0x12345678),
        )

    def test_int_from_bytes_big_endian_bit_offset(self):
        self.assertIdentical(
            Object.from_bytes_(
                self.prog,
                self.prog.int_type("int", 4, True, "big"),
                b"\x04\x8d\x15\x9e\x00",
                bit_offset=2,
            ),
            Object(self.prog, self.prog.int_type("int", 4, True, "big"), 0x12345678),
        )

    def test_int_from_bytes_bit_field(self):
        self.assertIdentical(
            Object.from_bytes_(self.prog, "int", b"\xcc", bit_field_size=8),
            Object(self.prog, "int", 0xCC, bit_field_size=8),
        )

    def test_float64_from_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                type_ = self.prog.float_type("double", 8, byteorder)
                self.assertIdentical(
                    Object.from_bytes_(
                        self.prog,
                        type_,
                        struct.pack(
                            ("<" if byteorder == "little" else ">") + "d", math.e
                        ),
                    ),
                    Object(self.prog, type_, math.e),
                )

    def test_float32_from_bytes(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                type_ = self.prog.float_type("float", 4, byteorder)
                self.assertIdentical(
                    Object.from_bytes_(
                        self.prog,
                        type_,
                        struct.pack(
                            ("<" if byteorder == "little" else ">") + "f", math.e
                        ),
                    ),
                    Object(self.prog, type_, math.e),
                )

    def test_struct_from_bytes(self):
        self.assertIdentical(
            Object.from_bytes_(
                self.prog, self.point_type, b"\x01\x00\x00\x00\x02\x00\x00\x00"
            ),
            Object(self.prog, self.point_type, {"x": 1, "y": 2}),
        )

    def test_struct_from_bytes_bit_offset(self):
        self.assertIdentical(
            Object.from_bytes_(
                self.prog,
                self.point_type,
                b"\xff\x01\x00\x00\x00\x02\x00\x00\x00",
                bit_offset=8,
            ),
            Object(self.prog, self.point_type, {"x": 1, "y": 2}),
        )

    def test_struct_from_bytes_invalid_bit_offset(self):
        self.assertRaisesRegex(
            ValueError,
            "non-scalar must be byte-aligned",
            Object.from_bytes_,
            self.prog,
            self.point_type,
            b"\xff\x01\x00\x00\x00\x02\x00\x00\x00",
            bit_offset=2,
        )

    def test_from_bytes_invalid_bit_field_size(self):
        self.assertRaisesRegex(
            ValueError,
            "bit field size cannot be zero",
            Object.from_bytes_,
            self.prog,
            "int",
            b"",
            bit_field_size=0,
        )

    def test_from_bytes_buffer_too_small(self):
        self.assertRaisesRegex(
            ValueError,
            "buffer is too small",
            Object.from_bytes_,
            self.prog,
            "int",
            bytes(3),
        )

    def test_from_bytes_incomplete_type(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot create object with void type",
            Object.from_bytes_,
            self.prog,
            "void",
            b"",
        )

    def test_from_bytes_bad_type(self):
        self.assertRaises(TypeError, Object.from_bytes_, self.prog, None, b"")


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

    def test_negative_subscript(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(obj[-1], Object(self.prog, "int", address=0xFFFEFFFC))

        obj = arr.read_()
        self.assertRaisesRegex(OutOfBoundsError, "out of bounds", obj.__getitem__, -1)

    def test_slice(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[1:3], Object(self.prog, "int [2]", address=0xFFFF0004)
            )

        obj = arr.read_()
        self.assertIdentical(obj[1:3], Object(self.prog, "int [2]", [1, 2]))

    def test_slice_step(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[1:3:1], Object(self.prog, "int [2]", address=0xFFFF0004)
            )

    def test_slice_invalid_step(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        with self.assertRaisesRegex(ValueError, "object slice step must be 1"):
            arr[0:4:2]

    def test_slice_negative_start(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[-2:2], Object(self.prog, "int [4]", address=0xFFFEFFF8)
            )

        obj = arr.read_()
        with self.assertRaisesRegex(OutOfBoundsError, "out of bounds"):
            obj[-2:2]

    def test_slice_both_negative(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[-4:-2], Object(self.prog, "int [2]", address=0xFFFEFFF0)
            )

        obj = arr.read_()
        with self.assertRaisesRegex(OutOfBoundsError, "out of bounds"):
            obj[-4:-2]

    def test_slice_both_none(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)

        self.assertIdentical(arr[:], Object(self.prog, "int [4]", address=0xFFFF0000))
        with self.assertRaisesRegex(TypeError, "has no length"):
            incomplete_arr[:]
        with self.assertRaisesRegex(TypeError, "has no length"):
            ptr[:]

        self.assertIdentical(arr.read_()[:], Object(self.prog, "int [4]", [0, 1, 2, 3]))

    def test_slice_start_none(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[:3], Object(self.prog, "int [3]", address=0xFFFF0000)
            )

        self.assertIdentical(arr.read_()[:3], Object(self.prog, "int [3]", [0, 1, 2]))

    def test_slice_stop_none(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)

        self.assertIdentical(arr[1:], Object(self.prog, "int [3]", address=0xFFFF0004))
        with self.assertRaisesRegex(TypeError, "has no length"):
            incomplete_arr[1:]
        with self.assertRaisesRegex(TypeError, "has no length"):
            ptr[1:]

        self.assertIdentical(arr.read_()[1:], Object(self.prog, "int [3]", [1, 2, 3]))

    def test_slice_start_negative_stop_none(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)

        self.assertIdentical(arr[-2:], Object(self.prog, "int [6]", address=0xFFFEFFF8))
        with self.assertRaisesRegex(TypeError, "has no length"):
            incomplete_arr[-2:]
        with self.assertRaisesRegex(TypeError, "has no length"):
            ptr[-2:]

        obj = arr.read_()
        with self.assertRaisesRegex(OutOfBoundsError, "out of bounds"):
            obj[-2:]

    def test_slice_start_none_stop_negative(self):
        arr = Object(self.prog, "int [4]", address=0xFFFF0000)
        incomplete_arr = Object(self.prog, "int []", address=0xFFFF0000)
        ptr = Object(self.prog, "int *", value=0xFFFF0000)
        for obj in [arr, incomplete_arr, ptr]:
            self.assertIdentical(
                obj[:-2], Object(self.prog, "int [0]", address=0xFFFF0000)
            )

        self.assertIdentical(arr.read_()[:-2], Object(self.prog, "int [0]", []))

    def test_cast_primitive_value(self):
        obj = Object(self.prog, "long", value=2**32 + 1)
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

    def test_cast_to_incomplete_type(self):
        self.assertRaisesRegex(
            TypeError,
            "cannot cast to incomplete enumerated type",
            cast,
            self.prog.enum_type("foo"),
            Object(self.prog, "int", 1),
        )

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

    def test_reinterpret_primitive_value_to_same_size_primitive(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertIdentical(
                    reinterpret(
                        self.prog.int_type("long long", 8, True, byteorder),
                        Object(
                            self.prog,
                            self.prog.int_type(
                                "unsigned long long", 8, False, byteorder
                            ),
                            0xFFFFFFFFFFFFFFF3,
                        ),
                    ),
                    Object(
                        self.prog,
                        self.prog.int_type("long long", 8, True, byteorder),
                        -13,
                    ),
                )

    def test_reinterpret_primitive_value_to_smaller_primitive(self):
        with self.subTest(byteorder="little"):
            self.assertIdentical(
                reinterpret(
                    self.prog.int_type("int", 4, True),
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False),
                        0x000027100000029A,
                    ),
                ),
                Object(self.prog, self.prog.int_type("int", 4, True), 666),
            )
        with self.subTest(byteorder="big"):
            self.assertIdentical(
                reinterpret(
                    self.prog.int_type("int", 4, True, "big"),
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False, "big"),
                        0x000027100000029A,
                    ),
                ),
                Object(self.prog, self.prog.int_type("int", 4, True, "big"), 10000),
            )

    def test_reinterpret_primitive_value_to_same_size_compound(self):
        with self.subTest(byteorder="little"):
            self.assertIdentical(
                reinterpret(
                    self.point_type,
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False),
                        0x000027100000029A,
                    ),
                ),
                Object(self.prog, self.point_type, {"x": 666, "y": 10000}),
            )
        with self.subTest(byteorder="big"):
            point_type = self.prog.struct_type(
                "point",
                8,
                (
                    TypeMember(self.prog.int_type("int", 4, True, "big"), "x", 0),
                    TypeMember(self.prog.int_type("int", 4, True, "big"), "y", 32),
                ),
            )
            self.assertIdentical(
                reinterpret(
                    point_type,
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False, "big"),
                        0x000027100000029A,
                    ),
                ),
                Object(self.prog, point_type, {"x": 10000, "y": 666}),
            )

    def test_reinterpret_primitive_value_to_smaller_compound(self):
        with self.subTest(byteorder="little"):
            small_point_type = self.prog.struct_type(
                "small_point",
                4,
                (
                    TypeMember(self.prog.int_type("short", 2, True), "x", 0),
                    TypeMember(self.prog.int_type("short", 2, True), "y", 16),
                ),
            )
            self.assertIdentical(
                reinterpret(
                    small_point_type,
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False),
                        0x123456782710029A,
                    ),
                ),
                Object(self.prog, small_point_type, {"x": 666, "y": 10000}),
            )
        with self.subTest(byteorder="big"):
            small_point_type = self.prog.struct_type(
                "small_point",
                4,
                (
                    TypeMember(self.prog.int_type("short", 2, True, "big"), "x", 0),
                    TypeMember(self.prog.int_type("short", 2, True, "big"), "y", 16),
                ),
            )
            self.assertIdentical(
                reinterpret(
                    small_point_type,
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned long long", 8, False, "big"),
                        0x123456782710029A,
                    ),
                ),
                Object(self.prog, small_point_type, {"x": 0x1234, "y": 0x5678}),
            )

    def test_reinterpret_bit_field_value_to_same_size_primitive(self):
        for byteorder in ("little", "big"):
            with self.subTest(byteorder=byteorder):
                self.assertIdentical(
                    reinterpret(
                        self.prog.int_type("uint24", 3, False, byteorder),
                        Object(
                            self.prog,
                            self.prog.int_type("unsigned int", 4, False, byteorder),
                            0xABCDEF,
                            bit_field_size=24,
                        ),
                    ),
                    Object(
                        self.prog,
                        self.prog.int_type("uint24", 3, False, byteorder),
                        0xABCDEF,
                    ),
                )

    def test_reinterpret_bit_field_value_to_smaller_primitive(self):
        with self.subTest(byteorder="little"):
            self.assertIdentical(
                reinterpret(
                    self.prog.int_type("unsigned short", 2, False),
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned int", 4, False),
                        0xABCDEF,
                        bit_field_size=24,
                    ),
                ),
                Object(
                    self.prog,
                    self.prog.int_type("unsigned short", 2, False),
                    0xCDEF,
                ),
            )
        with self.subTest(byteorder="big"):
            self.assertIdentical(
                reinterpret(
                    self.prog.int_type("unsigned short", 2, False, "big"),
                    Object(
                        self.prog,
                        self.prog.int_type("unsigned int", 4, False, "big"),
                        0xABCDEF,
                        bit_field_size=24,
                    ),
                ),
                Object(
                    self.prog,
                    self.prog.int_type("unsigned short", 2, False, "big"),
                    0xABCD,
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

    def test_format_invalid_integer_base(self):
        obj = Object(self.prog, "int", 1)
        for integer_base in (
            0,
            1,
            -(2**31),
            2**31 - 1,
            -(2**32),
            2**32,
            2**128,
            -(2**128),
        ):
            with self.subTest(integer_base=integer_base):
                self.assertRaisesRegex(
                    ValueError,
                    "invalid integer base",
                    obj.format_,
                    integer_base=integer_base,
                )
        self.assertRaises(TypeError, obj.format_, integer_base="hex")

    def test_sizeof_default_prog(self):
        self.objects.append(MockObject("foo", self.prog.int_type("int", 4, True), 1))
        self.assertRaises(NoDefaultProgramError, sizeof, "foo")
        with with_default_prog(self.prog):
            self.assertEqual(sizeof("foo"), 4)


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
        self.assertRaisesRegex(
            TypeError, "'int' is not iterable", iter, Object(self.prog, "int", value=0)
        )
        self.assertRaisesRegex(
            TypeError,
            r"'int \[\]' is not iterable",
            iter,
            Object(self.prog, "int []", address=0),
        )

    def test_iter_length_hint(self):
        it = iter(Object(self.prog, "int [3]", value=[0, 1, 2]))
        for i in range(3, 0, -1):
            self.assertEqual(operator.length_hint(it), i)
            next(it)
        self.assertEqual(operator.length_hint(it), 0)

    def test_reversed(self):
        obj = Object(self.prog, "int [4]", value=[0, 1, 2, 3])
        for i, element in zip(range(3, -1, -1), reversed(obj)):
            self.assertIdentical(element, Object(self.prog, "int", value=i))
        self.assertRaisesRegex(
            TypeError,
            "'int' is not iterable",
            reversed,
            Object(self.prog, "int", value=0),
        )
        self.assertRaisesRegex(
            TypeError,
            r"'int \[\]' is not iterable",
            reversed,
            Object(self.prog, "int []", address=0),
        )

    def test_reversed_length_hint(self):
        it = reversed(Object(self.prog, "int [3]", value=[0, 1, 2]))
        for i in range(3, 0, -1):
            self.assertEqual(operator.length_hint(it), i)
            next(it)
        self.assertEqual(operator.length_hint(it), 0)

    def test__repr_pretty_(self):
        obj = Object(self.prog, "int", value=0)
        assertReprPrettyEqualsStr(obj)
