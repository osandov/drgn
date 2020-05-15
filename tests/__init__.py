# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import functools
from typing import Any, NamedTuple, Optional
import unittest

from drgn import (
    Architecture,
    FindObjectFlags,
    Language,
    Object,
    Platform,
    PlatformFlags,
    Program,
    Type,
    TypeEnumerator,
    TypeKind,
    TypeMember,
    class_type,
    enum_type,
    float_type,
    int_type,
    struct_type,
    typedef_type,
    union_type,
)


DEFAULT_LANGUAGE = Language.C


coord_type = class_type(
    "coord",
    12,
    (
        TypeMember(int_type("int", 4, True), "x", 0),
        TypeMember(int_type("int", 4, True), "y", 32),
        TypeMember(int_type("int", 4, True), "z", 64),
    ),
)
point_type = struct_type(
    "point",
    8,
    (
        TypeMember(int_type("int", 4, True), "x", 0),
        TypeMember(int_type("int", 4, True), "y", 32),
    ),
)
line_segment_type = struct_type(
    "line_segment", 16, (TypeMember(point_type, "a"), TypeMember(point_type, "b", 64))
)
option_type = union_type(
    "option",
    4,
    (
        TypeMember(int_type("int", 4, True), "i"),
        TypeMember(float_type("float", 4), "f"),
    ),
)
color_type = enum_type(
    "color",
    int_type("unsigned int", 4, False),
    (TypeEnumerator("RED", 0), TypeEnumerator("GREEN", 1), TypeEnumerator("BLUE", 2)),
)
pid_type = typedef_type("pid_t", int_type("int", 4, True))


MOCK_32BIT_PLATFORM = Platform(Architecture.UNKNOWN, PlatformFlags.IS_LITTLE_ENDIAN)
MOCK_PLATFORM = Platform(
    Architecture.UNKNOWN, PlatformFlags.IS_64_BIT | PlatformFlags.IS_LITTLE_ENDIAN
)


class MockMemorySegment(NamedTuple):
    buf: bytes
    virt_addr: Optional[int] = None
    phys_addr: Optional[int] = None


def mock_memory_read(data, address, count, offset, physical):
    return data[offset : offset + count]


class MockObject(NamedTuple):
    name: str
    type: Type
    address: Optional[int] = None
    value: Any = None


def mock_program(platform=MOCK_PLATFORM, *, segments=None, types=None, objects=None):
    def mock_find_type(kind, name, filename):
        if filename:
            return None
        for type in types:
            if type.kind == kind:
                try:
                    type_name = type.name
                except AttributeError:
                    try:
                        type_name = type.tag
                    except AttributeError:
                        continue
                if type_name == name:
                    return type
        return None

    def mock_object_find(prog, name, flags, filename):
        if filename:
            return None
        for obj in objects:
            if obj.name == name:
                if obj.value is not None:
                    if flags & FindObjectFlags.CONSTANT:
                        break
                elif obj.type.kind == TypeKind.FUNCTION:
                    if flags & FindObjectFlags.FUNCTION:
                        break
                elif flags & FindObjectFlags.VARIABLE:
                    break
        else:
            return None
        return Object(prog, obj.type, address=obj.address, value=obj.value)

    prog = Program(platform)
    if segments is not None:
        for segment in segments:
            if segment.virt_addr is not None:
                prog.add_memory_segment(
                    segment.virt_addr,
                    len(segment.buf),
                    functools.partial(mock_memory_read, segment.buf),
                )
            if segment.phys_addr is not None:
                prog.add_memory_segment(
                    segment.phys_addr,
                    len(segment.buf),
                    functools.partial(mock_memory_read, segment.buf),
                    True,
                )
    if types is not None:
        prog.add_type_finder(mock_find_type)
    if objects is not None:
        prog.add_object_finder(mock_object_find)
    return prog


class ObjectTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.prog = mock_program()
        # For testing, we want to compare the raw objects rather than using the
        # language's equality operator.
        def object_equality_func(a, b, msg=None):
            if a.prog_ is not b.prog_:
                raise self.failureException(msg or "objects have different program")
            if a.type_ != b.type_:
                raise self.failureException(
                    msg or f"object types differ: {a.type_!r} != {b.type_!r}"
                )
            if a.address_ != b.address_:
                a_address = "None" if a.address_ is None else hex(a.address_)
                b_address = "None" if b.address_ is None else hex(b.address_)
                raise self.failureException(
                    msg or f"object addresses differ: {a_address} != {b_address}"
                )
            if a.byteorder_ != b.byteorder_:
                raise self.failureException(
                    msg or f"object byteorders differ: {a.byteorder_} != {b.byteorder_}"
                )
            if a.bit_offset_ != b.bit_offset_:
                raise self.failureException(
                    msg
                    or f"object bit offsets differ: {a.bit_offset_} != {b.bit_offset_}"
                )
            if a.bit_field_size_ != b.bit_field_size_:
                raise self.failureException(
                    msg
                    or f"object bit field sizes differ: {a.bit_field_size_} != {b.bit_field_size_}"
                )
            exc_a = exc_b = False
            try:
                value_a = a.value_()
            except Exception:
                exc_a = True
            try:
                value_b = b.value_()
            except Exception:
                exc_b = True
            if exc_a and not exc_b:
                raise self.failureException(
                    msg or f"exception raised while reading {a!r}"
                )
            if not exc_a and exc_b:
                raise self.failureException(
                    msg or f"exception raised while reading {b!r}"
                )
            if not exc_a and value_a != value_b:
                raise self.failureException(
                    msg or f"object values differ: {value_a!r} != {value_b!r}"
                )

        self.addTypeEqualityFunc(Object, object_equality_func)

    def bool(self, value):
        return Object(self.prog, "_Bool", value=value)

    def int(self, value):
        return Object(self.prog, "int", value=value)

    def unsigned_int(self, value):
        return Object(self.prog, "unsigned int", value=value)

    def long(self, value):
        return Object(self.prog, "long", value=value)

    def double(self, value):
        return Object(self.prog, "double", value=value)
