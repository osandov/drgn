# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import types
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
    TypeParameter,
    TypeTemplateParameter,
)

DEFAULT_LANGUAGE = Language.C


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


def identical(a, b):
    """
    Return whether two objects are "identical".

    drgn.Object, drgn.Type, drgn.TypeMember, or drgn.TypeParameter objects are
    identical iff they have they have the same type and identical attributes.
    Note that for drgn.Object, this is different from the objects comparing
    equal: their type, address, value, etc. must be identical.

    Two sequences are identical iff they have the same type, length, and all of
    their items are identical.
    """
    compared_types = set()

    def _identical_attrs(a, b, attr_names):
        for attr_name in attr_names:
            if not _identical(getattr(a, attr_name), getattr(b, attr_name)):
                return False
        return True

    def _identical_sequence(a, b):
        return len(a) == len(b) and all(
            _identical(elem_a, elem_b) for elem_a, elem_b in zip(a, b)
        )

    def _identical(a, b):
        if isinstance(a, Object) and isinstance(b, Object):
            if not _identical_attrs(
                a,
                b,
                (
                    "prog_",
                    "type_",
                    "address_",
                    "bit_offset_",
                    "bit_field_size_",
                ),
            ):
                return False
            exc_a = exc_b = False
            try:
                value_a = a.value_()
            except Exception:
                exc_a = True
            try:
                value_b = b.value_()
            except Exception:
                exc_b = True
            if exc_a != exc_b:
                return False
            return exc_a or _identical(value_a, value_b)
        elif isinstance(a, Type) and isinstance(b, Type):
            if a.qualifiers != b.qualifiers:
                return False
            if a._ptr == b._ptr:
                return True
            if a._ptr < b._ptr:
                key = (a._ptr, b._ptr)
            else:
                key = (b._ptr, a._ptr)
            if key in compared_types:
                return True
            compared_types.add(key)
            return _identical_attrs(
                a,
                b,
                [
                    name
                    for name in (
                        "prog",
                        "kind",
                        "primitive",
                        "language",
                        "name",
                        "tag",
                        "size",
                        "length",
                        "is_signed",
                        "byteorder",
                        "type",
                        "members",
                        "enumerators",
                        "parameters",
                        "is_variadic",
                        "template_parameters",
                    )
                    if hasattr(a, name) or hasattr(b, name)
                ],
            )
        elif isinstance(a, TypeMember) and isinstance(b, TypeMember):
            return _identical_attrs(a, b, ("object", "name", "bit_offset"))
        elif isinstance(a, TypeParameter) and isinstance(b, TypeParameter):
            return _identical_attrs(a, b, ("default_argument", "name"))
        elif isinstance(a, TypeTemplateParameter) and isinstance(
            b, TypeTemplateParameter
        ):
            return _identical_attrs(a, b, ("argument", "name", "is_default"))
        elif (isinstance(a, tuple) and isinstance(b, tuple)) or (
            isinstance(a, list) and isinstance(b, list)
        ):
            return _identical_sequence(a, b)
        else:
            return a == b

    return _identical(a, b)


# Wrapper class that defines == using identical(). This lets us use unittest's
# nice formatting of assert{,Not}Equal() failures.
class _AssertIdenticalWrapper:
    def __init__(self, obj):
        self._obj = obj

    def __str__(self):
        return str(self._obj)

    def __repr__(self):
        return repr(self._obj)

    def __eq__(self, other):
        if not isinstance(other, _AssertIdenticalWrapper):
            return NotImplemented
        return identical(self._obj, other._obj)


class TestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

    def assertIdentical(self, a, b, msg=None):
        return self.assertEqual(
            _AssertIdenticalWrapper(a), _AssertIdenticalWrapper(b), msg
        )

    def assertNotIdentical(self, a, b, msg=None):
        return self.assertNotEqual(
            _AssertIdenticalWrapper(a), _AssertIdenticalWrapper(b), msg
        )

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


class MockProgramTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.types = []
        self.objects = []
        self.prog = mock_program(types=self.types, objects=self.objects)
        self.coord_type = self.prog.class_type(
            "coord",
            12,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
                TypeMember(self.prog.int_type("int", 4, True), "z", 64),
            ),
        )
        self.point_type = self.prog.struct_type(
            "point",
            8,
            (
                TypeMember(self.prog.int_type("int", 4, True), "x", 0),
                TypeMember(self.prog.int_type("int", 4, True), "y", 32),
            ),
        )
        self.line_segment_type = self.prog.struct_type(
            "line_segment",
            16,
            (TypeMember(self.point_type, "a"), TypeMember(self.point_type, "b", 64)),
        )
        self.option_type = self.prog.union_type(
            "option",
            4,
            (
                TypeMember(self.prog.int_type("int", 4, True), "i"),
                TypeMember(self.prog.float_type("float", 4), "f"),
            ),
        )
        self.color_type = self.prog.enum_type(
            "color",
            self.prog.int_type("unsigned int", 4, False),
            (
                TypeEnumerator("RED", 0),
                TypeEnumerator("GREEN", 1),
                TypeEnumerator("BLUE", 2),
            ),
        )
        self.pid_type = self.prog.typedef_type(
            "pid_t", self.prog.int_type("int", 4, True)
        )

    def add_memory_segment(self, buf, virt_addr=None, phys_addr=None):
        if virt_addr is not None:
            self.prog.add_memory_segment(
                virt_addr, len(buf), functools.partial(mock_memory_read, buf)
            )
        if phys_addr is not None:
            self.prog.add_memory_segment(
                phys_addr, len(buf), functools.partial(mock_memory_read, buf), True
            )
