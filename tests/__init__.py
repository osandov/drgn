# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import functools
import os
from typing import Any, Mapping, NamedTuple, Optional
import unittest
from unittest.mock import Mock

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


def add_mock_memory_segments(prog, segments):
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


class MockObject(NamedTuple):
    name: str
    type: Type
    address: Optional[int] = None
    value: Any = None


def mock_program(platform=MOCK_PLATFORM, *, segments=None, types=None, objects=None):
    def mock_find_type(prog, kinds, name, filename):
        if filename:
            return None
        for type in types:
            if type.kind in kinds:
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
        add_mock_memory_segments(prog, segments)
    if types is not None:
        prog.register_type_finder("mock", mock_find_type, enable_index=0)
    if objects is not None:
        prog.register_object_finder("mock", mock_object_find, enable_index=0)
    return prog


def assertReprPrettyEqualsStr(obj):
    pretty_printer_mock = Mock()

    obj._repr_pretty_(pretty_printer_mock, False)
    pretty_printer_mock.text.assert_called_with(str(obj))

    obj._repr_pretty_(p=pretty_printer_mock, cycle=True)
    pretty_printer_mock.text.assert_called_with("...")


_IDENTICAL_EQ_TYPES = (
    type(None),
    Language,
    Program,
    TypeEnumerator,
    TypeKind,
    bool,
    float,
    int,
    str,
)
_IDENTICAL_MAPPING_TYPES = (dict,)
_IDENTICAL_SEQUENCE_TYPES = (list, tuple)
_IDENTICAL_SUPPORTED_TYPES = (
    _IDENTICAL_EQ_TYPES
    + _IDENTICAL_MAPPING_TYPES
    + _IDENTICAL_SEQUENCE_TYPES
    + (Object, Type, TypeMember, TypeParameter, TypeTemplateParameter)
)


def identical(a, b):
    """
    Return whether two objects are "identical".

    drgn.Object, drgn.Type, drgn.TypeMember, drgn.TypeParameter, and
    drgn.TypeTemplateParameter objects are identical iff they have they have
    the same type and identical attributes. Note that for drgn.Object, this is
    different from the objects comparing equal: their type, address, value,
    etc. must be identical.

    Two mappings or sequences are identical iff they have the same type,
    length, and all of their items are identical.

    Types in _IDENTICAL_EQ_TYPES are identical iff they have the same type and
    they compare equal.
    """
    compared_types = set()

    def _identical_attrs(a, b, attr_names):
        for attr_name in attr_names:
            if not _identical(getattr(a, attr_name), getattr(b, attr_name)):
                return False
        return True

    def _identical_mapping(a, b):
        return len(a) == len(b) and all(
            _identical(key_a, key_b) and _identical(value_a, value_b)
            for (key_a, value_a), (key_b, value_b) in zip(a.items(), b.items())
        )

    def _identical_sequence(a, b):
        return len(a) == len(b) and all(
            _identical(elem_a, elem_b) for elem_a, elem_b in zip(a, b)
        )

    def _identical(a, b):
        if (
            type(a) not in _IDENTICAL_SUPPORTED_TYPES
            or type(b) not in _IDENTICAL_SUPPORTED_TYPES
        ):
            raise NotImplementedError(f"can't compare {type(a)} to {type(b)}")
        if type(a) != type(b):  # noqa: E721
            return False

        t = type(a)
        if t == Object:
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
            if a.address_ is None:
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
            else:
                return True
        elif t == Type:
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
        elif t == TypeMember:
            return _identical_attrs(a, b, ("object", "name", "bit_offset"))
        elif t == TypeParameter:
            return _identical_attrs(a, b, ("default_argument", "name"))
        elif t == TypeTemplateParameter:
            return _identical_attrs(a, b, ("argument", "name", "is_default"))
        elif t in _IDENTICAL_EQ_TYPES:
            return a == b
        elif t in _IDENTICAL_MAPPING_TYPES:
            return _identical_mapping(a, b)
        elif t in _IDENTICAL_SEQUENCE_TYPES:
            return _identical_sequence(a, b)
        else:
            assert False

    return _identical(a, b)


# Wrapper class that defines == using identical(). This is useful for
# unittest.mock.Mock.assert_called_with().
class IdenticalMatcher:
    def __init__(self, obj):
        self._obj = obj

    def __str__(self):
        return str(self._obj)

    def __repr__(self):
        return repr(self._obj)

    def __eq__(self, other):
        if isinstance(other, IdenticalMatcher):
            other = other._obj
        return identical(self._obj, other)


class TestCase(unittest.TestCase):
    def assertIdentical(self, a, b, msg=None):
        return self.assertEqual(IdenticalMatcher(a), IdenticalMatcher(b), msg)

    def assertNotIdentical(self, a, b, msg=None):
        return self.assertNotEqual(IdenticalMatcher(a), IdenticalMatcher(b), msg)

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


@contextlib.contextmanager
def modifyenv(vars: Mapping[str, Optional[str]]):
    to_restore = []
    for key, value in vars.items():
        old_value = os.environ.get(key)
        if value != old_value:
            if value is None:
                del os.environ[key]
            else:
                os.environ[key] = value
            to_restore.append((key, old_value))
    try:
        yield
    finally:
        for key, old_value in to_restore:
            if old_value is None:
                del os.environ[key]
            else:
                os.environ[key] = old_value
